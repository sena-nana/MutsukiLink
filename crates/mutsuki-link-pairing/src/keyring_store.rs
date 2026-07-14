use crate::trust::{
    DEFAULT_MAX_TRUST_RECORDS, KeyState, RecordDto, TrustRecord, TrustStore, TrustStoreError,
    TrustStoreErrorKind, decode_peer_id, encode, validate_record,
};
use keyring::{Entry, Error as KeyringError};
use mutsuki_link_core::PeerId;
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct SystemKeyringTrustStore {
    service: String,
    known_peers: BTreeSet<PeerId>,
    max_records: usize,
}

impl SystemKeyringTrustStore {
    pub fn open(service: impl Into<String>) -> Result<Self, TrustStoreError> {
        Self::open_with_limit(service, DEFAULT_MAX_TRUST_RECORDS)
    }

    pub fn open_with_limit(
        service: impl Into<String>,
        max_records: usize,
    ) -> Result<Self, TrustStoreError> {
        let service = service.into();
        if service.is_empty() || max_records == 0 {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Unavailable,
                "system keyring service name is empty",
            ));
        }
        let index = Entry::new(&service, "__mutsuki_link_peer_index").map_err(keyring_error)?;
        let known_peers = match index.get_password() {
            Ok(encoded) => {
                if encoded.len() > max_records.saturating_mul(70).saturating_add(2) {
                    return Err(limit_error());
                }
                let values =
                    serde_json::from_str::<Vec<String>>(&encoded).map_err(|_| corrupt())?;
                if values.len() > max_records {
                    return Err(limit_error());
                }
                values
                    .iter()
                    .map(|value| decode_peer_id(value))
                    .collect::<Result<_, _>>()?
            }
            Err(KeyringError::NoEntry) => BTreeSet::new(),
            Err(error) => return Err(keyring_error(error)),
        };
        Ok(Self {
            service,
            known_peers,
            max_records,
        })
    }

    fn entry(&self, peer_id: &PeerId) -> Result<Entry, TrustStoreError> {
        Entry::new(&self.service, &encode(peer_id.as_bytes())).map_err(keyring_error)
    }

    fn persist_index(&self, peers: &BTreeSet<PeerId>) -> Result<(), TrustStoreError> {
        let values = peers
            .iter()
            .map(|peer| encode(peer.as_bytes()))
            .collect::<Vec<_>>();
        let encoded = serde_json::to_string(&values).map_err(|_| corrupt())?;
        Entry::new(&self.service, "__mutsuki_link_peer_index")
            .map_err(keyring_error)?
            .set_password(&encoded)
            .map_err(keyring_error)
    }
}

impl TrustStore for SystemKeyringTrustStore {
    fn get(&self, peer_id: &PeerId) -> Result<Option<TrustRecord>, TrustStoreError> {
        match self.entry(peer_id)?.get_password() {
            Ok(encoded) => {
                let dto: RecordDto = serde_json::from_str(&encoded).map_err(|_| corrupt())?;
                Ok(Some(TrustRecord::try_from(dto)?))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(keyring_error(error)),
        }
    }

    fn list(&self) -> Result<Vec<TrustRecord>, TrustStoreError> {
        self.known_peers
            .iter()
            .filter_map(|peer| self.get(peer).transpose())
            .collect()
    }

    fn upsert(&mut self, record: TrustRecord) -> Result<(), TrustStoreError> {
        validate_record(&record)?;
        if !self.known_peers.contains(&record.peer_id) && self.known_peers.len() >= self.max_records
        {
            return Err(limit_error());
        }
        let encoded = serde_json::to_string(&RecordDto::from(&record)).map_err(|_| corrupt())?;
        self.entry(&record.peer_id)?
            .set_password(&encoded)
            .map_err(keyring_error)?;
        let mut peers = self.known_peers.clone();
        peers.insert(record.peer_id);
        self.persist_index(&peers)?;
        self.known_peers = peers;
        Ok(())
    }

    fn remove(&mut self, peer_id: &PeerId) -> Result<bool, TrustStoreError> {
        let existed = self.known_peers.contains(peer_id) || self.get(peer_id)?.is_some();
        if !existed {
            return Ok(false);
        }
        match self.entry(peer_id)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => {}
            Err(error) => return Err(keyring_error(error)),
        }
        let mut peers = self.known_peers.clone();
        peers.remove(peer_id);
        self.persist_index(&peers)?;
        self.known_peers = peers;
        Ok(true)
    }

    fn revoke(&mut self, peer_id: &PeerId, now_unix_ms: u64) -> Result<(), TrustStoreError> {
        let mut record = self.get(peer_id)?.ok_or_else(unknown_peer)?;
        record.key_state = KeyState::Revoked {
            revoked_at_unix_ms: now_unix_ms,
        };
        self.upsert(record)
    }

    fn rotate(
        &mut self,
        old_peer_id: &PeerId,
        new_peer_id: PeerId,
        new_public_key: Vec<u8>,
        challenge_hash: [u8; 32],
        now_unix_ms: u64,
    ) -> Result<TrustRecord, TrustStoreError> {
        if self.get(&new_peer_id)?.is_some() || new_public_key.is_empty() {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Conflict,
                "new peer identity conflicts with trust store",
            ));
        }
        if self.known_peers.len() >= self.max_records {
            return Err(limit_error());
        }
        let mut old = self.get(old_peer_id)?.ok_or_else(unknown_peer)?;
        if !old.is_active() {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Conflict,
                "only an active identity can rotate",
            ));
        }
        let mut fingerprints = old.previous_key_fingerprints.clone();
        fingerprints.push(old.public_key_fingerprint());
        let replacement = TrustRecord {
            peer_id: new_peer_id,
            public_key: new_public_key,
            alias: old.alias.clone(),
            first_paired_at_unix_ms: old.first_paired_at_unix_ms,
            permissions: old.permissions.clone(),
            key_state: KeyState::Active,
            last_pairing_challenge_hash: challenge_hash,
            previous_key_fingerprints: fingerprints,
        };
        old.key_state = KeyState::Rotated {
            rotated_at_unix_ms: now_unix_ms,
            new_peer_id,
        };
        self.upsert(old)?;
        // Fail closed: the old key is disabled before the replacement becomes
        // active. An interrupted rotation can require retry, but cannot leave
        // the old identity silently authorized.
        self.upsert(replacement.clone())?;
        Ok(replacement)
    }
}

fn keyring_error(_error: KeyringError) -> TrustStoreError {
    TrustStoreError::new(
        TrustStoreErrorKind::Unavailable,
        "system credential store operation failed",
    )
}

fn corrupt() -> TrustStoreError {
    TrustStoreError::new(
        TrustStoreErrorKind::Corrupt,
        "system credential trust record is invalid",
    )
}

fn unknown_peer() -> TrustStoreError {
    TrustStoreError::new(TrustStoreErrorKind::UnknownPeer, "peer has no trust record")
}

fn limit_error() -> TrustStoreError {
    TrustStoreError::new(
        TrustStoreErrorKind::LimitExceeded,
        "system credential trust store limit exceeded",
    )
}
