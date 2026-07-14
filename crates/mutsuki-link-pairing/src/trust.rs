use mutsuki_link_core::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;

pub const DEFAULT_MAX_TRUST_RECORDS: usize = 1_024;
pub(crate) const MAX_TRUST_STORE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 4 * 1024;
const MAX_ALIAS_BYTES: usize = 256;
const MAX_PERMISSIONS: usize = 128;
const MAX_PERMISSION_NAMESPACE_BYTES: usize = 128;
const MAX_PREVIOUS_KEY_FINGERPRINTS: usize = 64;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LinkPermission {
    Connect,
    OpenNamespace(String),
    Datagram,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyState {
    Active,
    Revoked {
        revoked_at_unix_ms: u64,
    },
    Rotated {
        rotated_at_unix_ms: u64,
        new_peer_id: PeerId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRecord {
    pub peer_id: PeerId,
    pub public_key: Vec<u8>,
    pub alias: String,
    pub first_paired_at_unix_ms: u64,
    pub permissions: BTreeSet<LinkPermission>,
    pub key_state: KeyState,
    pub last_pairing_challenge_hash: [u8; 32],
    pub previous_key_fingerprints: Vec<[u8; 32]>,
}

impl TrustRecord {
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.public_key).into()
    }

    pub fn is_active(&self) -> bool {
        self.key_state == KeyState::Active
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustStoreErrorKind {
    Io,
    Corrupt,
    Unavailable,
    UnknownPeer,
    Revoked,
    Rotated,
    IdentityMismatch,
    Conflict,
    LimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustStoreError {
    pub kind: TrustStoreErrorKind,
    pub public_message: &'static str,
}

impl TrustStoreError {
    pub(crate) const fn new(kind: TrustStoreErrorKind, public_message: &'static str) -> Self {
        Self {
            kind,
            public_message,
        }
    }
}

impl fmt::Display for TrustStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for TrustStoreError {}

pub trait TrustStore {
    fn get(&self, peer_id: &PeerId) -> Result<Option<TrustRecord>, TrustStoreError>;
    fn list(&self) -> Result<Vec<TrustRecord>, TrustStoreError>;
    fn upsert(&mut self, record: TrustRecord) -> Result<(), TrustStoreError>;
    fn remove(&mut self, peer_id: &PeerId) -> Result<bool, TrustStoreError>;
    fn revoke(&mut self, peer_id: &PeerId, now_unix_ms: u64) -> Result<(), TrustStoreError>;
    fn rotate(
        &mut self,
        old_peer_id: &PeerId,
        new_peer_id: PeerId,
        new_public_key: Vec<u8>,
        challenge_hash: [u8; 32],
        now_unix_ms: u64,
    ) -> Result<TrustRecord, TrustStoreError>;
}

pub(crate) fn validate_record(record: &TrustRecord) -> Result<(), TrustStoreError> {
    if record.public_key.is_empty()
        || record.public_key.len() > MAX_PUBLIC_KEY_BYTES
        || record.alias.is_empty()
        || record.alias.len() > MAX_ALIAS_BYTES
        || record.permissions.len() > MAX_PERMISSIONS
        || record.previous_key_fingerprints.len() > MAX_PREVIOUS_KEY_FINGERPRINTS
        || record.permissions.iter().any(|permission| {
            matches!(
                permission,
                LinkPermission::OpenNamespace(namespace)
                    if namespace.is_empty() || namespace.len() > MAX_PERMISSION_NAMESPACE_BYTES
            )
        })
    {
        return Err(TrustStoreError::new(
            TrustStoreErrorKind::LimitExceeded,
            "trust record exceeds configured limits",
        ));
    }
    Ok(())
}

pub fn authorize_trusted_reconnect(
    store: &impl TrustStore,
    peer_id: &PeerId,
    presented_public_key: &[u8],
) -> Result<TrustRecord, TrustStoreError> {
    let record = store.get(peer_id)?.ok_or_else(|| {
        TrustStoreError::new(TrustStoreErrorKind::UnknownPeer, "peer has no trust record")
    })?;
    validate_record(&record)?;
    match record.key_state {
        KeyState::Active => {}
        KeyState::Revoked { .. } => {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Revoked,
                "peer trust has been revoked",
            ));
        }
        KeyState::Rotated { .. } => {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Rotated,
                "peer identity key was rotated",
            ));
        }
    }
    if record.public_key != presented_public_key {
        return Err(TrustStoreError::new(
            TrustStoreErrorKind::IdentityMismatch,
            "peer public key does not match trust record",
        ));
    }
    Ok(record)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RecordDto {
    peer_id: String,
    public_key: Vec<u8>,
    alias: String,
    first_paired_at_unix_ms: u64,
    permissions: Vec<PermissionDto>,
    key_state: KeyStateDto,
    last_pairing_challenge_hash: Vec<u8>,
    previous_key_fingerprints: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum PermissionDto {
    Connect,
    OpenNamespace(String),
    Datagram,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum KeyStateDto {
    Active,
    Revoked {
        revoked_at_unix_ms: u64,
    },
    Rotated {
        rotated_at_unix_ms: u64,
        new_peer_id: String,
    },
}

impl TryFrom<RecordDto> for TrustRecord {
    type Error = TrustStoreError;

    fn try_from(value: RecordDto) -> Result<Self, Self::Error> {
        let peer_id = decode_peer_id(&value.peer_id)?;
        let challenge = decode_32(&value.last_pairing_challenge_hash)?;
        let previous_key_fingerprints = value
            .previous_key_fingerprints
            .iter()
            .map(|value| decode_32(value))
            .collect::<Result<Vec<_>, _>>()?;
        let key_state = match value.key_state {
            KeyStateDto::Active => KeyState::Active,
            KeyStateDto::Revoked { revoked_at_unix_ms } => KeyState::Revoked { revoked_at_unix_ms },
            KeyStateDto::Rotated {
                rotated_at_unix_ms,
                new_peer_id,
            } => KeyState::Rotated {
                rotated_at_unix_ms,
                new_peer_id: decode_peer_id(&new_peer_id)?,
            },
        };
        let permissions = value
            .permissions
            .into_iter()
            .map(|permission| match permission {
                PermissionDto::Connect => LinkPermission::Connect,
                PermissionDto::OpenNamespace(namespace) => LinkPermission::OpenNamespace(namespace),
                PermissionDto::Datagram => LinkPermission::Datagram,
            })
            .collect();
        let record = Self {
            peer_id,
            public_key: value.public_key,
            alias: value.alias,
            first_paired_at_unix_ms: value.first_paired_at_unix_ms,
            permissions,
            key_state,
            last_pairing_challenge_hash: challenge,
            previous_key_fingerprints,
        };
        validate_record(&record)?;
        Ok(record)
    }
}

impl From<&TrustRecord> for RecordDto {
    fn from(value: &TrustRecord) -> Self {
        let permissions = value
            .permissions
            .iter()
            .map(|permission| match permission {
                LinkPermission::Connect => PermissionDto::Connect,
                LinkPermission::OpenNamespace(namespace) => {
                    PermissionDto::OpenNamespace(namespace.clone())
                }
                LinkPermission::Datagram => PermissionDto::Datagram,
            })
            .collect();
        let key_state = match value.key_state {
            KeyState::Active => KeyStateDto::Active,
            KeyState::Revoked { revoked_at_unix_ms } => KeyStateDto::Revoked { revoked_at_unix_ms },
            KeyState::Rotated {
                rotated_at_unix_ms,
                new_peer_id,
            } => KeyStateDto::Rotated {
                rotated_at_unix_ms,
                new_peer_id: encode(new_peer_id.as_bytes()),
            },
        };
        Self {
            peer_id: encode(value.peer_id.as_bytes()),
            public_key: value.public_key.clone(),
            alias: value.alias.clone(),
            first_paired_at_unix_ms: value.first_paired_at_unix_ms,
            permissions,
            key_state,
            last_pairing_challenge_hash: value.last_pairing_challenge_hash.to_vec(),
            previous_key_fingerprints: value
                .previous_key_fingerprints
                .iter()
                .map(|value| value.to_vec())
                .collect(),
        }
    }
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to string");
    }
    encoded
}

pub(crate) fn decode_peer_id(value: &str) -> Result<PeerId, TrustStoreError> {
    Ok(PeerId::from_bytes(decode_hex_32(value)?))
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], TrustStoreError> {
    if value.len() != 64 {
        return Err(corrupt());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| corrupt())?;
    }
    Ok(bytes)
}

fn decode_32(value: &[u8]) -> Result<[u8; 32], TrustStoreError> {
    value.try_into().map_err(|_| corrupt())
}

pub(crate) const fn corrupt() -> TrustStoreError {
    TrustStoreError::new(TrustStoreErrorKind::Corrupt, "trust store data is invalid")
}
