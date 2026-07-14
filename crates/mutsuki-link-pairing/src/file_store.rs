use crate::trust::{
    DEFAULT_MAX_TRUST_RECORDS, KeyState, MAX_TRUST_STORE_FILE_BYTES, RecordDto, TrustRecord,
    TrustStore, TrustStoreError, TrustStoreErrorKind, validate_record,
};
use mutsuki_link_core::PeerId;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct FileTrustStore {
    path: PathBuf,
    records: BTreeMap<PeerId, TrustRecord>,
    max_records: usize,
}

impl FileTrustStore {
    /// Opens the explicit file-backed development store. Production callers
    /// should prefer a system credential backend where available.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TrustStoreError> {
        Self::open_with_limit(path, DEFAULT_MAX_TRUST_RECORDS)
    }

    pub fn open_with_limit(
        path: impl Into<PathBuf>,
        max_records: usize,
    ) -> Result<Self, TrustStoreError> {
        if max_records == 0 {
            return Err(limit_error());
        }
        let path = path.into();
        let records = if path.exists() {
            if fs::metadata(&path).map_err(io_error)?.len() > MAX_TRUST_STORE_FILE_BYTES {
                return Err(limit_error());
            }
            let file = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(io_error)?;
            let dtos: Vec<RecordDto> =
                serde_json::from_reader(BufReader::new(file)).map_err(|_| invalid_store())?;
            if dtos.len() > max_records {
                return Err(limit_error());
            }
            dtos.into_iter()
                .map(|dto| {
                    let record = TrustRecord::try_from(dto)?;
                    Ok((record.peer_id, record))
                })
                .collect::<Result<_, TrustStoreError>>()?
        } else {
            BTreeMap::new()
        };
        let store = Self {
            path,
            records,
            max_records,
        };
        if !store.path.exists() {
            store.persist(&store.records)?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self, records: &BTreeMap<PeerId, TrustRecord>) -> Result<(), TrustStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        let temporary = self.path.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temporary).map_err(io_error)?;
        let mut writer = BufWriter::new(file);
        let dtos = records.values().map(RecordDto::from).collect::<Vec<_>>();
        serde_json::to_writer_pretty(&mut writer, &dtos).map_err(|_| invalid_store())?;
        writer.write_all(b"\n").map_err(io_error)?;
        writer.flush().map_err(io_error)?;
        writer.get_ref().sync_all().map_err(io_error)?;
        drop(writer);
        #[cfg(windows)]
        if self.path.exists() {
            // This backend is explicitly for development; Windows rename does
            // not replace an existing file, so use a bounded remove+rename.
            fs::remove_file(&self.path).map_err(io_error)?;
        }
        fs::rename(&temporary, &self.path).map_err(io_error)?;
        Ok(())
    }

    fn replace(&mut self, records: BTreeMap<PeerId, TrustRecord>) -> Result<(), TrustStoreError> {
        self.persist(&records)?;
        self.records = records;
        Ok(())
    }
}

impl TrustStore for FileTrustStore {
    fn get(&self, peer_id: &PeerId) -> Result<Option<TrustRecord>, TrustStoreError> {
        Ok(self.records.get(peer_id).cloned())
    }

    fn list(&self) -> Result<Vec<TrustRecord>, TrustStoreError> {
        Ok(self.records.values().cloned().collect())
    }

    fn upsert(&mut self, record: TrustRecord) -> Result<(), TrustStoreError> {
        validate_record(&record)?;
        if !self.records.contains_key(&record.peer_id) && self.records.len() >= self.max_records {
            return Err(limit_error());
        }
        let mut records = self.records.clone();
        records.insert(record.peer_id, record);
        self.replace(records)
    }

    fn remove(&mut self, peer_id: &PeerId) -> Result<bool, TrustStoreError> {
        let mut records = self.records.clone();
        let removed = records.remove(peer_id).is_some();
        if removed {
            self.replace(records)?;
        }
        Ok(removed)
    }

    fn revoke(&mut self, peer_id: &PeerId, now_unix_ms: u64) -> Result<(), TrustStoreError> {
        let mut records = self.records.clone();
        let record = records.get_mut(peer_id).ok_or_else(unknown_peer)?;
        record.key_state = KeyState::Revoked {
            revoked_at_unix_ms: now_unix_ms,
        };
        self.replace(records)
    }

    fn rotate(
        &mut self,
        old_peer_id: &PeerId,
        new_peer_id: PeerId,
        new_public_key: Vec<u8>,
        challenge_hash: [u8; 32],
        now_unix_ms: u64,
    ) -> Result<TrustRecord, TrustStoreError> {
        if new_public_key.is_empty() || &new_peer_id == old_peer_id {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Conflict,
                "identity rotation parameters conflict",
            ));
        }
        let mut records = self.records.clone();
        if records.contains_key(&new_peer_id) {
            return Err(TrustStoreError::new(
                TrustStoreErrorKind::Conflict,
                "new peer identity already exists",
            ));
        }
        if records.len() >= self.max_records {
            return Err(limit_error());
        }
        let old = records.get_mut(old_peer_id).ok_or_else(unknown_peer)?;
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
        validate_record(&replacement)?;
        old.key_state = KeyState::Rotated {
            rotated_at_unix_ms: now_unix_ms,
            new_peer_id,
        };
        records.insert(new_peer_id, replacement.clone());
        self.replace(records)?;
        Ok(replacement)
    }
}

fn unknown_peer() -> TrustStoreError {
    TrustStoreError::new(TrustStoreErrorKind::UnknownPeer, "peer has no trust record")
}

fn limit_error() -> TrustStoreError {
    TrustStoreError::new(
        TrustStoreErrorKind::LimitExceeded,
        "trust store limit exceeded",
    )
}

fn io_error(_error: std::io::Error) -> TrustStoreError {
    TrustStoreError::new(TrustStoreErrorKind::Io, "trust store I/O failed")
}

fn invalid_store() -> TrustStoreError {
    TrustStoreError::new(TrustStoreErrorKind::Corrupt, "trust store file is invalid")
}
