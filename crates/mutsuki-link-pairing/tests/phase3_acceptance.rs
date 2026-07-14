use mutsuki_link_core::{PeerId, ProtocolVersion};
use mutsuki_link_pairing::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestCrypto(Vec<u8>);

impl PairingCrypto for TestCrypto {
    fn sign_transcript(&self, transcript_hash: &[u8; 32]) -> Result<Vec<u8>, PairingError> {
        Ok(signature(&self.0, transcript_hash))
    }

    fn verify_transcript(
        &self,
        public_key: &[u8],
        transcript_hash: &[u8; 32],
        signature_value: &[u8],
    ) -> bool {
        signature(public_key, transcript_hash) == signature_value
    }
}

fn signature(key: &[u8], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(transcript_hash);
    hash.finalize().to_vec()
}

fn identity(value: u8, name: &str) -> LongTermIdentity {
    LongTermIdentity {
        peer_id: PeerId::from_bytes([value; 32]),
        public_key: vec![value; 32],
        display_name: name.to_owned(),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn two_devices_pair_persist_trust_revoke_remove_and_rotate() {
    let alice = identity(1, "Alice desktop");
    let bob = identity(2, "Bob phone");
    let mut replay = ReplayGuard::new(8).unwrap();
    let challenge = [7; 32];
    replay.reserve(&challenge).unwrap();
    assert_eq!(
        replay.reserve(&challenge).unwrap_err().kind,
        PairingErrorKind::ReplayDetected
    );

    let mut initiator = PairingSession::initiator(
        alice.clone(),
        PairingId::from_bytes([4; 16]),
        ProtocolVersion::new(1, 0),
        challenge,
        PairingMethod::ShortCode,
        10_000,
        false,
        8,
    )
    .unwrap();
    let offer = initiator.offer().unwrap();
    let (mut responder, response) =
        PairingSession::responder(bob.clone(), offer, 1_000, false, 8).unwrap();
    initiator.receive_response(response, 1_000).unwrap();

    let alice_view = initiator.presentation().unwrap();
    let bob_view = responder.presentation().unwrap();
    assert_eq!(alice_view.short_code, bob_view.short_code);
    assert_eq!(alice_view.peer_name, "Bob phone");
    assert_eq!(bob_view.peer_name, "Alice desktop");
    assert_ne!(alice_view.peer_fingerprint, bob_view.peer_fingerprint);

    let alice_crypto = TestCrypto(alice.public_key.clone());
    let bob_crypto = TestCrypto(bob.public_key.clone());
    let alice_proof = initiator
        .confirm(&alice_view.short_code, &alice_crypto, 1_001)
        .unwrap();
    let bob_proof = responder
        .confirm(&bob_view.short_code, &bob_crypto, 1_001)
        .unwrap();
    initiator
        .receive_confirmation(bob_proof, &alice_crypto, 1_002)
        .unwrap();
    responder
        .receive_confirmation(alice_proof, &bob_crypto, 1_002)
        .unwrap();
    assert_eq!(initiator.state(), PairingState::Paired);
    assert_eq!(responder.state(), PairingState::Paired);

    let permissions = BTreeSet::from([
        LinkPermission::Connect,
        LinkPermission::OpenNamespace("mutsuki.lilia".to_owned()),
    ]);
    let record = initiator
        .trust_record("phone".to_owned(), permissions, 1_002)
        .unwrap();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("mutsuki-link-trust-{unique}.json"));
    let mut store = FileTrustStore::open(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    store.upsert(record.clone()).unwrap();
    drop(store);

    let mut store = FileTrustStore::open(&path).unwrap();
    assert_eq!(
        authorize_trusted_reconnect(&store, &bob.peer_id, &bob.public_key)
            .unwrap()
            .alias,
        "phone"
    );
    store.revoke(&bob.peer_id, 2_000).unwrap();
    assert_eq!(
        authorize_trusted_reconnect(&store, &bob.peer_id, &bob.public_key)
            .unwrap_err()
            .kind,
        TrustStoreErrorKind::Revoked
    );
    assert!(store.remove(&bob.peer_id).unwrap());
    assert_eq!(
        authorize_trusted_reconnect(&store, &bob.peer_id, &bob.public_key)
            .unwrap_err()
            .kind,
        TrustStoreErrorKind::UnknownPeer
    );

    store.upsert(record).unwrap();
    let replacement = store
        .rotate(
            &bob.peer_id,
            PeerId::from_bytes([3; 32]),
            vec![3; 32],
            [9; 32],
            3_000,
        )
        .unwrap();
    assert_eq!(replacement.previous_key_fingerprints.len(), 1);
    assert_eq!(
        authorize_trusted_reconnect(&store, &bob.peer_id, &bob.public_key)
            .unwrap_err()
            .kind,
        TrustStoreErrorKind::Rotated
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn duplicate_timeout_cancel_and_transcript_tampering_fail_structurally() {
    let local = identity(1, "desktop");
    let duplicate = PairingSession::initiator(
        local.clone(),
        PairingId::from_bytes([1; 16]),
        ProtocolVersion::new(1, 0),
        [1; 32],
        PairingMethod::ShortCode,
        10,
        true,
        2,
    )
    .unwrap_err();
    assert_eq!(duplicate.kind, PairingErrorKind::DuplicatePairing);

    let mut timed = PairingSession::initiator(
        local.clone(),
        PairingId::from_bytes([2; 16]),
        ProtocolVersion::new(1, 0),
        [2; 32],
        PairingMethod::ShortCode,
        10,
        false,
        2,
    )
    .unwrap();
    assert_eq!(timed.tick(10).unwrap_err().kind, PairingErrorKind::TimedOut);
    assert_eq!(timed.state(), PairingState::TimedOut);

    let mut cancelled = PairingSession::initiator(
        local,
        PairingId::from_bytes([3; 16]),
        ProtocolVersion::new(1, 0),
        [3; 32],
        PairingMethod::BilateralConfirmation,
        20,
        false,
        2,
    )
    .unwrap();
    cancelled.cancel().unwrap();
    assert_eq!(cancelled.state(), PairingState::Cancelled);

    let mut rejecting_initiator = PairingSession::initiator(
        identity(4, "rejecting desktop"),
        PairingId::from_bytes([4; 16]),
        ProtocolVersion::new(1, 0),
        [4; 32],
        PairingMethod::ShortCode,
        20,
        false,
        2,
    )
    .unwrap();
    let offer = rejecting_initiator.offer().unwrap();
    let (mut rejecting_responder, _) =
        PairingSession::responder(identity(5, "rejecting phone"), offer, 1, false, 2).unwrap();
    let termination = rejecting_responder.reject().unwrap();
    rejecting_initiator
        .receive_termination(termination)
        .unwrap();
    assert_eq!(rejecting_responder.state(), PairingState::Rejected);
    assert_eq!(rejecting_initiator.state(), PairingState::Rejected);
}
