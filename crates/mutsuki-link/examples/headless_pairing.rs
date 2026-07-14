use mutsuki_link::pairing::{
    LongTermIdentity, PairingId, PairingMethod, PairingOffer, PairingSession,
};
use mutsuki_link::{PeerId, ProtocolVersion};

enum PairingCommand {
    SendOffer(PairingOffer),
}

fn begin_mobile_desktop_pairing() -> Result<PairingCommand, Box<dyn std::error::Error>> {
    let session = PairingSession::initiator(
        LongTermIdentity {
            peer_id: PeerId::from_bytes([1; 32]),
            public_key: vec![2; 32],
            display_name: "desktop".to_owned(),
        },
        PairingId::from_bytes([3; 16]),
        ProtocolVersion::new(1, 0),
        [4; 32],
        PairingMethod::ShortCode,
        60_000,
        false,
        8,
    )?;
    Ok(PairingCommand::SendOffer(session.offer()?))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match begin_mobile_desktop_pairing()? {
        PairingCommand::SendOffer(offer) => {
            println!(
                "deliver {:?} pairing offer to the mobile/desktop UI adapter; expires at {}",
                offer.method, offer.expires_at_unix_ms
            );
        }
    }
    // The owner renders names, fingerprints, short code/QR and confirmation UI,
    // then supplies its real long-term-key `PairingCrypto` implementation.
    Ok(())
}
