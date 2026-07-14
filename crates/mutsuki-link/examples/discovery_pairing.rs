use mutsuki_link::discovery::{
    DiscoveredEndpoint, DiscoveryEvent, DiscoveryId, DiscoveryProvider, DiscoveryRequest,
    ManualDiscovery, RateLimit,
};
use mutsuki_link::pairing::{LongTermIdentity, PairingId, PairingMethod, PairingSession};
use mutsuki_link::{EndpointAddress, PeerId, ProtocolVersion, SecurityLevel};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let mut discovery = ManualDiscovery::new(RateLimit {
        attempts: 4,
        window: Duration::from_secs(1),
        max_sources: 16,
        max_candidates: 32,
    })?;
    discovery.start(
        DiscoveryRequest {
            service_type: "_mutsuki-link._tcp.local.".to_owned(),
            max_results_per_poll: 4,
        },
        now,
    )?;
    discovery.add_address(
        "manual-qr",
        DiscoveryId::from_bytes([7; 16]),
        DiscoveredEndpoint {
            address: EndpointAddress {
                scheme: "quic".to_owned(),
                address: "192.0.2.10:4433".to_owned(),
            },
            priority: 0,
            advertised_security: SecurityLevel::AuthenticatedEncrypted,
        },
        Duration::from_secs(30),
        now,
    )?;

    let Some(DiscoveryEvent::Found(candidate)) = discovery.poll(now)?.into_iter().next() else {
        return Err("candidate was not discovered".into());
    };
    // Discovery output is intentionally untrusted. Only the explicit pairing
    // ceremony can produce a trusted PeerId and trust-store record.
    let session = PairingSession::initiator(
        LongTermIdentity {
            peer_id: PeerId::from_bytes([1; 32]),
            public_key: vec![2; 32],
            display_name: "desktop".to_owned(),
        },
        PairingId::from_bytes([3; 16]),
        ProtocolVersion::new(1, 0),
        [4; 32],
        PairingMethod::QrCode,
        60_000,
        false,
        8,
    )?;
    let offer = session.offer()?;
    println!(
        "discovered {} untrusted endpoint(s); present {:?} pairing for explicit approval",
        candidate.endpoints.len(),
        offer.method
    );
    discovery.stop()?;
    Ok(())
}
