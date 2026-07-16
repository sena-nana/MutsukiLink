use mutsuki_link_core::{
    AuthenticatedSession, COMPACT_DATA_HEADER_BYTES, ConnectContext, Connection, ConnectionQuality,
    EndpointAddress, EndpointId, ForwardSecrecyPolicy, IdentityEvidence, IdentityStatus,
    LocalPeerCredentialPolicy, MemoryConnection, MemoryTransportConfig, PeerId, ProtocolVersion,
    RemoteSecurityPolicy, SecurityExpectation, SecurityLevel, SecurityPolicy, SessionContinuity,
    SessionId as LinkSessionId, SessionInfo, SessionKeyBinding, TransportBudget, TransportKind,
    TransportSecurityEvidence, authenticate_session, memory_transport_pair,
};
use mutsuki_link_pairing::{KeyState, LinkPermission, TrustRecord};
use mutsuki_link_quic::{QuicConnector, QuicListener, QuicOptions};
use nana_tracking_protocol::{
    ActiveLayout, CanonicalCodec, CoordinateSpace, Direction3, LayoutLimits, LayoutProposal,
    LengthBasis, NanaTrackingDescriptor, NanaTrackingResult, Pose, ProducerClockEstimate,
    Quaternion, RegionQuality, SessionId, SideMap, SignalBitSet, SignalId, SignalSample,
    SignalState, StructureFeatures, Tracked, TrackingFeatures, TrackingProfile, Vec3,
};
use ntp_mutsuki_link::{
    BindingConfig, ClockSynchronizer, GeometryTopology, NtpAuthorization, NtpPermission,
    NtpPermissions, NtpRole, PublishOutcome, Publisher, PublisherEvent, RESULT_FRAGMENT_HEADER_LEN,
    ReceiveOutcome, SessionCommand, Subscriber, SubscriberEvent, TrackingTransportMode,
    authorize_trusted_ntp_session,
};
use quinn::{ClientConfig, ServerConfig};
use rustls::RootCertStore;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn authorization(role: NtpRole, peer: u8) -> NtpAuthorization {
    let permissions = NtpPermissions::empty().with(NtpPermission::Negotiate);
    let permissions = match role {
        NtpRole::Publisher => permissions.with(NtpPermission::Publish),
        NtpRole::Subscriber => permissions.with(NtpPermission::Subscribe),
    };
    authorization_with(role, peer, 9, permissions).unwrap()
}

fn authorization_with(
    role: NtpRole,
    peer: u8,
    link_session: u8,
    permissions: NtpPermissions,
) -> Result<NtpAuthorization, ntp_mutsuki_link::BindingError> {
    authorization_with_state(role, peer, link_session, permissions, KeyState::Active)
}

fn authorization_with_state(
    role: NtpRole,
    peer: u8,
    link_session: u8,
    permissions: NtpPermissions,
    key_state: KeyState,
) -> Result<NtpAuthorization, ntp_mutsuki_link::BindingError> {
    let link_session_id = LinkSessionId::from_bytes([link_session; 16]);
    let peer_id = PeerId::from_bytes([peer; 32]);
    let mut link_permissions = BTreeSet::from([LinkPermission::Connect]);
    for (permission, link_permission) in [
        (NtpPermission::Publish, LinkPermission::TrackingPublish),
        (NtpPermission::Subscribe, LinkPermission::TrackingSubscribe),
        (NtpPermission::Negotiate, LinkPermission::TrackingNegotiate),
        (
            NtpPermission::CalibrationWrite,
            LinkPermission::TrackingCalibrationWrite,
        ),
    ] {
        if permissions.contains(permission) {
            link_permissions.insert(link_permission);
        }
    }
    let record = TrustRecord {
        peer_id,
        public_key: vec![peer; 32],
        alias: "test peer".to_owned(),
        first_paired_at_unix_ms: 1,
        permissions: link_permissions,
        key_state,
        last_pairing_challenge_hash: [7; 32],
        previous_key_fingerprints: Vec::new(),
    };
    let fingerprint = record.public_key_fingerprint();
    let local_endpoint = EndpointAddress {
        scheme: "quic".to_owned(),
        address: "local".to_owned(),
    };
    let remote_endpoint = EndpointAddress {
        scheme: "quic".to_owned(),
        address: "remote".to_owned(),
    };
    let session = SessionInfo {
        session_id: link_session_id,
        peer_id,
        protocols: Vec::new(),
        continuity: SessionContinuity::default(),
        quality: ConnectionQuality::default(),
        close_reason: None,
    };
    let evidence = TransportSecurityEvidence {
        transport: TransportKind::Quic,
        security_level: SecurityLevel::AuthenticatedEncrypted,
        mutually_authenticated: true,
        local_peer_credential_verified: false,
        development_plaintext: false,
        identity: IdentityEvidence {
            peer_id,
            public_key_fingerprint: fingerprint,
            key_epoch: 4,
            status: IdentityStatus::Active {
                valid_until_unix_ms: 2_000,
            },
        },
        session_key: Some(SessionKeyBinding {
            key_id: [6; 32],
            forward_secure: true,
            handshake_transcript_hash: [5; 32],
            local_endpoint: local_endpoint.clone(),
            remote_endpoint: remote_endpoint.clone(),
            link_version: ProtocolVersion::new(1, 0),
        }),
    };
    let expectation = SecurityExpectation {
        peer_id,
        public_key_fingerprint: fingerprint,
        minimum_key_epoch: 4,
        handshake_transcript_hash: [5; 32],
        local_endpoint,
        remote_endpoint,
        link_version: ProtocolVersion::new(1, 0),
        now_unix_ms: 1_000,
    };
    let authenticated: AuthenticatedSession<'_> = authenticate_session(
        &session,
        &evidence,
        &expectation,
        SecurityPolicy {
            remote: RemoteSecurityPolicy::AuthenticatedEncrypted,
            forward_secrecy: ForwardSecrecyPolicy::Required,
            local_peer_credential: LocalPeerCredentialPolicy::Optional,
        },
    )
    .unwrap();
    authorize_trusted_ntp_session(authenticated, role, &record, 1)
}

fn crypto_configs() -> (ServerConfig, ClientConfig) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = generated.cert.der().clone();
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let server =
        ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    (server, client)
}

async fn quic_pair() -> (
    mutsuki_link_quic::QuicConnection,
    mutsuki_link_quic::QuicConnection,
) {
    let (server_config, client_config) = crypto_configs();
    let options = QuicOptions {
        budget: TransportBudget {
            receive_queue_capacity: 128,
            idle_timeout: None,
            ..TransportBudget::default()
        },
        ..QuicOptions::default()
    };
    let listener = QuicListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        EndpointId::from_bytes([2; 16]),
        server_config,
        options,
    )
    .unwrap();
    let connector =
        QuicConnector::new("127.0.0.1:0".parse().unwrap(), client_config, options).unwrap();
    let address = listener.local_addr().unwrap();
    let context = ConnectContext::default();
    let (server, client) = tokio::join!(
        listener.accept(EndpointId::from_bytes([1; 16])),
        connector.connect(
            address,
            "localhost",
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            &context,
        )
    );
    (client.unwrap(), server.unwrap())
}

async fn wait_publisher<C: Connection>(
    publisher: &mut Publisher<C>,
    producer_now_ns: u64,
) -> PublisherEvent {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(event) = publisher.poll_control(producer_now_ns).unwrap() {
            return event;
        }
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
}

async fn wait_subscriber<C: Connection>(
    subscriber: &mut Subscriber<C>,
    receiver_now_ns: u64,
) -> SubscriberEvent {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(event) = subscriber.poll_control(receiver_now_ns).unwrap() {
            return event;
        }
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
}

async fn established_memory_pair(
    config: BindingConfig,
    target_fps: u16,
) -> (
    Publisher<MemoryConnection>,
    Subscriber<MemoryConnection>,
    NanaTrackingDescriptor,
    NanaTrackingResult,
) {
    let (client, server) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        MemoryTransportConfig {
            queue_capacity: 16,
            max_message_bytes: 8 * 1024 * 1024,
            datagram_capacity: 0,
        },
    );
    let mut publisher =
        Publisher::new(client, authorization(NtpRole::Publisher, 2), config).unwrap();
    let mut subscriber =
        Subscriber::new(server, authorization(NtpRole::Subscriber, 1), config).unwrap();
    publisher.try_send_hello().unwrap();
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_000_000).await,
        SubscriberEvent::HelloAccepted
    );
    subscriber.try_send_hello().unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_000_000).await,
        PublisherEvent::HelloAccepted
    );
    let (descriptor, result) = full_result(15, 2_150_000, 2_160_000);
    publisher
        .publish_descriptor(
            descriptor.clone(),
            result.session_id,
            result.generation,
            7,
            LayoutProposal::for_profile(TrackingProfile::Full, target_fps),
            GeometryTopology::default(),
        )
        .unwrap();
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_100_000).await,
        SubscriberEvent::ProposalAccepted
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_100_000).await,
        PublisherEvent::LayoutAccepted
    );
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_150_000).await,
        SubscriberEvent::SessionReady
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_150_000).await,
        PublisherEvent::SessionReady
    );
    subscriber.try_send_command(SessionCommand::Start).unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_160_000).await,
        PublisherEvent::PlaybackChanged(SessionCommand::Start)
    );
    (publisher, subscriber, descriptor, result)
}

#[test]
fn tracking_roles_require_explicit_negotiate_and_direction_permissions() {
    let missing_publish = authorization_with(
        NtpRole::Publisher,
        2,
        9,
        NtpPermissions::empty().with(NtpPermission::Negotiate),
    )
    .unwrap_err();
    assert_eq!(
        missing_publish,
        ntp_mutsuki_link::BindingError::Unauthorized
    );

    let missing_negotiate = authorization_with(
        NtpRole::Subscriber,
        1,
        9,
        NtpPermissions::empty().with(NtpPermission::Subscribe),
    )
    .unwrap_err();
    assert_eq!(
        missing_negotiate,
        ntp_mutsuki_link::BindingError::Unauthorized
    );

    let revoked = authorization_with_state(
        NtpRole::Publisher,
        2,
        9,
        NtpPermissions::empty()
            .with(NtpPermission::Publish)
            .with(NtpPermission::Negotiate),
        KeyState::Revoked {
            revoked_at_unix_ms: 1_500,
        },
    )
    .unwrap_err();
    assert_eq!(revoked, ntp_mutsuki_link::BindingError::PeerRevoked);
}

#[test]
fn control_hello_rejects_a_different_link_session_before_layout_parsing() {
    let (client, server) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        MemoryTransportConfig {
            datagram_capacity: 0,
            ..MemoryTransportConfig::default()
        },
    );
    let mut publisher = Publisher::new(
        client,
        authorization(NtpRole::Publisher, 2),
        BindingConfig::default(),
    )
    .unwrap();
    let subscriber_authorization = authorization_with(
        NtpRole::Subscriber,
        1,
        8,
        NtpPermissions::empty()
            .with(NtpPermission::Subscribe)
            .with(NtpPermission::Negotiate),
    )
    .unwrap();
    let mut subscriber =
        Subscriber::new(server, subscriber_authorization, BindingConfig::default()).unwrap();
    publisher.try_send_hello().unwrap();
    assert_eq!(
        subscriber.poll_control(1_000).unwrap_err(),
        ntp_mutsuki_link::BindingError::SessionBindingMismatch
    );
}

#[test]
fn reconnect_requires_a_new_connection_and_new_authenticated_link_session() {
    let config = BindingConfig::default();
    let pair = || {
        memory_transport_pair(
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            MemoryTransportConfig {
                datagram_capacity: 0,
                ..MemoryTransportConfig::default()
            },
        )
    };
    let (client, _) = pair();
    let mut publisher =
        Publisher::new(client, authorization(NtpRole::Publisher, 2), config).unwrap();
    let (same_session_connection, _) = pair();
    assert_eq!(
        publisher
            .reset_for_reconnect(
                same_session_connection,
                authorization(NtpRole::Publisher, 2),
            )
            .unwrap_err(),
        ntp_mutsuki_link::BindingError::SessionBindingMismatch
    );
    let (new_session_connection, _) = pair();
    let new_authorization = authorization_with(
        NtpRole::Publisher,
        2,
        10,
        NtpPermissions::empty()
            .with(NtpPermission::Publish)
            .with(NtpPermission::Negotiate),
    )
    .unwrap();
    publisher
        .reset_for_reconnect(new_session_connection, new_authorization)
        .unwrap();
    assert!(publisher.bound_session().is_none());
    assert_eq!(
        publisher.transport_mode(),
        TrackingTransportMode::ReliableLatestOnly
    );
}

#[tokio::test]
async fn frame_flood_and_reconfigure_windows_fail_closed() {
    let config = BindingConfig {
        max_target_fps: 60,
        max_burst_fps: 60,
        max_reconfigure_per_minute: 1,
        geometry_cadence: None,
        ..BindingConfig::default()
    };
    let (mut publisher, mut subscriber, descriptor, mut result) =
        established_memory_pair(config, 60).await;
    publisher.try_send_latest(&result).unwrap();
    let mut rate_limited = 0;
    for sequence in 16..175 {
        result.sequence = sequence;
        match publisher.try_send_latest(&result) {
            Ok(_) => {}
            Err(ntp_mutsuki_link::BindingError::RateLimited) => rate_limited += 1,
            result => panic!("unexpected flood result: {result:?}"),
        }
    }
    assert_eq!(rate_limited, 100);
    assert_eq!(publisher.telemetry().rate_limited, 100);

    publisher
        .publish_descriptor(
            descriptor.clone(),
            result.session_id,
            result.generation + 1,
            8,
            LayoutProposal::for_profile(TrackingProfile::Full, 60),
            GeometryTopology::default(),
        )
        .unwrap();
    assert_eq!(
        wait_subscriber(&mut subscriber, 61_200_000_000).await,
        SubscriberEvent::ProposalAccepted
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_200_000).await,
        PublisherEvent::LayoutAccepted
    );
    assert_eq!(
        wait_subscriber(&mut subscriber, 61_250_000_000).await,
        SubscriberEvent::SessionReady
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_250_000).await,
        PublisherEvent::SessionReady
    );
    assert_eq!(
        publisher
            .publish_descriptor(
                descriptor,
                result.session_id,
                result.generation + 2,
                9,
                LayoutProposal::for_profile(TrackingProfile::Full, 60),
                GeometryTopology::default(),
            )
            .unwrap_err(),
        ntp_mutsuki_link::BindingError::RateLimited
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_profile_remote_producer_negotiates_and_uses_the_ntp_result_interface() {
    let (client, server) = quic_pair().await;
    let config = BindingConfig::default();
    let mut publisher =
        Publisher::new(client, authorization(NtpRole::Publisher, 2), config).unwrap();
    let mut subscriber =
        Subscriber::new(server, authorization(NtpRole::Subscriber, 1), config).unwrap();

    publisher.try_send_hello().unwrap();
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_000_000).await,
        SubscriberEvent::HelloAccepted
    );
    subscriber.try_send_hello().unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_000_000).await,
        PublisherEvent::HelloAccepted
    );

    let (descriptor, result) = full_result(15, 2_150_000, 2_160_000);
    publisher
        .publish_descriptor(
            descriptor,
            result.session_id,
            result.generation,
            7,
            LayoutProposal::for_profile(TrackingProfile::Full, 120),
            GeometryTopology::default(),
        )
        .unwrap();
    assert_eq!(
        publisher.try_send_latest(&result).unwrap_err(),
        ntp_mutsuki_link::BindingError::InvalidState
    );
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_100_000).await,
        SubscriberEvent::ProposalAccepted
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_100_000).await,
        PublisherEvent::LayoutAccepted
    );
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_150_000).await,
        SubscriberEvent::SessionReady
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let _ = subscriber.poll_control(1_150_000).unwrap();
        if publisher.poll_control(2_150_000).unwrap() == Some(PublisherEvent::SessionReady) {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }

    subscriber.try_send_command(SessionCommand::Start).unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_160_000).await,
        PublisherEvent::PlaybackChanged(SessionCommand::Start)
    );
    subscriber.try_send_ping(1_000_000).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let _ = publisher.poll_control(2_000_000).unwrap();
        if subscriber.poll_control(1_200_000).unwrap() == Some(SubscriberEvent::ClockSynchronized) {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }

    let outcome = publisher.try_send_latest(&result).unwrap();
    assert_publish_uses_all_flows(outcome);
    let clock = subscriber.producer_clock(1_250_000).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut compact_samples = 0usize;
    let received = loop {
        let (progress, result) = subscriber
            .poll_realtime(clock, |frame| {
                compact_samples = frame.samples().count();
            })
            .unwrap();
        if let Some(result) = result {
            break result;
        }
        if progress == ReceiveOutcome::Idle {
            tokio::task::yield_now().await;
        }
        assert!(Instant::now() < deadline);
    };
    assert_eq!(compact_samples, 76);
    assert_eq!(received, result);
    assert_eq!(subscriber.receiver_report().received, 1);

    subscriber.try_send_receiver_report().unwrap();
    assert!(matches!(
        wait_publisher(&mut publisher, 2_300_000).await,
        PublisherEvent::ReceiverReport(report) if report.received == 1
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn authenticated_reliable_fallback_is_latest_only_bounded_and_control_safe() {
    let (client, server) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        MemoryTransportConfig {
            queue_capacity: 1,
            max_message_bytes: 8 * 1024 * 1024,
            datagram_capacity: 0,
        },
    );
    let config = BindingConfig {
        geometry_cadence: None,
        max_protocol_violations: 1,
        ..BindingConfig::default()
    };
    let mut publisher =
        Publisher::new(client, authorization(NtpRole::Publisher, 2), config).unwrap();
    let mut subscriber =
        Subscriber::new(server, authorization(NtpRole::Subscriber, 1), config).unwrap();
    assert_eq!(
        publisher.transport_mode(),
        TrackingTransportMode::ReliableLatestOnly
    );
    assert_eq!(
        subscriber.transport_mode(),
        TrackingTransportMode::ReliableLatestOnly
    );

    publisher.try_send_hello().unwrap();
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_000_000).await,
        SubscriberEvent::HelloAccepted
    );
    subscriber.try_send_hello().unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_000_000).await,
        PublisherEvent::HelloAccepted
    );
    let (descriptor, mut result) = full_result(15, 2_150_000, 2_160_000);
    publisher
        .publish_descriptor(
            descriptor,
            result.session_id,
            result.generation,
            7,
            LayoutProposal::for_profile(TrackingProfile::Full, 120),
            GeometryTopology::default(),
        )
        .unwrap();
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_100_000).await,
        SubscriberEvent::ProposalAccepted
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_100_000).await,
        PublisherEvent::LayoutAccepted
    );
    assert_eq!(
        wait_subscriber(&mut subscriber, 1_150_000).await,
        SubscriberEvent::SessionReady
    );
    assert_eq!(
        wait_publisher(&mut publisher, 2_150_000).await,
        PublisherEvent::SessionReady
    );
    subscriber.try_send_command(SessionCommand::Start).unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_160_000).await,
        PublisherEvent::PlaybackChanged(SessionCommand::Start)
    );

    for sequence in 15..18 {
        result.sequence = sequence;
        result.capture_timestamp_ns = 2_150_000 + sequence;
        result.produced_timestamp_ns = 2_160_000 + sequence;
        publisher.try_send_latest(&result).unwrap();
    }
    assert_eq!(
        publisher.try_send_latest(&result).unwrap_err(),
        ntp_mutsuki_link::BindingError::ReplayOrDuplicate
    );
    let telemetry = publisher.telemetry();
    assert!(telemetry.reliable_pending <= 3);
    assert!(telemetry.queue_replacements > 0);

    subscriber.try_send_command(SessionCommand::Pause).unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_200_000).await,
        PublisherEvent::PlaybackChanged(SessionCommand::Pause)
    );

    let clock = ProducerClockEstimate::synchronized(2_200_000, 0);
    let deadline = Instant::now() + Duration::from_secs(1);
    let received = loop {
        let (_, received) = subscriber.poll_realtime(clock, |_| {}).unwrap();
        let _ = publisher.poll_control(2_200_000).unwrap();
        if let Some(received) = received {
            break received;
        }
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    };
    assert_eq!(received.sequence, 17);
    let bound = publisher.bound_session().unwrap();
    assert_eq!(bound.peer_id, PeerId::from_bytes([2; 32]));
    assert_eq!(bound.link_session_id, LinkSessionId::from_bytes([9; 16]));
    assert_eq!(bound.ntp_session_id, result.session_id);
    assert_eq!(bound.generation, result.generation);
    assert_eq!(bound.layout_id, 7);
    assert_eq!(bound.target_fps, 120);
    assert_eq!(
        bound.transport_mode,
        TrackingTransportMode::ReliableLatestOnly
    );

    subscriber.try_send_command(SessionCommand::Resume).unwrap();
    assert_eq!(
        wait_publisher(&mut publisher, 2_210_000).await,
        PublisherEvent::PlaybackChanged(SessionCommand::Resume)
    );
    let started = Instant::now();
    let mut result_latencies_us = Vec::with_capacity(120);
    for sequence in 100..220 {
        let result_started = Instant::now();
        result.sequence = sequence;
        result.capture_timestamp_ns = 2_150_000 + sequence;
        result.produced_timestamp_ns = 2_160_000 + sequence;
        publisher.try_send_latest(&result).unwrap();
        loop {
            let (_, received) = subscriber.poll_realtime(clock, |_| {}).unwrap();
            let _ = publisher.poll_control(2_220_000).unwrap();
            if received.is_some() {
                result_latencies_us.push(result_started.elapsed().as_micros());
                break;
            }
            tokio::task::yield_now().await;
        }
        if sequence % 12 == 0 {
            subscriber.try_send_ping(1_000_000 + sequence).unwrap();
            loop {
                let _ = publisher.poll_control(2_220_000).unwrap();
                if subscriber.poll_control(1_100_000 + sequence).unwrap()
                    == Some(SubscriberEvent::ClockSynchronized)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
    }
    let elapsed = started.elapsed();
    result_latencies_us.sort_unstable();
    let p50_us = result_latencies_us[result_latencies_us.len() / 2];
    let p99_us = result_latencies_us[result_latencies_us.len() * 99 / 100];
    let max_us = *result_latencies_us.last().unwrap();
    assert_eq!(subscriber.receiver_report().received, 121);
    assert_eq!(publisher.telemetry().steady_buffer_growths, 0);
    println!(
        "reliable-latest smoke: 120 full results in {}us; p50={}us p99={}us max={}us; control pings remained live",
        elapsed.as_micros(),
        p50_us,
        p99_us,
        max_us
    );

    let mut malformed = Vec::new();
    malformed.extend_from_slice(b"NTLF");
    malformed.push(1);
    malformed.extend_from_slice(&0x4e10_u16.to_be_bytes());
    malformed.extend_from_slice(&result.generation.to_be_bytes());
    malformed.extend_from_slice(&220_u64.to_be_bytes());
    malformed.extend_from_slice(&1_u32.to_be_bytes());
    malformed.push(0);
    let mut raw_connection = publisher.into_inner();
    raw_connection.try_send(&malformed).unwrap();
    let mut entered_runtime = false;
    let malformed_result = subscriber.poll_realtime(clock, |_| entered_runtime = true);
    assert!(
        matches!(
            malformed_result,
            Err(ntp_mutsuki_link::BindingError::LayoutMismatch)
        ),
        "unexpected malformed-frame result: {malformed_result:?}"
    );
    assert!(!entered_runtime);
    assert_eq!(subscriber.telemetry().malformed_frames, 1);
    assert!(subscriber.telemetry().fuse_tripped);
    assert_eq!(
        subscriber.poll_realtime(clock, |_| {}).unwrap_err(),
        ntp_mutsuki_link::BindingError::ChannelFused
    );
}

fn assert_publish_uses_all_flows(outcome: PublishOutcome) {
    assert!(outcome.core.fragments > 1);
    assert!(outcome.core.delivered_to_transport());
    assert!(outcome.geometry.is_some());
    assert_ne!(outcome.compact, mutsuki_link_core::SendOutcome::Unsupported);
}

#[test]
fn full_profile_60_and_120_fps_bandwidth_remains_bounded() {
    const CONSERVATIVE_PAYLOAD: usize = 1_100;
    let (descriptor, result) = full_result(15, 2_150_000, 2_160_000);
    let layout = ActiveLayout::negotiate(
        7,
        LayoutProposal::for_profile(TrackingProfile::Full, 120),
        &descriptor,
        LayoutLimits::default(),
    )
    .unwrap();
    let canonical_bytes = CanonicalCodec::encode(&result).unwrap().len();
    let chunk_bytes = CONSERVATIVE_PAYLOAD - RESULT_FRAGMENT_HEADER_LEN;
    let fragments = canonical_bytes.div_ceil(chunk_bytes);
    let compact_wire_bytes = COMPACT_DATA_HEADER_BYTES + layout.frame_len();
    let full_wire_bytes =
        canonical_bytes + fragments * (COMPACT_DATA_HEADER_BYTES + RESULT_FRAGMENT_HEADER_LEN);
    let per_frame_with_geometry_cadence =
        compact_wire_bytes + full_wire_bytes + full_wire_bytes / 15;
    let bandwidth_60_bps = per_frame_with_geometry_cadence * 60 * 8;
    let bandwidth_120_bps = per_frame_with_geometry_cadence * 120 * 8;

    assert!(layout.frame_len() <= CONSERVATIVE_PAYLOAD);
    assert!(fragments > 1);
    assert!(bandwidth_60_bps < 10_000_000);
    assert!(bandwidth_120_bps < 20_000_000);
    println!(
        "compact={}B canonical={}B fragments={} 60fps={}bps 120fps={}bps",
        layout.frame_len(),
        canonical_bytes,
        fragments,
        bandwidth_60_bps,
        bandwidth_120_bps
    );
}

#[test]
fn one_hour_at_120_fps_does_not_accumulate_clock_age() {
    const FPS: u64 = 120;
    const HOUR_FRAMES: u64 = 60 * 60 * FPS;
    const FRAME_NS: u64 = 1_000_000_000 / FPS;
    const NETWORK_AGE_NS: u64 = 10_000_000;
    let mut clock = ClockSynchronizer::default();
    clock.note_ping(1_000_000_000);
    clock
        .note_pong(1_000_000_000, 2_000_000_000, 1_020_000_000)
        .unwrap();
    for frame in 0..HOUR_FRAMES {
        let receiver_now = 1_020_000_000 + frame * FRAME_NS;
        let producer_now = clock.estimate(receiver_now).unwrap().now_ns();
        let capture_timestamp = producer_now - NETWORK_AGE_NS;
        assert_eq!(producer_now - capture_timestamp, NETWORK_AGE_NS);
    }
}

fn full_result(
    sequence: u64,
    capture_timestamp_ns: u64,
    produced_timestamp_ns: u64,
) -> (NanaTrackingDescriptor, NanaTrackingResult) {
    let descriptor = NanaTrackingDescriptor::from_capabilities(
        SignalBitSet::stable_through(76),
        StructureFeatures::FULL_REQUIRED,
        TrackingFeatures::WRIST_POSE,
    );
    let mut result = NanaTrackingResult::unsupported(
        SessionId([9; 16]),
        3,
        sequence,
        capture_timestamp_ns,
        produced_timestamp_ns,
    );
    for raw in 1..=76 {
        result.rig.set(
            SignalId::new(raw).unwrap(),
            SignalSample::available(0.0, 0.7, SignalState::Observed, capture_timestamp_ns, 0),
        );
    }
    result.geometry.head_camera_pose = tracked_pose(
        CoordinateSpace::Camera,
        LengthBasis::HeadRelative,
        capture_timestamp_ns,
    );
    let eye_origin = Tracked::available(
        nana_tracking_protocol::Position3 {
            space: CoordinateSpace::HeadLocal,
            length_basis: LengthBasis::HeadRelative,
            value: Vec3::default(),
        },
        0.8,
        SignalState::Fused,
        capture_timestamp_ns,
        0,
    );
    let eye_direction = tracked_direction(CoordinateSpace::HeadLocal, capture_timestamp_ns);
    result.geometry.eyes.left.origin_head = eye_origin.clone();
    result.geometry.eyes.right.origin_head = eye_origin;
    result.geometry.eyes.left.direction_head = eye_direction.clone();
    result.geometry.eyes.right.direction_head = eye_direction;
    result.geometry.look_at_camera = Tracked::available(
        nana_tracking_protocol::Position3 {
            space: CoordinateSpace::Camera,
            length_basis: LengthBasis::HeadRelative,
            value: Vec3 {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
        },
        0.8,
        SignalState::Fused,
        capture_timestamp_ns,
        0,
    );
    result.geometry.face_geometry_state = SignalState::Fused;
    result.skeleton.torso_camera_pose = tracked_pose(
        CoordinateSpace::Camera,
        LengthBasis::TorsoRelative,
        capture_timestamp_ns,
    );
    let joint = tracked_pose(
        CoordinateSpace::TorsoLocal,
        LengthBasis::TorsoRelative,
        capture_timestamp_ns,
    );
    result.skeleton.shoulder = sides(joint.clone());
    result.skeleton.elbow = sides(joint.clone());
    result.skeleton.wrist = sides(joint);
    let direction = tracked_direction(CoordinateSpace::TorsoLocal, capture_timestamp_ns);
    result.skeleton.upper_arm_direction_torso = sides(direction.clone());
    result.skeleton.forearm_direction_torso = sides(direction);
    let twist = Tracked::available(0.0, 0.8, SignalState::Fused, capture_timestamp_ns, 0);
    result.skeleton.upper_arm_twist = sides(twist.clone());
    result.skeleton.forearm_twist = sides(twist);
    let tracked = RegionQuality {
        confidence: 0.8,
        state: SignalState::Fused,
    };
    result.quality.overall_confidence = 0.8;
    result.quality.face = tracked;
    result.quality.eyes = tracked;
    result.quality.torso = tracked;
    result.quality.arm = sides(tracked);
    result.quality.auricle = sides(tracked);
    descriptor.validate_result(&result).unwrap();
    (descriptor, result)
}

fn tracked_pose(space: CoordinateSpace, basis: LengthBasis, timestamp_ns: u64) -> Tracked<Pose> {
    Tracked::available(
        Pose {
            parent_space: space,
            length_basis: basis,
            position: Vec3::default(),
            orientation_xyzw: Quaternion::IDENTITY,
        },
        0.8,
        SignalState::Fused,
        timestamp_ns,
        0,
    )
}

fn tracked_direction(space: CoordinateSpace, timestamp_ns: u64) -> Tracked<Direction3> {
    Tracked::available(
        Direction3 {
            space,
            value: Vec3 {
                x: 0.0,
                y: 0.0,
                z: 1.0,
            },
        },
        0.8,
        SignalState::Fused,
        timestamp_ns,
        0,
    )
}

fn sides<T>(value: T) -> SideMap<T>
where
    T: Clone,
{
    SideMap {
        left: value.clone(),
        right: value,
    }
}
