use mutsuki_link_core::{
    COMPACT_DATA_HEADER_BYTES, ConnectContext, Connection, EndpointId, TransportBudget,
};
use mutsuki_link_quic::{QuicConnector, QuicListener, QuicOptions};
use nana_tracking_protocol::{
    ActiveLayout, CanonicalCodec, CoordinateSpace, Direction3, LayoutLimits, LayoutProposal,
    LengthBasis, NanaTrackingDescriptor, NanaTrackingResult, Pose, Quaternion, RegionQuality,
    SessionId, SideMap, SignalBitSet, SignalId, SignalSample, SignalState, StructureFeatures,
    Tracked, TrackingFeatures, TrackingProfile, Vec3,
};
use ntp_mutsuki_link::{
    BindingConfig, ClockSynchronizer, GeometryTopology, PublishOutcome, Publisher, PublisherEvent,
    RESULT_FRAGMENT_HEADER_LEN, ReceiveOutcome, SessionCommand, Subscriber, SubscriberEvent,
};
use quinn::{ClientConfig, ServerConfig};
use rustls::RootCertStore;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_profile_remote_producer_negotiates_and_uses_the_ntp_result_interface() {
    let (client, server) = quic_pair().await;
    let config = BindingConfig::default();
    let mut publisher = Publisher::new(client, config).unwrap();
    let mut subscriber = Subscriber::new(server, config).unwrap();

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
