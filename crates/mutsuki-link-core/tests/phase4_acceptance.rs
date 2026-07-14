use mutsuki_link_core::*;

fn endpoint(scheme: &str, address: &str) -> EndpointAddress {
    EndpointAddress {
        scheme: scheme.to_owned(),
        address: address.to_owned(),
    }
}

fn security_expectation() -> SecurityExpectation {
    SecurityExpectation {
        peer_id: PeerId::from_bytes([2; 32]),
        public_key_fingerprint: [3; 32],
        minimum_key_epoch: 4,
        handshake_transcript_hash: [5; 32],
        local_endpoint: endpoint("quic", "192.0.2.1:443"),
        remote_endpoint: endpoint("quic", "198.51.100.2:443"),
        link_version: ProtocolVersion::new(1, 0),
        now_unix_ms: 1_000,
    }
}

fn remote_security() -> TransportSecurityEvidence {
    let expected = security_expectation();
    TransportSecurityEvidence {
        transport: TransportKind::Quic,
        security_level: SecurityLevel::AuthenticatedEncrypted,
        mutually_authenticated: true,
        local_peer_credential_verified: false,
        development_plaintext: false,
        identity: IdentityEvidence {
            peer_id: expected.peer_id,
            public_key_fingerprint: expected.public_key_fingerprint,
            key_epoch: expected.minimum_key_epoch,
            status: IdentityStatus::Active {
                valid_until_unix_ms: 2_000,
            },
        },
        session_key: Some(SessionKeyBinding {
            key_id: [6; 32],
            forward_secure: true,
            handshake_transcript_hash: expected.handshake_transcript_hash,
            local_endpoint: expected.local_endpoint,
            remote_endpoint: expected.remote_endpoint,
            link_version: expected.link_version,
        }),
    }
}

#[test]
fn remote_security_is_mutual_forward_secure_bound_and_fail_closed() {
    let expected = security_expectation();
    let policy = SecurityPolicy::default();
    let mut evidence = remote_security();
    validate_transport_security(&evidence, &expected, policy).unwrap();
    let session = Session::established(negotiated(), MultiplexerLimits::default(), 1).unwrap();
    let authenticated = authenticate_session(session.info(), &evidence, &expected, policy).unwrap();
    assert_eq!(authenticated.info().peer_id, expected.peer_id);
    assert_eq!(authenticated.security().transport, TransportKind::Quic);

    evidence.identity.status = IdentityStatus::Revoked;
    assert_eq!(
        validate_transport_security(&evidence, &expected, policy)
            .unwrap_err()
            .kind,
        SecurityErrorKind::IdentityRevoked
    );
    evidence = remote_security();
    evidence.identity.key_epoch = 3;
    assert_eq!(
        validate_transport_security(&evidence, &expected, policy)
            .unwrap_err()
            .kind,
        SecurityErrorKind::KeyRotated
    );
    evidence = remote_security();
    evidence.identity.status = IdentityStatus::Active {
        valid_until_unix_ms: 1_000,
    };
    assert_eq!(
        validate_transport_security(&evidence, &expected, policy)
            .unwrap_err()
            .kind,
        SecurityErrorKind::IdentityExpired
    );
    evidence = remote_security();
    evidence.session_key.as_mut().unwrap().forward_secure = false;
    assert_eq!(
        validate_transport_security(&evidence, &expected, policy)
            .unwrap_err()
            .kind,
        SecurityErrorKind::ForwardSecrecyRequired
    );
    evidence = remote_security();
    evidence
        .session_key
        .as_mut()
        .unwrap()
        .handshake_transcript_hash = [9; 32];
    assert_eq!(
        validate_transport_security(&evidence, &expected, policy)
            .unwrap_err()
            .kind,
        SecurityErrorKind::TranscriptMismatch
    );
}

#[test]
fn plaintext_is_explicit_development_only_and_local_uses_peer_credentials() {
    let expected = security_expectation();
    let mut plaintext = remote_security();
    plaintext.transport = TransportKind::Tcp;
    plaintext.security_level = SecurityLevel::Plaintext;
    plaintext.development_plaintext = true;
    plaintext.session_key = None;
    assert_eq!(
        validate_transport_security(&plaintext, &expected, SecurityPolicy::default())
            .unwrap_err()
            .kind,
        SecurityErrorKind::PlaintextForbidden
    );
    validate_transport_security(
        &plaintext,
        &expected,
        SecurityPolicy {
            remote: RemoteSecurityPolicy::AllowExplicitDevelopmentPlaintext,
            forward_secrecy: ForwardSecrecyPolicy::Optional,
            local_peer_credential: LocalPeerCredentialPolicy::Required,
        },
    )
    .unwrap();

    let mut local = remote_security();
    local.transport = TransportKind::Local;
    local.security_level = SecurityLevel::Authenticated;
    local.local_peer_credential_verified = false;
    assert_eq!(
        validate_transport_security(&local, &expected, SecurityPolicy::default())
            .unwrap_err()
            .kind,
        SecurityErrorKind::LocalPeerCredentialRequired
    );
    local.local_peer_credential_verified = true;
    validate_transport_security(&local, &expected, SecurityPolicy::default()).unwrap();
}

#[test]
fn interrupted_network_reconnects_with_bounds_but_permanent_errors_stop() {
    let mut disabled =
        ReconnectController::new(ReconnectPolicy::Disabled, CancellationToken::default()).unwrap();
    assert_eq!(
        disabled.after_failure(ReconnectFailure::TransportClosed, 0, 0),
        ReconnectAction::Stop(ReconnectStopReason::Disabled)
    );
    let mut application = ReconnectController::new(
        ReconnectPolicy::ApplicationControlled,
        CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(
        application.after_failure(ReconnectFailure::NetworkChanged, 0, 0),
        ReconnectAction::AwaitApplication
    );
    let mut immediate = ReconnectController::new(
        ReconnectPolicy::Immediate(RetryLimit {
            max_attempts: 1,
            max_elapsed_ms: 1_000,
        }),
        CancellationToken::default(),
    )
    .unwrap();
    assert_eq!(
        immediate.after_failure(ReconnectFailure::SleepWake, 10, 0),
        ReconnectAction::AttemptAt {
            unix_ms: 10,
            attempt: 1
        }
    );
    assert_eq!(
        immediate.after_failure(ReconnectFailure::TransportClosed, 11, 0),
        ReconnectAction::Stop(ReconnectStopReason::AttemptsExhausted)
    );

    let config = ExponentialBackoff {
        initial_delay_ms: 100,
        maximum_delay_ms: 1_000,
        multiplier_per_thousand: 2_000,
        jitter_per_thousand: 200,
        limit: RetryLimit {
            max_attempts: 3,
            max_elapsed_ms: 10_000,
        },
    };
    let cancellation = CancellationToken::default();
    let mut reconnect = ReconnectController::new(
        ReconnectPolicy::ExponentialBackoff(config),
        cancellation.clone(),
    )
    .unwrap();
    assert_eq!(
        reconnect.after_failure(ReconnectFailure::TemporarilyUnreachable, 1_000, 500),
        ReconnectAction::AttemptAt {
            unix_ms: 1_100,
            attempt: 1
        }
    );
    assert_eq!(
        reconnect.after_failure(ReconnectFailure::NetworkChanged, 1_100, 500),
        ReconnectAction::AttemptAt {
            unix_ms: 1_300,
            attempt: 2
        }
    );
    assert_eq!(
        reconnect.after_failure(ReconnectFailure::PairingRevoked, 1_300, 500),
        ReconnectAction::Stop(ReconnectStopReason::PermanentFailure(
            ReconnectFailure::PairingRevoked
        ))
    );
    reconnect.reset();
    reconnect.pause();
    assert_eq!(
        reconnect.after_failure(ReconnectFailure::SleepWake, 2_000, 500),
        ReconnectAction::AwaitApplication
    );
    reconnect.resume();
    cancellation.cancel();
    assert_eq!(
        reconnect.after_failure(ReconnectFailure::TransportClosed, 2_000, 500),
        ReconnectAction::Stop(ReconnectStopReason::Cancelled)
    );
}

struct AcceptToken;

impl ResumeTokenVerifier for AcceptToken {
    fn verify(&self, offer: &ResumeOffer) -> bool {
        offer.token == b"authenticated-token"
    }
}

#[test]
fn resume_is_connection_only_and_never_replays_non_idempotent_requests() {
    let peer = PeerId::from_bytes([7; 32]);
    let previous = SessionId::from_bytes([8; 16]);
    let mut coordinator = ResumeCoordinator::new(ResumeLimits {
        max_pending_requests: 3,
        ..ResumeLimits::default()
    })
    .unwrap();
    coordinator
        .record_unacknowledged(1, RequestReplay::Idempotent)
        .unwrap();
    coordinator
        .record_unacknowledged(2, RequestReplay::Never)
        .unwrap();
    coordinator
        .record_unacknowledged(3, RequestReplay::ApplicationDecides)
        .unwrap();
    let offer = ResumeOffer {
        token: b"authenticated-token".to_vec(),
        peer_id: peer,
        previous_session_id: previous,
        expires_at_unix_ms: 5_000,
        channel_cursors: vec![ChannelCursor {
            channel: ChannelKey {
                namespace: "mutsuki.events".to_owned(),
                version: ProtocolVersion::new(1, 0),
                id: ChannelId(1),
            },
            cursor: b"owner-sequence-42".to_vec(),
        }],
    };
    let continuity = coordinator.validate_offer(&offer, peer, 1_000, &AcceptToken);
    assert_eq!(
        continuity,
        SessionContinuity::Resumed {
            previous_session_id: previous
        }
    );
    let plan = coordinator.plan_after_reconnect(continuity);
    assert_eq!(plan.automatically_retry, vec![1]);
    assert_eq!(plan.fail_without_retry, vec![2]);
    assert_eq!(plan.application_decision, vec![3]);

    assert_eq!(
        coordinator.validate_offer(&offer, peer, 5_000, &AcceptToken),
        SessionContinuity::NewSession {
            reason: NewSessionReason::TokenExpired
        }
    );
}

fn negotiated() -> NegotiatedSession {
    NegotiatedSession {
        session_id: SessionId::from_bytes([1; 16]),
        local: Identity {
            peer_id: PeerId::from_bytes([1; 32]),
            endpoint_id: EndpointId::from_bytes([1; 16]),
            connection_id: ConnectionId::from_bytes([1; 16]),
        },
        remote: Identity {
            peer_id: PeerId::from_bytes([2; 32]),
            endpoint_id: EndpointId::from_bytes([2; 16]),
            connection_id: ConnectionId::from_bytes([2; 16]),
        },
        link_version: ProtocolVersion::new(1, 0),
        protocols: vec![ProtocolSelection {
            namespace: "mutsuki.events".to_owned(),
            version: ProtocolVersion::new(1, 0),
        }],
        auth_path: AuthPath::TrustedReconnect,
    }
}

#[test]
fn upper_layer_receives_explicit_continuity_and_significant_quality_events() {
    let previous = SessionId::from_bytes([9; 16]);
    let mut session = Session::established(negotiated(), MultiplexerLimits::default(), 1).unwrap();
    let subscriber = session.events().subscribe(8).unwrap();
    session
        .report_continuity(SessionContinuity::Resumed {
            previous_session_id: previous,
        })
        .unwrap();
    assert!(matches!(
        session.events().next(subscriber),
        Some(SessionEvent::ContinuityChanged(SessionContinuity::Resumed {
            previous_session_id
        })) if previous_session_id == previous
    ));

    let mut accumulator = QualityAccumulator::new(TransportKind::Quic);
    let mut detector = QualityChangeDetector::new(QualityChangeThreshold::default());
    let first = accumulator.observe(QualityObservation {
        round_trip_millis: Some(20),
        sent_packets: 100,
        lost_packets: 1,
        retransmitted_packets: 2,
        transmitted_bytes: 1_000,
        received_bytes: 2_000,
        elapsed_ms: 1_000,
        send_queue_depth: 1,
        send_queue_capacity: 10,
        consecutive_failures: 0,
        liveness: LivenessState::Healthy,
    });
    assert_eq!(first.loss_per_million, Some(10_000));
    assert_eq!(first.send_queue_pressure_per_million, 100_000);
    assert_eq!(detector.consider(first), Some(first));
    assert_eq!(detector.consider(first), None);
}

#[test]
fn idle_heartbeat_uses_transport_signal_and_fixed_state() {
    let policy = HeartbeatPolicy {
        idle_interval_ms: 10,
        active_interval_ms: 5,
        mobile_interval_ms: 20,
        background_interval_ms: 100,
        local_ipc_interval_ms: 50,
        unreachable_after_ms: 30,
        dead_after_ms: 60,
    };
    let mut heartbeat = HeartbeatController::new(policy, 0).unwrap();
    assert_eq!(
        heartbeat.observe_latency(1, 250, 200),
        HeartbeatAction::StateChanged(LivenessState::LatencyElevated)
    );
    assert_eq!(
        heartbeat.observe_latency(2, 50, 200),
        HeartbeatAction::StateChanged(LivenessState::Healthy)
    );
    heartbeat.observe_transport_ack(9);
    assert_eq!(
        heartbeat.tick(10, ConnectionActivityProfile::Idle),
        HeartbeatAction::SuppressedByTransport
    );
    assert_eq!(
        heartbeat.tick(40, ConnectionActivityProfile::Idle),
        HeartbeatAction::StateChanged(LivenessState::TemporarilyUnreachable)
    );
    assert_eq!(
        heartbeat.tick(70, ConnectionActivityProfile::Idle),
        HeartbeatAction::StateChanged(LivenessState::Dead)
    );
    heartbeat.pause();
    assert_eq!(
        heartbeat.tick(1_000, ConnectionActivityProfile::Background),
        HeartbeatAction::None
    );
}

#[test]
fn saturated_lossy_channel_cannot_block_control_and_budgets_are_hard() {
    let limits = MultiplexerLimits {
        max_total_pending_frames: 1,
        ..MultiplexerLimits::default()
    };
    let mut mux = Multiplexer::new(limits).unwrap();
    let channel = ChannelConfig {
        key: ChannelKey {
            namespace: "mutsuki.events".to_owned(),
            version: ProtocolVersion::new(1, 0),
            id: ChannelId(1),
        },
        mode: ChannelMode::Event,
        priority_hint: u8::MAX,
        capacity: 1,
    };
    mux.open_channel(channel.clone()).unwrap();
    let frame = |sequence| Envelope {
        session_id: SessionId::from_bytes([1; 16]),
        channel: channel.key.clone(),
        sequence,
        nesting_depth: 0,
        flags: EnvelopeFlags::default(),
        payload: vec![1],
    };
    assert_eq!(
        mux.enqueue_discardable(frame(1)).unwrap(),
        QueueAdmission::Enqueued
    );
    assert_eq!(
        mux.enqueue_discardable(frame(2)).unwrap(),
        QueueAdmission::DroppedDiscardable
    );
    mux.enqueue_control(b"heartbeat".to_vec()).unwrap();
    assert_eq!(
        mux.next_outbound(),
        Some(OutboundFrame::Control(b"heartbeat".to_vec()))
    );

    let connection = ConnectionBudget {
        max_maintenance_operations_per_tick: 4,
        ..ConnectionBudget::default()
    };
    let mut maintenance = MaintenanceBudget::new(connection).unwrap();
    maintenance.set_mode(MaintenanceMode::Reduced);
    maintenance.begin_tick();
    assert!(maintenance.try_consume());
    assert!(!maintenance.try_consume());
    maintenance.set_mode(MaintenanceMode::Paused);
    maintenance.begin_tick();
    assert!(!maintenance.try_consume());
}
