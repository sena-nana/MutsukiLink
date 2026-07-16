use mutsuki_link_core::*;
use std::collections::BTreeSet;

fn version(major: u16, minor: u16) -> ProtocolVersion {
    ProtocolVersion::new(major, minor)
}

fn range(major: u16, minimum: u16, maximum: u16) -> VersionRange {
    VersionRange::new(version(major, minimum), version(major, maximum))
}

fn compatible_link_versions() -> VersionRange {
    VersionRange::new(
        version(MIN_COMPATIBLE_LINK_PROTOCOL_VERSION, 0),
        version(LINK_PROTOCOL_VERSION, 1),
    )
}

fn release_offer() -> ProtocolOffer {
    ProtocolOffer::from_debug_namespace("example.release", range(1, 0, 1))
}

fn release_selection(version: ProtocolVersion) -> ProtocolSelection {
    let offer = release_offer();
    ProtocolSelection {
        stable_id: offer.stable_id,
        version,
        schema: offer.schema,
        capabilities: offer.capabilities,
    }
}

fn identity(value: u8) -> Identity {
    Identity {
        peer_id: PeerId::from_bytes([value; 32]),
        endpoint_id: EndpointId::from_bytes([value; 16]),
        connection_id: ConnectionId::from_bytes([value; 16]),
    }
}

fn handshake_config(value: u8) -> HandshakeConfig {
    HandshakeConfig {
        identity: identity(value),
        policy: HandshakePolicy {
            link_versions: compatible_link_versions(),
            link_capabilities: LinkCapabilities::COMPACT_CHANNEL_ID
                | LinkCapabilities::DATAGRAMS
                | LinkCapabilities::TYPED_CONTROL,
            protocols: vec![release_offer()],
            pairing_protocols: vec![release_offer()],
            allow_pairing: true,
            trusted_peers: BTreeSet::new(),
            max_protocol_offers: 2,
            max_identity_proof_bytes: 64,
        },
        challenge_nonce: [value; 32],
        identity_proof: IdentityProof {
            opaque: vec![value; 32],
        },
        session_id: SessionId::from_bytes([value; 16]),
    }
}

#[test]
fn current_previous_and_incompatible_versions_are_explicit() {
    let current = version(LINK_PROTOCOL_VERSION, 1);
    let previous = version(MIN_COMPATIBLE_LINK_PROTOCOL_VERSION, 0);
    let supported = compatible_link_versions();
    assert!(protocol_version_is_compatible(LINK_PROTOCOL_VERSION));
    assert!(!protocol_version_is_compatible(
        LINK_PROTOCOL_VERSION.saturating_add(1)
    ));
    assert_eq!(
        supported.negotiate(VersionRange::new(current, current)),
        Some(current)
    );
    assert_eq!(
        supported.negotiate(VersionRange::new(previous, previous)),
        Some(previous)
    );
    assert_eq!(supported.negotiate(range(99, 0, 1)), None);

    let mut responder = HandshakeMachine::responder(handshake_config(2));
    let incompatible = responder
        .receive(HandshakeFrame::Hello {
            identity: identity(1),
            link_versions: range(99, 0, 1),
            link_capabilities: LinkCapabilities::default(),
            protocols: vec![],
            requested_auth: AuthPath::FirstPairing,
        })
        .unwrap_err();
    assert_eq!(incompatible.kind, HandshakeErrorKind::IncompatibleVersion);
    assert_eq!(responder.state(), HandshakeState::Failed);
}

#[test]
fn duplicate_out_of_order_and_oversized_handshake_input_fail_closed() {
    let hello = HandshakeFrame::Hello {
        identity: identity(1),
        link_versions: compatible_link_versions(),
        link_capabilities: LinkCapabilities::COMPACT_CHANNEL_ID,
        protocols: vec![release_offer()],
        requested_auth: AuthPath::FirstPairing,
    };
    let mut responder = HandshakeMachine::responder(handshake_config(2));
    responder.receive(hello.clone()).unwrap();
    assert_eq!(
        responder.receive(hello).unwrap_err().kind,
        HandshakeErrorKind::UnexpectedMessage
    );

    let mut fresh = HandshakeMachine::responder(handshake_config(2));
    assert_eq!(
        fresh
            .receive(HandshakeFrame::IdentityProof(IdentityProof {
                opaque: vec![0; 65],
            }))
            .unwrap_err()
            .kind,
        HandshakeErrorKind::UnexpectedMessage
    );

    let mut oversized = HandshakeMachine::responder(handshake_config(2));
    assert_eq!(
        oversized
            .receive(HandshakeFrame::Hello {
                identity: identity(1),
                link_versions: compatible_link_versions(),
                link_capabilities: LinkCapabilities::default(),
                protocols: vec![
                    ProtocolOffer::from_debug_namespace("example.one", range(1, 0, 0)),
                    ProtocolOffer::from_debug_namespace("example.two", range(1, 0, 0)),
                    ProtocolOffer::from_debug_namespace("example.three", range(1, 0, 0)),
                ],
                requested_auth: AuthPath::FirstPairing,
            })
            .unwrap_err()
            .kind,
        HandshakeErrorKind::LimitExceeded
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn unknown_protocol_channel_and_malformed_envelopes_are_isolated() {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    let offer = release_offer();
    registry
        .register(ProtocolDescriptor {
            stable_id: offer.stable_id,
            debug_identity: offer.debug_identity,
            versions: range(1, 0, 1),
            schema: offer.schema,
            capabilities: offer.capabilities,
            channels: vec![ProtocolChannel {
                id: ProtocolChannelId(1),
                debug_name: Some("control".to_owned()),
                mode: ChannelMode::RequestResponse,
                priority: 0,
                max_frame_bytes: 8,
                max_stream_bytes: None,
                max_in_flight_frames: 1,
                discardable: false,
            }],
        })
        .unwrap();
    let registry = registry.freeze();
    let active = registry
        .activate(&[release_selection(version(1, 1))])
        .unwrap();
    assert_eq!(
        active
            .open_channel(ChannelOpenRequest {
                protocol_id: release_offer().stable_id,
                protocol_channel_id: ProtocolChannelId(99),
                channel_id: ChannelId(1),
                capacity: 1,
            })
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::ChannelNotDefined
    );
    assert_eq!(
        registry
            .activate(&[{
                let offer = ProtocolOffer::from_debug_namespace("example.unknown", range(1, 0, 0));
                ProtocolSelection {
                    stable_id: offer.stable_id,
                    version: version(1, 0),
                    schema: offer.schema,
                    capabilities: offer.capabilities,
                }
            }])
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::UnknownProtocol
    );

    let mut mux = Multiplexer::restricted(
        MultiplexerLimits {
            max_frame_bytes: 8,
            max_nesting_depth: 2,
            max_channels: 1,
            control_queue_capacity: 1,
            max_total_pending_frames: 1,
        },
        [("example.release".to_owned(), version(1, 1))],
    )
    .unwrap();
    let config = ChannelConfig {
        key: ChannelKey {
            namespace: "example.release".to_owned(),
            version: version(1, 1),
            id: ChannelId(1),
        },
        mode: ChannelMode::RequestResponse,
        priority_hint: 0,
        capacity: 1,
    };
    mux.open_channel(config.clone()).unwrap();
    let malformed = |sequence, nesting_depth, payload: Vec<u8>| Envelope {
        session_id: SessionId::from_bytes([1; 16]),
        channel: config.key.clone(),
        sequence,
        nesting_depth,
        flags: EnvelopeFlags::default(),
        payload,
    };
    assert!(matches!(
        mux.enqueue(malformed(1, 3, vec![])),
        Err(LinkError::LimitExceeded {
            kind: LimitKind::NestingDepth,
            ..
        })
    ));
    assert!(matches!(
        mux.enqueue(malformed(2, 0, vec![0; 9])),
        Err(LinkError::LimitExceeded {
            kind: LimitKind::FrameBytes,
            ..
        })
    ));
    mux.enqueue(malformed(3, 0, vec![1])).unwrap();
    assert!(matches!(
        mux.enqueue(malformed(3, 0, vec![2])),
        Err(LinkError::LimitExceeded {
            kind: LimitKind::PendingFrames,
            ..
        })
    ));
    assert_eq!(mux.pending_frames(), 1);
}

#[test]
fn lifecycle_and_reconnect_storms_remain_quiet_and_bounded() {
    let policy = HeartbeatPolicy::default();
    let mut heartbeat = HeartbeatController::new(policy, 0).unwrap();
    for now in 0..policy.idle_interval_ms {
        assert_eq!(
            heartbeat.tick(now, ConnectionActivityProfile::Idle),
            HeartbeatAction::None
        );
    }
    heartbeat.pause();
    assert_eq!(
        heartbeat.tick(u64::MAX, ConnectionActivityProfile::Background),
        HeartbeatAction::None
    );
    heartbeat.resume(1_000, ConnectionActivityProfile::Mobile);
    assert_eq!(
        heartbeat.tick(1_001, ConnectionActivityProfile::Mobile),
        HeartbeatAction::None
    );

    let mut reconnect = ReconnectController::new(
        ReconnectPolicy::ExponentialBackoff(ExponentialBackoff {
            initial_delay_ms: 10,
            maximum_delay_ms: 1_000,
            multiplier_per_thousand: 2_000,
            jitter_per_thousand: 100,
            limit: RetryLimit {
                max_attempts: 8,
                max_elapsed_ms: 30_000,
            },
        }),
        CancellationToken::default(),
    )
    .unwrap();
    for attempt in 1..=8 {
        assert!(matches!(
            reconnect.after_failure(ReconnectFailure::NetworkChanged, u64::from(attempt), 500),
            ReconnectAction::AttemptAt { attempt: observed, .. } if observed == attempt
        ));
    }
    for _ in 0..10_000 {
        assert_eq!(
            reconnect.after_failure(ReconnectFailure::TransportClosed, 100, 500),
            ReconnectAction::Stop(ReconnectStopReason::AttemptsExhausted)
        );
    }
}
