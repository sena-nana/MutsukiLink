use mutsuki_link_core::*;

fn versions(major: u16, minimum: u16, maximum: u16) -> VersionRange {
    VersionRange::new(
        ProtocolVersion::new(major, minimum),
        ProtocolVersion::new(major, maximum),
    )
}

fn channel(
    name: &str,
    mode: ChannelMode,
    priority: u8,
    max_frame_bytes: usize,
    max_stream_bytes: Option<u64>,
    discardable: bool,
) -> ProtocolChannel {
    ProtocolChannel {
        id: protocol_channel_id(name),
        debug_name: Some(name.to_owned()),
        mode,
        priority,
        max_frame_bytes,
        max_stream_bytes,
        max_in_flight_frames: 8,
        discardable,
    }
}

fn protocol_channel_id(name: &str) -> ProtocolChannelId {
    ProtocolChannelId(match name {
        "command" | "control" | "request" | "stream" => 1,
        "debug" | "resource" => 2,
        "file" | "result" => 3,
        "event" => 4,
        _ => 99,
    })
}

fn offer(namespace: &str, supported: VersionRange) -> ProtocolOffer {
    ProtocolOffer::from_debug_namespace(namespace, supported)
}

fn descriptor(
    namespace: &str,
    supported: VersionRange,
    channels: Vec<ProtocolChannel>,
) -> ProtocolDescriptor {
    let offer = offer(namespace, supported);
    ProtocolDescriptor {
        stable_id: offer.stable_id,
        debug_identity: offer.debug_identity,
        versions: supported,
        schema: offer.schema,
        capabilities: offer.capabilities,
        channels,
    }
}

fn product_registry() -> FrozenProtocolRegistry {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    registry
        .register(descriptor(
            "lilia.code",
            versions(1, 0, 2),
            vec![
                channel(
                    "command",
                    ChannelMode::RequestResponse,
                    10,
                    64 * 1024,
                    None,
                    false,
                ),
                channel("debug", ChannelMode::Event, 100, 32 * 1024, None, true),
                channel(
                    "file",
                    ChannelMode::Stream,
                    80,
                    1024 * 1024,
                    Some(8 * 1024 * 1024 * 1024),
                    false,
                ),
                channel("event", ChannelMode::Event, 60, 64 * 1024, None, true),
            ],
        ))
        .unwrap();
    registry
        .register(descriptor(
            "mutsuki.distributed.cluster",
            versions(2, 0, 1),
            vec![
                channel(
                    "control",
                    ChannelMode::RequestResponse,
                    0,
                    64 * 1024,
                    None,
                    false,
                ),
                channel(
                    "resource",
                    ChannelMode::Stream,
                    50,
                    1024 * 1024,
                    Some(16 * 1024 * 1024 * 1024),
                    false,
                ),
                channel(
                    "result",
                    ChannelMode::Stream,
                    40,
                    1024 * 1024,
                    Some(16 * 1024 * 1024 * 1024),
                    false,
                ),
            ],
        ))
        .unwrap();
    registry.freeze()
}

#[test]
fn independent_protocols_share_link_without_sharing_business_messages() {
    let registry = product_registry();
    let offers = registry.offers();
    assert_eq!(offers.len(), 2);
    let selections = registry
        .negotiate(&[
            offer("lilia.code", versions(1, 1, 1)),
            offer("mutsuki.distributed.cluster", versions(2, 0, 0)),
        ])
        .unwrap();
    assert_eq!(selections.len(), 2);
    let active = registry.activate(&selections).unwrap();
    assert_eq!(active.len(), 2);

    let lilia = active
        .open_channel(ChannelOpenRequest {
            protocol_id: offer("lilia.code", versions(1, 0, 2)).stable_id,
            protocol_channel_id: protocol_channel_id("file"),
            channel_id: ChannelId(1),
            capacity: 4,
        })
        .unwrap();
    let distributed = active
        .open_channel(ChannelOpenRequest {
            protocol_id: offer("mutsuki.distributed.cluster", versions(2, 0, 1)).stable_id,
            protocol_channel_id: protocol_channel_id("control"),
            channel_id: ChannelId(2),
            capacity: 2,
        })
        .unwrap();
    assert_ne!(
        lilia.config().key.protocol_id,
        distributed.config().key.protocol_id
    );
    assert_eq!(lilia.config().mode, ChannelMode::Stream);
    assert_eq!(distributed.config().mode, ChannelMode::RequestResponse);
    assert_eq!(
        lilia.accepted_mapping(),
        AcceptChannel {
            protocol_id: lilia.protocol_id(),
            protocol_channel_id: protocol_channel_id("file"),
            session_channel_id: ChannelId(1),
        }
    );

    let mut mux = Multiplexer::restricted(
        SessionId::from_bytes([1; 16]),
        MultiplexerLimits::default(),
        selections
            .iter()
            .map(|selection| (selection.stable_id, selection.version)),
    )
    .unwrap();
    mux.open_channel(lilia.config().clone()).unwrap();
    mux.open_channel(distributed.config().clone()).unwrap();
}

#[test]
fn one_incompatible_protocol_is_disabled_without_breaking_the_other() {
    let registry = product_registry();
    let selections = registry
        .negotiate(&[
            offer("lilia.code", versions(9, 0, 0)),
            offer("mutsuki.distributed.cluster", versions(2, 1, 3)),
        ])
        .unwrap();
    assert_eq!(selections.len(), 1);
    assert_eq!(
        selections[0].stable_id,
        offer("mutsuki.distributed.cluster", versions(2, 0, 1)).stable_id
    );
    let active = registry.activate(&selections).unwrap();
    assert!(!active.contains(&ProtocolId::new("lilia.code").unwrap()));
    assert!(active.contains(&ProtocolId::new("mutsuki.distributed.cluster").unwrap()));
    assert_eq!(
        active
            .open_channel(ChannelOpenRequest {
                protocol_id: offer("lilia.code", versions(1, 0, 2)).stable_id,
                protocol_channel_id: protocol_channel_id("command"),
                channel_id: ChannelId(1),
                capacity: 1,
            })
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::ProtocolNotNegotiated
    );
}

#[test]
fn activation_rejects_capabilities_not_selected_from_frozen_descriptor() {
    let registry = product_registry();
    let mut selection = registry
        .negotiate(&[offer("lilia.code", versions(1, 0, 2))])
        .unwrap()
        .remove(0);
    selection.capabilities.words = vec![1];
    assert_eq!(
        registry.activate(&[selection]).unwrap_err().kind,
        ProtocolRegistryErrorKind::InvalidCapabilities
    );
}

#[test]
fn channel_shape_frame_stream_and_queue_limits_are_enforced() {
    let registry = product_registry();
    let selections = registry
        .negotiate(&[offer("lilia.code", versions(1, 0, 2))])
        .unwrap();
    let active = registry.activate(&selections).unwrap();
    let file = active
        .open_channel(ChannelOpenRequest {
            protocol_id: offer("lilia.code", versions(1, 0, 2)).stable_id,
            protocol_channel_id: protocol_channel_id("file"),
            channel_id: ChannelId(1),
            capacity: 8,
        })
        .unwrap();
    file.validate_payload(1024 * 1024, Some(8 * 1024 * 1024 * 1024))
        .unwrap();
    assert_eq!(
        file.validate_payload(1024 * 1024 + 1, None)
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::FrameLimitExceeded
    );
    assert_eq!(
        file.validate_payload(1, Some(8 * 1024 * 1024 * 1024 + 1))
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::StreamLimitExceeded
    );
    assert_eq!(
        active
            .open_channel(ChannelOpenRequest {
                protocol_id: offer("lilia.code", versions(1, 0, 2)).stable_id,
                protocol_channel_id: protocol_channel_id("file"),
                channel_id: ChannelId(2),
                capacity: 9,
            })
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::ChannelCapacityExceeded
    );
}

#[test]
fn registry_rejects_identity_schema_and_channel_collisions() {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    let echo_descriptor = descriptor(
        "example.echo",
        versions(1, 0, 0),
        vec![channel(
            "request",
            ChannelMode::RequestResponse,
            0,
            1024,
            None,
            false,
        )],
    );
    registry.register(echo_descriptor.clone()).unwrap();
    let mut identity_collision = echo_descriptor.clone();
    identity_collision.debug_identity = Some(ProtocolDebugIdentity::new("attacker", "echo"));
    assert_eq!(
        registry.register(identity_collision).unwrap_err().kind,
        ProtocolRegistryErrorKind::IdentityConflict
    );
    let mut schema_collision = echo_descriptor.clone();
    schema_collision.schema = SchemaRef::for_contract("example", "echo", 1, b"different-contract");
    assert_eq!(
        registry.register(schema_collision).unwrap_err().kind,
        ProtocolRegistryErrorKind::SchemaConflict
    );
    assert_eq!(
        registry.register(echo_descriptor.clone()).unwrap_err().kind,
        ProtocolRegistryErrorKind::DuplicateProtocol
    );
    let duplicate_channel = descriptor(
        "example.duplicate",
        versions(1, 0, 0),
        vec![
            channel(
                "request",
                ChannelMode::RequestResponse,
                0,
                1024,
                None,
                false,
            ),
            ProtocolChannel {
                id: ProtocolChannelId(1),
                debug_name: Some("other".to_owned()),
                mode: ChannelMode::Event,
                priority: 0,
                max_frame_bytes: 1024,
                max_stream_bytes: None,
                max_in_flight_frames: 1,
                discardable: true,
            },
        ],
    );
    assert_eq!(
        ProtocolRegistry::new(ProtocolRegistryLimits::default())
            .unwrap()
            .register(duplicate_channel)
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::DuplicateChannel
    );
}

#[test]
fn registry_rejects_invalid_and_unbounded_descriptors_before_freeze() {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    registry
        .register(descriptor(
            "example.echo",
            versions(1, 0, 0),
            vec![channel(
                "request",
                ChannelMode::RequestResponse,
                0,
                1024,
                None,
                false,
            )],
        ))
        .unwrap();
    assert_eq!(
        ProtocolId::new("not_namespaced").unwrap_err().kind,
        ProtocolRegistryErrorKind::InvalidProtocolId
    );
    let frozen = registry.freeze();
    assert_eq!(frozen.offers().len(), 1);

    let mut bounded = ProtocolRegistry::new(ProtocolRegistryLimits {
        max_protocols: 1,
        ..ProtocolRegistryLimits::default()
    })
    .unwrap();
    assert_eq!(
        bounded
            .register(descriptor(
                "example.invalidstream",
                versions(1, 0, 0),
                vec![channel("stream", ChannelMode::Stream, 0, 1024, None, false)],
            ))
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::InvalidChannel
    );
    bounded
        .register(descriptor(
            "example.bounded",
            versions(1, 0, 0),
            vec![channel(
                "request",
                ChannelMode::RequestResponse,
                0,
                1024,
                None,
                false,
            )],
        ))
        .unwrap();
    let bounded = bounded.freeze();
    assert_eq!(
        bounded
            .negotiate(&[
                offer("example.bounded", versions(1, 0, 0)),
                offer("example.extra", versions(1, 0, 0)),
            ])
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::RegistryLimitExceeded
    );
}
