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
        name: name.to_owned(),
        mode,
        priority,
        max_frame_bytes,
        max_stream_bytes,
        max_in_flight_frames: 8,
        discardable,
    }
}

fn product_registry() -> FrozenProtocolRegistry {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    registry
        .register(ProtocolDescriptor {
            id: ProtocolId::new("lilia.code").unwrap(),
            versions: versions(1, 0, 2),
            channels: vec![
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
        })
        .unwrap();
    registry
        .register(ProtocolDescriptor {
            id: ProtocolId::new("mutsuki.distributed.cluster").unwrap(),
            versions: versions(2, 0, 1),
            channels: vec![
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
        })
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
            ProtocolOffer {
                namespace: "lilia.code".to_owned(),
                versions: versions(1, 1, 1),
            },
            ProtocolOffer {
                namespace: "mutsuki.distributed.cluster".to_owned(),
                versions: versions(2, 0, 0),
            },
        ])
        .unwrap();
    assert_eq!(selections.len(), 2);
    let active = registry.activate(&selections).unwrap();
    assert_eq!(active.len(), 2);

    let lilia = active
        .open_channel(ChannelOpenRequest {
            protocol: ProtocolId::new("lilia.code").unwrap(),
            channel_name: "file".to_owned(),
            channel_id: ChannelId(1),
            capacity: 4,
        })
        .unwrap();
    let distributed = active
        .open_channel(ChannelOpenRequest {
            protocol: ProtocolId::new("mutsuki.distributed.cluster").unwrap(),
            channel_name: "control".to_owned(),
            channel_id: ChannelId(2),
            capacity: 2,
        })
        .unwrap();
    assert_ne!(lilia.config.key.namespace, distributed.config.key.namespace);
    assert_eq!(lilia.config.mode, ChannelMode::Stream);
    assert_eq!(distributed.config.mode, ChannelMode::RequestResponse);

    let mut mux = Multiplexer::restricted(
        MultiplexerLimits::default(),
        selections
            .iter()
            .map(|selection| (selection.namespace.clone(), selection.version)),
    )
    .unwrap();
    mux.open_channel(lilia.config).unwrap();
    mux.open_channel(distributed.config).unwrap();
}

#[test]
fn one_incompatible_protocol_is_disabled_without_breaking_the_other() {
    let registry = product_registry();
    let selections = registry
        .negotiate(&[
            ProtocolOffer {
                namespace: "lilia.code".to_owned(),
                versions: versions(9, 0, 0),
            },
            ProtocolOffer {
                namespace: "mutsuki.distributed.cluster".to_owned(),
                versions: versions(2, 1, 3),
            },
        ])
        .unwrap();
    assert_eq!(selections.len(), 1);
    assert_eq!(selections[0].namespace, "mutsuki.distributed.cluster");
    let active = registry.activate(&selections).unwrap();
    assert!(!active.contains(&ProtocolId::new("lilia.code").unwrap()));
    assert!(active.contains(&ProtocolId::new("mutsuki.distributed.cluster").unwrap()));
    assert_eq!(
        active
            .open_channel(ChannelOpenRequest {
                protocol: ProtocolId::new("lilia.code").unwrap(),
                channel_name: "command".to_owned(),
                channel_id: ChannelId(1),
                capacity: 1,
            })
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::ProtocolNotNegotiated
    );
}

#[test]
fn channel_shape_frame_stream_and_queue_limits_are_enforced() {
    let registry = product_registry();
    let selections = registry
        .negotiate(&[ProtocolOffer {
            namespace: "lilia.code".to_owned(),
            versions: versions(1, 0, 2),
        }])
        .unwrap();
    let active = registry.activate(&selections).unwrap();
    let file = active
        .open_channel(ChannelOpenRequest {
            protocol: ProtocolId::new("lilia.code").unwrap(),
            channel_name: "file".to_owned(),
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
                protocol: ProtocolId::new("lilia.code").unwrap(),
                channel_name: "file".to_owned(),
                channel_id: ChannelId(2),
                capacity: 9,
            })
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::ChannelCapacityExceeded
    );
}

#[test]
fn registry_rejects_collisions_and_freezes_before_session_use() {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    let descriptor = ProtocolDescriptor {
        id: ProtocolId::new("example.echo").unwrap(),
        versions: versions(1, 0, 0),
        channels: vec![channel(
            "request",
            ChannelMode::RequestResponse,
            0,
            1024,
            None,
            false,
        )],
    };
    registry.register(descriptor.clone()).unwrap();
    assert_eq!(
        registry.register(descriptor).unwrap_err().kind,
        ProtocolRegistryErrorKind::DuplicateProtocol
    );
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
            .register(ProtocolDescriptor {
                id: ProtocolId::new("example.invalidstream").unwrap(),
                versions: versions(1, 0, 0),
                channels: vec![channel("stream", ChannelMode::Stream, 0, 1024, None, false,)],
            })
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::InvalidChannel
    );
    bounded
        .register(ProtocolDescriptor {
            id: ProtocolId::new("example.bounded").unwrap(),
            versions: versions(1, 0, 0),
            channels: vec![channel(
                "request",
                ChannelMode::RequestResponse,
                0,
                1024,
                None,
                false,
            )],
        })
        .unwrap();
    let bounded = bounded.freeze();
    assert_eq!(
        bounded
            .negotiate(&[
                ProtocolOffer {
                    namespace: "example.bounded".to_owned(),
                    versions: versions(1, 0, 0),
                },
                ProtocolOffer {
                    namespace: "example.extra".to_owned(),
                    versions: versions(1, 0, 0),
                },
            ])
            .unwrap_err()
            .kind,
        ProtocolRegistryErrorKind::RegistryLimitExceeded
    );
}
