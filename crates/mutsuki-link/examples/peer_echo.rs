use mutsuki_link::{
    ChannelId, ChannelMode, ChannelOpenRequest, Connection, EndpointId, Envelope, EnvelopeFlags,
    MemoryTransportConfig, Multiplexer, MultiplexerLimits, OutboundFrame, ProtocolChannel,
    ProtocolDescriptor, ProtocolId, ProtocolOffer, ProtocolRegistry, ProtocolRegistryLimits,
    ProtocolVersion, SessionId, VersionRange, memory_transport_pair,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let version = ProtocolVersion::new(1, 0);
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default())?;
    registry.register(ProtocolDescriptor {
        id: ProtocolId::new("example.echo")?,
        versions: VersionRange::new(version, version),
        channels: vec![ProtocolChannel {
            name: "request".to_owned(),
            mode: ChannelMode::RequestResponse,
            priority: 0,
            max_frame_bytes: 4 * 1024,
            max_stream_bytes: None,
            max_in_flight_frames: 4,
            discardable: false,
        }],
    })?;
    let registry = registry.freeze();
    let negotiated = registry.negotiate(&[ProtocolOffer {
        namespace: "example.echo".to_owned(),
        versions: VersionRange::new(version, version),
    }])?;
    let active = registry.activate(&negotiated)?;
    let channel = active.open_channel(ChannelOpenRequest {
        protocol: ProtocolId::new("example.echo")?,
        channel_name: "request".to_owned(),
        channel_id: ChannelId(1),
        capacity: 4,
    })?;

    // The payload remains opaque to Link. A real example adapter would encode
    // and decode it using the `example.echo` protocol crate.
    channel.validate_payload(b"hello".len(), None)?;
    let mut mux = Multiplexer::restricted(
        MultiplexerLimits::default(),
        negotiated
            .iter()
            .map(|selection| (selection.namespace.clone(), selection.version)),
    )?;
    mux.open_channel(channel.config.clone())?;
    mux.enqueue(Envelope {
        session_id: SessionId::from_bytes([1; 16]),
        channel: channel.config.key.clone(),
        sequence: 1,
        nesting_depth: 0,
        flags: EnvelopeFlags::default(),
        payload: b"hello".to_vec(),
    })?;
    let OutboundFrame::Data(request) = mux.next_outbound().expect("queued echo request") else {
        unreachable!("echo request uses the data channel");
    };

    let (mut client, mut server) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        MemoryTransportConfig::default(),
    );
    client.try_send(&request.payload)?;
    let received = server.try_receive()?.expect("server receives request");
    server.try_send(&received)?;
    let echoed = client.try_receive()?.expect("client receives response");
    println!(
        "open {:?} and echo {} opaque bytes",
        channel.config.key,
        echoed.len()
    );
    Ok(())
}
