use mutsuki_link::{
    ChannelId, ChannelMode, ChannelOpenRequest, Connection, EndpointId, Envelope, EnvelopeFlags,
    MemoryTransportConfig, Multiplexer, MultiplexerLimits, OutboundFrame, ProtocolChannel,
    ProtocolChannelId, ProtocolDescriptor, ProtocolOffer, ProtocolRegistry, ProtocolRegistryLimits,
    ProtocolVersion, SessionId, VersionRange, memory_transport_pair,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let version = ProtocolVersion::new(1, 0);
    let offer =
        ProtocolOffer::from_debug_namespace("example.echo", VersionRange::new(version, version));
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default())?;
    registry.register(ProtocolDescriptor {
        stable_id: offer.stable_id,
        debug_identity: offer.debug_identity.clone(),
        versions: VersionRange::new(version, version),
        schema: offer.schema,
        capabilities: offer.capabilities.clone(),
        channels: vec![ProtocolChannel {
            id: ProtocolChannelId(1),
            debug_name: Some("request".to_owned()),
            mode: ChannelMode::RequestResponse,
            priority: 0,
            max_frame_bytes: 4 * 1024,
            max_stream_bytes: None,
            max_in_flight_frames: 4,
            discardable: false,
        }],
    })?;
    let registry = registry.freeze();
    let negotiated = registry.negotiate(std::slice::from_ref(&offer))?;
    let active = registry.activate(&negotiated)?;
    let channel = active.open_channel(ChannelOpenRequest {
        protocol_id: offer.stable_id,
        protocol_channel_id: ProtocolChannelId(1),
        channel_id: ChannelId(1),
        capacity: 4,
    })?;

    // The payload remains opaque to Link. A real example adapter would encode
    // and decode it using the `example.echo` protocol crate.
    channel.validate_payload(b"hello".len(), None)?;
    let session_id = SessionId::from_bytes([1; 16]);
    let mut mux = Multiplexer::restricted(
        session_id,
        MultiplexerLimits::default(),
        negotiated
            .iter()
            .map(|selection| (selection.stable_id, selection.version)),
    )?;
    mux.open_channel(channel.config().clone())?;
    mux.enqueue(Envelope {
        session_id,
        channel_id: channel.config().id,
        generation: channel.config().generation,
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
        channel.config().key,
        echoed.len()
    );
    Ok(())
}
