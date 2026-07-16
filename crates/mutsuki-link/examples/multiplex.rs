use mutsuki_link::{
    ChannelConfig, ChannelGeneration, ChannelId, ChannelKey, ChannelMode, Envelope, EnvelopeFlags,
    Multiplexer, MultiplexerLimits, OutboundFrame, ProtocolChannelId, ProtocolStableId,
    ProtocolVersion, SessionId,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let version = ProtocolVersion::new(1, 0);
    let protocol_id = ProtocolStableId::derive("example", "multi");
    let session_id = SessionId::from_bytes([1; 16]);
    let mut mux = Multiplexer::restricted(
        session_id,
        MultiplexerLimits::default(),
        [(protocol_id, version)],
    )?;
    for (id, mode, priority) in [
        (1, ChannelMode::RequestResponse, 0),
        (2, ChannelMode::Event, 50),
        (3, ChannelMode::Stream, 100),
    ] {
        mux.open_channel(ChannelConfig {
            key: ChannelKey {
                protocol_id,
                version,
                protocol_channel_id: ProtocolChannelId(u16::try_from(id)?),
            },
            id: ChannelId(id),
            generation: ChannelGeneration::INITIAL,
            mode,
            priority_hint: priority,
            capacity: 4,
            max_frame_bytes: 1024,
            max_stream_bytes: (mode == ChannelMode::Stream).then_some(16 * 1024),
            discardable: mode == ChannelMode::Event,
        })?;
    }
    for (id, payload) in [(1, b"request".as_slice()), (2, b"event"), (3, b"stream")] {
        mux.enqueue(Envelope {
            session_id,
            channel_id: ChannelId(id),
            generation: ChannelGeneration::INITIAL,
            sequence: 1,
            nesting_depth: 0,
            flags: EnvelopeFlags {
                end_of_stream: id == 3,
                cancelled: false,
            },
            payload: payload.to_vec(),
        })?;
    }
    mux.enqueue_control(b"heartbeat".to_vec())?;

    let mut order = Vec::new();
    while let Some(frame) = mux.next_outbound() {
        match frame {
            OutboundFrame::Control(_) => order.push("control".to_owned()),
            OutboundFrame::Data(envelope) => {
                order.push(format!("channel-{}", envelope.channel_id.0));
            }
        }
    }
    assert_eq!(order.first().map(String::as_str), Some("control"));
    println!("bounded multiplex order: {}", order.join(", "));
    Ok(())
}
