use mutsuki_link::{
    ChannelConfig, ChannelId, ChannelKey, ChannelMode, Envelope, EnvelopeFlags, Multiplexer,
    MultiplexerLimits, OutboundFrame, ProtocolVersion, SessionId,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let version = ProtocolVersion::new(1, 0);
    let namespace = "example.multi";
    let mut mux = Multiplexer::restricted(
        MultiplexerLimits::default(),
        [(namespace.to_owned(), version)],
    )?;
    for (id, mode, priority) in [
        (1, ChannelMode::RequestResponse, 0),
        (2, ChannelMode::Event, 50),
        (3, ChannelMode::Stream, 100),
    ] {
        mux.open_channel(ChannelConfig {
            key: ChannelKey {
                namespace: namespace.to_owned(),
                version,
                id: ChannelId(id),
            },
            mode,
            priority_hint: priority,
            capacity: 4,
        })?;
    }
    let session_id = SessionId::from_bytes([1; 16]);
    for (id, payload) in [(1, b"request".as_slice()), (2, b"event"), (3, b"stream")] {
        mux.enqueue(Envelope {
            session_id,
            channel: ChannelKey {
                namespace: namespace.to_owned(),
                version,
                id: ChannelId(id),
            },
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
                order.push(format!("channel-{}", envelope.channel.id.0));
            }
        }
    }
    assert_eq!(order.first().map(String::as_str), Some("control"));
    println!("bounded multiplex order: {}", order.join(", "));
    Ok(())
}
