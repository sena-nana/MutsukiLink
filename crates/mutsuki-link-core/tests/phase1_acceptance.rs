use mutsuki_link_core::*;
use std::collections::{BTreeMap, BTreeSet};

fn identity(value: u8) -> Identity {
    Identity {
        peer_id: PeerId::from_bytes([value; 32]),
        endpoint_id: EndpointId::from_bytes([value; 16]),
        connection_id: ConnectionId::from_bytes([value; 16]),
    }
}

fn offer(namespace: &str) -> ProtocolOffer {
    ProtocolOffer {
        namespace: namespace.to_owned(),
        versions: VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 3)),
    }
}

fn config(value: u8, session: u8, offers: Vec<ProtocolOffer>) -> HandshakeConfig {
    HandshakeConfig {
        identity: identity(value),
        policy: HandshakePolicy {
            link_versions: VersionRange::new(
                ProtocolVersion::new(1, 0),
                ProtocolVersion::new(1, 2),
            ),
            pairing_protocols: offers.clone(),
            protocols: offers,
            allow_pairing: true,
            trusted_peers: BTreeSet::new(),
            max_protocol_offers: 8,
            max_identity_proof_bytes: 128,
        },
        challenge_nonce: [value; 32],
        identity_proof: IdentityProof {
            opaque: vec![value; 32],
        },
        session_id: SessionId::from_bytes([session; 16]),
    }
}

/// A deliberately external test codec: the wire carries only bounded opaque
/// frame handles, proving link-core does not require a concrete serializer.
struct HarnessCodec {
    next: u64,
    frames: BTreeMap<u64, HandshakeFrame>,
}

impl HarnessCodec {
    fn new() -> Self {
        Self {
            next: 1,
            frames: BTreeMap::new(),
        }
    }

    fn transmit(
        &mut self,
        sender: &mut MemoryConnection,
        receiver: &mut MemoryConnection,
        frame: HandshakeFrame,
    ) -> HandshakeFrame {
        let id = self.next;
        self.next += 1;
        self.frames.insert(id, frame);
        sender.try_send(&id.to_be_bytes()).unwrap();
        let wire = receiver.try_receive().unwrap().unwrap();
        let bytes: [u8; 8] = wire.try_into().unwrap();
        self.frames.remove(&u64::from_be_bytes(bytes)).unwrap()
    }
}

fn sent(outputs: Vec<HandshakeOutput>) -> HandshakeFrame {
    outputs
        .into_iter()
        .find_map(|output| match output {
            HandshakeOutput::Send(frame) => Some(frame),
            _ => None,
        })
        .unwrap()
}

fn established(outputs: &[HandshakeOutput]) -> NegotiatedSession {
    outputs
        .iter()
        .find_map(|output| match output {
            HandshakeOutput::Established(session) => Some(session.clone()),
            _ => None,
        })
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn in_memory_transport_covers_handshake_mux_flow_control_drain_and_abort() {
    let offers = vec![offer("mutsuki.lilia"), offer("mutsuki.distributed")];
    let mut initiator = HandshakeMachine::initiator(config(1, 0, offers.clone()));
    let mut responder = HandshakeMachine::responder(config(2, 9, offers));
    let (mut client_wire, mut server_wire) = memory_transport_pair(
        EndpointId::from_bytes([1; 16]),
        EndpointId::from_bytes([2; 16]),
        MemoryTransportConfig {
            queue_capacity: 1,
            max_message_bytes: 8,
            datagram_capacity: 0,
        },
    );
    let mut codec = HarnessCodec::new();

    let hello = initiator.start(AuthPath::FirstPairing).unwrap();
    let hello = codec.transmit(&mut client_wire, &mut server_wire, hello);
    let challenge = sent(responder.receive(hello).unwrap());
    let challenge = codec.transmit(&mut server_wire, &mut client_wire, challenge);
    let proof = sent(initiator.receive(challenge).unwrap());
    let proof = codec.transmit(&mut client_wire, &mut server_wire, proof);
    assert!(matches!(
        &responder.receive(proof).unwrap()[0],
        HandshakeOutput::VerifyIdentity(_)
    ));
    let selection = sent(responder.decide_identity(ProofDecision::Accept).unwrap());
    let selection = codec.transmit(&mut server_wire, &mut client_wire, selection);
    let confirm = sent(initiator.receive(selection).unwrap());
    let confirm = codec.transmit(&mut client_wire, &mut server_wire, confirm);
    let responder_outputs = responder.receive(confirm).unwrap();
    let confirmed = sent(responder_outputs.clone());
    let confirmed = codec.transmit(&mut server_wire, &mut client_wire, confirmed);
    let initiator_outputs = initiator.receive(confirmed).unwrap();
    let negotiated = established(&initiator_outputs);
    assert_eq!(negotiated.protocols.len(), 2);
    assert_eq!(
        established(&responder_outputs).session_id,
        negotiated.session_id
    );

    let limits = MultiplexerLimits {
        max_frame_bytes: 16,
        max_nesting_depth: 2,
        max_channels: 4,
        control_queue_capacity: 2,
        max_total_pending_frames: 2,
    };
    let mut session = Session::established(negotiated.clone(), limits, 2).unwrap();
    let lilia = ChannelConfig {
        key: ChannelKey {
            namespace: "mutsuki.lilia".to_owned(),
            version: ProtocolVersion::new(1, 3),
            id: ChannelId(1),
        },
        mode: ChannelMode::Event,
        priority_hint: 1,
        capacity: 1,
    };
    let distributed = ChannelConfig {
        key: ChannelKey {
            namespace: "mutsuki.distributed".to_owned(),
            version: ProtocolVersion::new(1, 3),
            id: ChannelId(2),
        },
        mode: ChannelMode::RequestResponse,
        priority_hint: 10,
        capacity: 1,
    };
    session.multiplexer().open_channel(lilia.clone()).unwrap();
    session
        .multiplexer()
        .open_channel(distributed.clone())
        .unwrap();
    let session_id = negotiated.session_id;
    let envelope = |channel: &ChannelConfig, value: u8| Envelope {
        session_id,
        channel: channel.key.clone(),
        sequence: u64::from(value),
        nesting_depth: 1,
        flags: EnvelopeFlags::default(),
        payload: vec![value],
    };
    session.multiplexer().enqueue(envelope(&lilia, 1)).unwrap();
    assert!(matches!(
        session.multiplexer().enqueue(envelope(&lilia, 2)),
        Err(LinkError::Backpressure { channel: 1, .. })
    ));
    session
        .multiplexer()
        .enqueue(envelope(&distributed, 3))
        .unwrap();
    // Data reached its global bound, but reserved control capacity remains usable.
    session
        .multiplexer()
        .enqueue_control(b"drain".to_vec())
        .unwrap();
    assert!(matches!(
        session.multiplexer().next_outbound(),
        Some(OutboundFrame::Control(_))
    ));

    session.begin_drain().unwrap();
    while session.multiplexer().next_outbound().is_some() {}
    session.finish_drain().unwrap();
    assert_eq!(session.info().close_reason, Some(CloseReason::Graceful));

    let mut aborted = Session::established(negotiated, limits, 1).unwrap();
    aborted.multiplexer().open_channel(lilia.clone()).unwrap();
    aborted.multiplexer().enqueue(envelope(&lilia, 9)).unwrap();
    aborted.abort();
    assert_eq!(aborted.multiplexer().pending_frames(), 0);
    assert_eq!(aborted.info().close_reason, Some(CloseReason::LocalAbort));
}
