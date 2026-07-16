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
    ProtocolOffer::from_debug_namespace(
        namespace,
        VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 3)),
    )
}

fn config(value: u8, session: u8, offers: Vec<ProtocolOffer>) -> HandshakeConfig {
    HandshakeConfig {
        identity: identity(value),
        policy: HandshakePolicy {
            link_versions: VersionRange::new(
                ProtocolVersion::new(1, 0),
                ProtocolVersion::new(1, 2),
            ),
            link_capabilities: LinkCapabilities::COMPACT_CHANNEL_ID
                | LinkCapabilities::TYPED_CONTROL,
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

fn protocol_registry(offers: &[ProtocolOffer]) -> FrozenProtocolRegistry {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    for offer in offers {
        let is_event = offer
            .debug_identity
            .as_ref()
            .is_some_and(|identity| identity.name == "lilia");
        registry
            .register(ProtocolDescriptor {
                stable_id: offer.stable_id,
                debug_identity: offer.debug_identity.clone(),
                versions: offer.versions,
                schema: offer.schema,
                capabilities: offer.capabilities.clone(),
                channels: vec![ProtocolChannelDescriptor {
                    id: ProtocolChannelId(1),
                    debug_name: None,
                    mode: if is_event {
                        ChannelMode::Event
                    } else {
                        ChannelMode::RequestResponse
                    },
                    priority: if is_event { 1 } else { 10 },
                    max_frame_bytes: 16,
                    max_stream_bytes: None,
                    max_in_flight_frames: 1,
                    discardable: is_event,
                }],
            })
            .unwrap();
    }
    registry.freeze()
}

#[test]
#[allow(clippy::too_many_lines)]
fn in_memory_transport_covers_handshake_mux_flow_control_drain_and_abort() {
    let offers = vec![offer("mutsuki.lilia"), offer("mutsuki.distributed")];
    let registry = protocol_registry(&offers);
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
    let active = registry.activate(&negotiated.protocols).unwrap();
    let lilia_validated = active
        .open_channel(ChannelOpenRequest {
            protocol_id: ProtocolStableId::derive("mutsuki", "lilia"),
            protocol_channel_id: ProtocolChannelId(1),
            channel_id: ChannelId(1),
            capacity: 1,
        })
        .unwrap();
    let distributed_validated = active
        .open_channel(ChannelOpenRequest {
            protocol_id: ProtocolStableId::derive("mutsuki", "distributed"),
            protocol_channel_id: ProtocolChannelId(1),
            channel_id: ChannelId(2),
            capacity: 1,
        })
        .unwrap();
    let lilia = lilia_validated.config().clone();
    let distributed = distributed_validated.config().clone();
    session.open_validated_channel(&lilia_validated).unwrap();
    session
        .open_validated_channel(&distributed_validated)
        .unwrap();
    let session_id = negotiated.session_id;
    let envelope = |channel: &ChannelConfig, value: u8| Envelope {
        session_id,
        channel_id: channel.id,
        generation: channel.generation,
        sequence: u64::from(value),
        nesting_depth: 1,
        flags: EnvelopeFlags::default(),
        payload: vec![value],
    };
    session.data_plane().enqueue(envelope(&lilia, 1)).unwrap();
    assert!(matches!(
        session.data_plane().enqueue(envelope(&lilia, 2)),
        Err(LinkError::Backpressure { channel: 1, .. })
    ));
    session
        .data_plane()
        .enqueue(envelope(&distributed, 3))
        .unwrap();
    // Data reached its global bound, but reserved control capacity remains usable.
    session
        .data_plane()
        .enqueue_control(b"drain".to_vec())
        .unwrap();
    assert!(matches!(
        session.data_plane().next_outbound(),
        Some(OutboundFrame::Control(_))
    ));

    session.begin_drain().unwrap();
    while session.data_plane().next_outbound().is_some() {}
    session.finish_drain().unwrap();
    assert_eq!(session.info().close_reason, Some(CloseReason::Graceful));

    let mut aborted = Session::established(negotiated, limits, 1).unwrap();
    aborted.open_validated_channel(&lilia_validated).unwrap();
    aborted.data_plane().enqueue(envelope(&lilia, 9)).unwrap();
    aborted.abort();
    assert_eq!(aborted.data_plane().pending_frames(), 0);
    assert_eq!(aborted.info().close_reason, Some(CloseReason::LocalAbort));
}
