//! Shared behavioral suite used by every concrete transport.

#![forbid(unsafe_code)]
// The acceptance suite intentionally exercises the facade-like full core surface.
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::wildcard_imports
)]

use mutsuki_link_core::*;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub async fn run_session_transport_suite(
    client: &mut impl Connection,
    server: &mut impl Connection,
) {
    let offers = vec![offer("mutsuki.lilia"), offer("mutsuki.distributed")];
    let registry = protocol_registry(&offers);
    let mut initiator = HandshakeMachine::initiator(config(1, 0, offers.clone()));
    let mut responder = HandshakeMachine::responder(config(2, 9, offers));
    let mut codec = HarnessCodec::new();

    let hello = initiator.start(AuthPath::FirstPairing).unwrap();
    let hello = codec.transmit(client, server, hello).await;
    let challenge = sent(responder.receive(hello).unwrap());
    let challenge = codec.transmit(server, client, challenge).await;
    let proof = sent(initiator.receive(challenge).unwrap());
    let proof = codec.transmit(client, server, proof).await;
    assert!(matches!(
        &responder.receive(proof).unwrap()[0],
        HandshakeOutput::VerifyIdentity(_)
    ));
    let selection = sent(responder.decide_identity(ProofDecision::Accept).unwrap());
    let selection = codec.transmit(server, client, selection).await;
    let confirmation = sent(initiator.receive(selection).unwrap());
    let confirmation = codec.transmit(client, server, confirmation).await;
    let responder_outputs = responder.receive(confirmation).unwrap();
    let confirmed = sent(responder_outputs.clone());
    let confirmed = codec.transmit(server, client, confirmed).await;
    let initiator_outputs = initiator.receive(confirmed).unwrap();
    let negotiated = established(&initiator_outputs);
    assert_eq!(
        established(&responder_outputs).session_id,
        negotiated.session_id
    );

    let limits = MultiplexerLimits {
        max_frame_bytes: 64,
        max_nesting_depth: 4,
        max_channels: 4,
        control_queue_capacity: 2,
        max_total_pending_frames: 2,
    };
    let mut session = Session::established(negotiated.clone(), limits, 2).unwrap();
    let active = registry.activate(&negotiated.protocols).unwrap();
    let data_validated = active
        .open_channel(ChannelOpenRequest {
            protocol_id: ProtocolStableId::derive("mutsuki", "lilia"),
            protocol_channel_id: ProtocolChannelId(1),
            channel_id: ChannelId(1),
            capacity: 1,
        })
        .unwrap();
    let control_validated = active
        .open_channel(ChannelOpenRequest {
            protocol_id: ProtocolStableId::derive("mutsuki", "distributed"),
            protocol_channel_id: ProtocolChannelId(1),
            channel_id: ChannelId(2),
            capacity: 1,
        })
        .unwrap();
    let data_channel = data_validated.config().clone();
    let control_channel = control_validated.config().clone();
    session.open_validated_channel(&data_validated).unwrap();
    session.open_validated_channel(&control_validated).unwrap();
    session
        .data_plane()
        .enqueue(envelope(&negotiated, &data_channel, b"bulk"))
        .unwrap();
    session
        .data_plane()
        .enqueue(envelope(&negotiated, &control_channel, b"status"))
        .unwrap();
    session
        .data_plane()
        .enqueue_control(b"ping".to_vec())
        .unwrap();
    assert!(matches!(
        session.data_plane().next_outbound(),
        Some(OutboundFrame::Control(value)) if value == b"ping"
    ));
    client.try_send_control(b"ping").unwrap();
    assert_eq!(receive(server).await, b"ping");

    while let Some(frame) = session.data_plane().next_outbound() {
        let payload = match frame {
            OutboundFrame::Control(payload) => payload,
            OutboundFrame::Data(envelope) => envelope.payload,
        };
        client.try_send(&payload).unwrap();
        assert_eq!(receive(server).await, payload);
    }
    session.begin_drain().unwrap();
    session.finish_drain().unwrap();
    assert_eq!(session.info().close_reason, Some(CloseReason::Graceful));

    let mut aborted = Session::established(negotiated, limits, 1).unwrap();
    aborted.open_validated_channel(&data_validated).unwrap();
    let aborted_session_id = aborted.info().session_id;
    aborted
        .data_plane()
        .enqueue(Envelope {
            session_id: aborted_session_id,
            channel_id: data_channel.id,
            generation: data_channel.generation,
            sequence: 2,
            nesting_depth: 0,
            flags: EnvelopeFlags::default(),
            payload: b"discard".to_vec(),
        })
        .unwrap();
    aborted.abort();
    assert_eq!(aborted.data_plane().pending_frames(), 0);
    assert_eq!(aborted.info().close_reason, Some(CloseReason::LocalAbort));
}

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

fn config(value: u8, session: u8, protocols: Vec<ProtocolOffer>) -> HandshakeConfig {
    HandshakeConfig {
        identity: identity(value),
        policy: HandshakePolicy {
            link_versions: VersionRange::new(
                ProtocolVersion::new(1, 0),
                ProtocolVersion::new(1, 2),
            ),
            link_capabilities: LinkCapabilities::COMPACT_CHANNEL_ID
                | LinkCapabilities::DATAGRAMS
                | LinkCapabilities::TYPED_CONTROL,
            pairing_protocols: protocols.clone(),
            protocols,
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

fn envelope(session: &NegotiatedSession, channel: &ChannelConfig, payload: &[u8]) -> Envelope {
    Envelope {
        session_id: session.session_id,
        channel_id: channel.id,
        generation: channel.generation,
        sequence: 1,
        nesting_depth: 0,
        flags: EnvelopeFlags::default(),
        payload: payload.to_vec(),
    }
}

fn protocol_registry(offers: &[ProtocolOffer]) -> FrozenProtocolRegistry {
    let mut registry = ProtocolRegistry::new(ProtocolRegistryLimits::default()).unwrap();
    for offer in offers {
        let is_stream = offer
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
                    mode: if is_stream {
                        ChannelMode::Stream
                    } else {
                        ChannelMode::RequestResponse
                    },
                    priority: if is_stream { 1 } else { 10 },
                    max_frame_bytes: 64,
                    max_stream_bytes: is_stream.then_some(1024),
                    max_in_flight_frames: 1,
                    discardable: false,
                }],
            })
            .unwrap();
    }
    registry.freeze()
}

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

    async fn transmit(
        &mut self,
        sender: &mut impl Connection,
        receiver: &mut impl Connection,
        frame: HandshakeFrame,
    ) -> HandshakeFrame {
        let id = self.next;
        self.next += 1;
        self.frames.insert(id, frame);
        sender.try_send(&id.to_be_bytes()).unwrap();
        let wire = receive(receiver).await;
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

async fn receive(connection: &mut impl Connection) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match connection.try_receive() {
            Ok(Some(message)) => return message,
            Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                assert!(tokio::time::Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            result => panic!("unexpected transport receive result: {result:?}"),
        }
    }
}
