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
    let data_channel = ChannelConfig {
        key: ChannelKey {
            namespace: "mutsuki.lilia".to_owned(),
            version: ProtocolVersion::new(1, 3),
            id: ChannelId(1),
        },
        mode: ChannelMode::Stream,
        priority_hint: 1,
        capacity: 1,
    };
    let control_channel = ChannelConfig {
        key: ChannelKey {
            namespace: "mutsuki.distributed".to_owned(),
            version: ProtocolVersion::new(1, 3),
            id: ChannelId(2),
        },
        mode: ChannelMode::RequestResponse,
        priority_hint: 10,
        capacity: 1,
    };
    session
        .multiplexer()
        .open_channel(data_channel.clone())
        .unwrap();
    session
        .multiplexer()
        .open_channel(control_channel.clone())
        .unwrap();
    session
        .multiplexer()
        .enqueue(envelope(&negotiated, &data_channel, b"bulk"))
        .unwrap();
    session
        .multiplexer()
        .enqueue(envelope(&negotiated, &control_channel, b"status"))
        .unwrap();
    session
        .multiplexer()
        .enqueue_control(b"ping".to_vec())
        .unwrap();
    assert!(matches!(
        session.multiplexer().next_outbound(),
        Some(OutboundFrame::Control(value)) if value == b"ping"
    ));
    client.try_send_control(b"ping").unwrap();
    assert_eq!(receive(server).await, b"ping");

    while let Some(frame) = session.multiplexer().next_outbound() {
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
    aborted
        .multiplexer()
        .open_channel(data_channel.clone())
        .unwrap();
    let aborted_session_id = aborted.info().session_id;
    aborted
        .multiplexer()
        .enqueue(Envelope {
            session_id: aborted_session_id,
            channel: data_channel.key,
            sequence: 2,
            nesting_depth: 0,
            flags: EnvelopeFlags::default(),
            payload: b"discard".to_vec(),
        })
        .unwrap();
    aborted.abort();
    assert_eq!(aborted.multiplexer().pending_frames(), 0);
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
    ProtocolOffer {
        namespace: namespace.to_owned(),
        versions: VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 3)),
    }
}

fn config(value: u8, session: u8, protocols: Vec<ProtocolOffer>) -> HandshakeConfig {
    HandshakeConfig {
        identity: identity(value),
        policy: HandshakePolicy {
            link_versions: VersionRange::new(
                ProtocolVersion::new(1, 0),
                ProtocolVersion::new(1, 2),
            ),
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
        channel: channel.key.clone(),
        sequence: 1,
        nesting_depth: 0,
        flags: EnvelopeFlags::default(),
        payload: payload.to_vec(),
    }
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
