#![allow(
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use mutsuki_link::{
    AuthPath, ConnectContext, Connection, ConnectionActivityProfile, EndpointId, HandshakeConfig,
    HandshakeFrame, HandshakeMachine, HandshakeOutput, HandshakePolicy, HeartbeatAction,
    HeartbeatController, HeartbeatPolicy, Identity, IdentityProof, PeerId, ProofDecision,
    ProtocolOffer, ProtocolVersion, SessionId, TransportBudget, TransportErrorKind, VersionRange,
    local::{self, LocalAddress, LocalListener},
    quic::{QuicConnector, QuicListener, QuicOptions},
    tcp::{self, TcpConfig, TcpListener},
};
use quinn::{ClientConfig, ServerConfig};
use rustls::RootCertStore;
use serde::Serialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const CONNECT_BUDGET_MS: u128 = 5_000;
const RTT_P99_BUDGET_US: u128 = 50_000;
const CONTROL_P99_BUDGET_US: u128 = 50_000;
const MIN_THROUGHPUT_BYTES_PER_SECOND: u128 = 4 * 1024 * 1024;
const SHUTDOWN_BUDGET_MS: u128 = 2_000;
const RTT_SAMPLE_COUNT: usize = 128;
const CONTROL_SAMPLE_COUNT: usize = 32;
const WARMUP_SAMPLES: usize = 16;
const THROUGHPUT_CASES: [(usize, usize); 4] = [
    (1024, 1024),
    (16 * 1024, 256),
    (64 * 1024, 64),
    (1024 * 1024, 8),
];

#[derive(Serialize)]
struct ThroughputSample {
    payload_bytes: usize,
    frames: usize,
    bytes_per_second: u128,
}

#[derive(Serialize)]
struct Baseline {
    transport: &'static str,
    connect_us: u128,
    rtt_p50_us: u128,
    rtt_p95_us: u128,
    rtt_p99_us: u128,
    saturated_control_p99_us: u128,
    throughput: Vec<ThroughputSample>,
    fixed_handle_bytes: usize,
    shutdown_us: u128,
}

#[derive(Serialize)]
struct ReleaseReport<'a> {
    schema: &'static str,
    smoke_only: bool,
    claim_boundary: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    handshake_us: u128,
    idle_tick_ns: u128,
    baselines: &'a [Baseline],
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn Error>> {
    let handshake_us = measure_link_handshake()?;
    let (idle_tick_ns, idle_actions) = measure_idle_state_machine()?;
    if idle_actions != 0 || idle_tick_ns > 100_000 {
        return Err("idle state-machine budget exceeded".into());
    }

    let mut baselines = Vec::new();
    baselines.push(measure_local().await?);
    baselines.push(measure_tcp().await?);
    baselines.push(measure_quic().await?);
    for baseline in &baselines {
        enforce(baseline)?;
        println!(
            "{} connect={}us rtt_p50={}us rtt_p95={}us rtt_p99={}us control_p99={}us min_throughput={}B/s handles={}B shutdown={}us",
            baseline.transport,
            baseline.connect_us,
            baseline.rtt_p50_us,
            baseline.rtt_p95_us,
            baseline.rtt_p99_us,
            baseline.saturated_control_p99_us,
            baseline
                .throughput
                .iter()
                .map(|sample| sample.bytes_per_second)
                .min()
                .unwrap_or(0),
            baseline.fixed_handle_bytes,
            baseline.shutdown_us,
        );
    }
    println!(
        "link_handshake={handshake_us}us idle_tick={idle_tick_ns}ns idle_actions={idle_actions} rtt_samples={RTT_SAMPLE_COUNT}"
    );
    let report = ReleaseReport {
        schema: "mutsuki-link-release-baseline/2.0.0",
        smoke_only: true,
        claim_boundary: "Local loopback transport smoke only; not LAN, Wi-Fi, or production latency",
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism()?.get(),
        handshake_us,
        idle_tick_ns,
        baselines: &baselines,
    };
    let json = serde_json::to_string_pretty(&report)?;
    if let Ok(path) = std::env::var("MUTSUKI_LINK_OUTPUT") {
        fs::write(path, json.as_bytes())?;
    }
    println!("{json}");
    Ok(())
}

async fn measure_local() -> Result<Baseline, Box<dyn Error>> {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let address = LocalAddress(format!("mutsuki-link-baseline-{unique}"));
    let budget = baseline_budget();
    let listener = LocalListener::bind(&address, EndpointId::from_bytes([2; 16]), budget)?;
    let context = ConnectContext::default();
    let started = Instant::now();
    let (server, client) = tokio::join!(
        listener.accept(EndpointId::from_bytes([1; 16])),
        local::connect(
            &address,
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            budget,
            &context,
        )
    );
    let connect_us = started.elapsed().as_micros();
    measure_connection("local", connect_us, client?, server?).await
}

async fn measure_tcp() -> Result<Baseline, Box<dyn Error>> {
    let config = TcpConfig {
        budget: baseline_budget(),
        ..TcpConfig::default()
    };
    let listener = TcpListener::bind(
        "127.0.0.1:0".parse()?,
        EndpointId::from_bytes([2; 16]),
        config,
    )
    .await?;
    let address = listener.local_addr()?;
    let context = ConnectContext::default();
    let started = Instant::now();
    let (server, client) = tokio::join!(
        listener.accept(EndpointId::from_bytes([1; 16])),
        tcp::connect(
            address,
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            config,
            &context,
        )
    );
    let connect_us = started.elapsed().as_micros();
    measure_connection("tcp", connect_us, client?, server?).await
}

async fn measure_quic() -> Result<Baseline, Box<dyn Error>> {
    let (server_config, client_config) = crypto_configs()?;
    let options = QuicOptions {
        budget: baseline_budget(),
        ..QuicOptions::default()
    };
    let listener = QuicListener::bind(
        "127.0.0.1:0".parse()?,
        EndpointId::from_bytes([2; 16]),
        server_config,
        options,
    )?;
    let connector = QuicConnector::new("127.0.0.1:0".parse()?, client_config, options)?;
    let address = listener.local_addr()?;
    let context = ConnectContext::default();
    let started = Instant::now();
    let (server, client) = tokio::join!(
        listener.accept(EndpointId::from_bytes([1; 16])),
        connector.connect(
            address,
            "localhost",
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            &context,
        )
    );
    let connect_us = started.elapsed().as_micros();
    measure_connection("quic", connect_us, client?, server?).await
}

async fn measure_connection<Client, Server>(
    transport: &'static str,
    connect_us: u128,
    mut client: Client,
    mut server: Server,
) -> Result<Baseline, Box<dyn Error>>
where
    Client: Connection,
    Server: Connection,
{
    for _ in 0..WARMUP_SAMPLES {
        send_with_retry(&mut client, b"warmup", true).await?;
        let request = receive_with_deadline(&mut server).await?;
        send_with_retry(&mut server, &request, true).await?;
        let _response = receive_with_deadline(&mut client).await?;
    }
    let mut rtts = Vec::with_capacity(RTT_SAMPLE_COUNT);
    for _ in 0..RTT_SAMPLE_COUNT {
        let started = Instant::now();
        send_with_retry(&mut client, b"rtt", true).await?;
        let request = receive_with_deadline(&mut server).await?;
        send_with_retry(&mut server, &request, true).await?;
        let _response = receive_with_deadline(&mut client).await?;
        rtts.push(started.elapsed().as_micros());
    }

    let mut control_samples = Vec::with_capacity(CONTROL_SAMPLE_COUNT);
    for _ in 0..CONTROL_SAMPLE_COUNT {
        for _ in 0..32 {
            send_with_retry(&mut client, &[9; 1024], false).await?;
        }
        let started = Instant::now();
        send_with_retry(&mut client, b"release-control", true).await?;
        loop {
            if receive_with_deadline(&mut server).await? == b"release-control" {
                break;
            }
        }
        control_samples.push(started.elapsed().as_micros());
    }

    let mut throughput = Vec::with_capacity(THROUGHPUT_CASES.len());
    for (payload_bytes, frames) in THROUGHPUT_CASES {
        let payload = vec![7; payload_bytes];
        let throughput_started = Instant::now();
        let mut transferred = 0_u128;
        let mut remaining = frames;
        while remaining > 0 {
            let batch = remaining.min(32);
            for _ in 0..batch {
                send_with_retry(&mut client, &payload, false).await?;
            }
            for _ in 0..batch {
                transferred = transferred
                    .saturating_add(receive_with_deadline(&mut server).await?.len() as u128);
            }
            remaining -= batch;
        }
        let elapsed_us = throughput_started.elapsed().as_micros().max(1);
        throughput.push(ThroughputSample {
            payload_bytes,
            frames,
            bytes_per_second: transferred.saturating_mul(1_000_000) / elapsed_us,
        });
    }

    let fixed_handle_bytes = std::mem::size_of::<Client>() + std::mem::size_of::<Server>();
    let shutdown_started = Instant::now();
    client.close_write()?;
    server.close_write()?;
    drop(client);
    drop(server);
    let shutdown_us = shutdown_started.elapsed().as_micros();

    rtts.sort_unstable();
    control_samples.sort_unstable();
    Ok(Baseline {
        transport,
        connect_us,
        rtt_p50_us: percentile(&rtts, 50),
        rtt_p95_us: percentile(&rtts, 95),
        rtt_p99_us: percentile(&rtts, 99),
        saturated_control_p99_us: percentile(&control_samples, 99),
        throughput,
        fixed_handle_bytes,
        shutdown_us,
    })
}

async fn send_with_retry<C: Connection>(
    connection: &mut C,
    payload: &[u8],
    control: bool,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let result = if control {
            connection.try_send_control(payload)
        } else {
            connection.try_send(payload)
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("send remained backpressured".into());
                }
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn receive_with_deadline<C: Connection>(
    connection: &mut C,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match connection.try_receive() {
            Ok(Some(message)) => return Ok(message),
            Ok(None) => return Err("connection closed during baseline".into()),
            Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("receive timed out".into());
                }
                tokio::task::yield_now().await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn baseline_budget() -> TransportBudget {
    TransportBudget {
        max_connections: 4,
        max_concurrent_streams: 64,
        control_queue_capacity: 64,
        data_queue_capacity: 128,
        receive_queue_capacity: 128,
        max_frame_bytes: 1024 * 1024,
        control_bytes_per_second: None,
        data_bytes_per_second: None,
        receive_bytes_per_second: None,
        idle_timeout: None,
    }
}

fn crypto_configs() -> Result<(ServerConfig, ClientConfig), Box<dyn Error>> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
    let certificate = generated.cert.der().clone();
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let server = ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
    let client = ClientConfig::with_root_certificates(Arc::new(roots))?;
    Ok((server, client))
}

fn measure_link_handshake() -> Result<u128, Box<dyn Error>> {
    let offer = ProtocolOffer {
        namespace: "example.release".to_owned(),
        versions: VersionRange::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0)),
    };
    let config = |value: u8| HandshakeConfig {
        identity: Identity {
            peer_id: PeerId::from_bytes([value; 32]),
            endpoint_id: EndpointId::from_bytes([value; 16]),
            connection_id: mutsuki_link::ConnectionId::from_bytes([value; 16]),
        },
        policy: HandshakePolicy {
            link_versions: offer.versions,
            protocols: vec![offer.clone()],
            pairing_protocols: vec![offer.clone()],
            allow_pairing: true,
            trusted_peers: BTreeSet::new(),
            max_protocol_offers: 4,
            max_identity_proof_bytes: 64,
        },
        challenge_nonce: [value; 32],
        identity_proof: IdentityProof {
            opaque: vec![value; 32],
        },
        session_id: SessionId::from_bytes([value; 16]),
    };
    let started = Instant::now();
    let mut initiator = HandshakeMachine::initiator(config(1));
    let mut responder = HandshakeMachine::responder(config(2));
    let hello = initiator.start(AuthPath::FirstPairing)?;
    let challenge = sent(responder.receive(hello)?)?;
    let proof = sent(initiator.receive(challenge)?)?;
    responder.receive(proof)?;
    let selection = sent(responder.decide_identity(ProofDecision::Accept)?)?;
    let confirm = sent(initiator.receive(selection)?)?;
    let confirmed = sent(responder.receive(confirm)?)?;
    initiator.receive(confirmed)?;
    Ok(started.elapsed().as_micros())
}

fn sent(outputs: Vec<HandshakeOutput>) -> Result<HandshakeFrame, Box<dyn Error>> {
    outputs
        .into_iter()
        .find_map(|output| match output {
            HandshakeOutput::Send(frame) => Some(frame),
            _ => None,
        })
        .ok_or_else(|| "handshake produced no outbound frame".into())
}

fn measure_idle_state_machine() -> Result<(u128, usize), Box<dyn Error>> {
    let mut heartbeat = HeartbeatController::new(HeartbeatPolicy::default(), 0)?;
    let started = Instant::now();
    let mut actions = 0;
    for sample in 0..100_000 {
        let now = sample % 10_000;
        if heartbeat.tick(now, ConnectionActivityProfile::Idle) != HeartbeatAction::None {
            actions += 1;
        }
    }
    Ok((started.elapsed().as_nanos() / 100_000, actions))
}

fn percentile(samples: &[u128], value: usize) -> u128 {
    let index = samples
        .len()
        .saturating_mul(value)
        .div_ceil(100)
        .saturating_sub(1);
    samples[index.min(samples.len().saturating_sub(1))]
}

fn enforce(baseline: &Baseline) -> Result<(), Box<dyn Error>> {
    if baseline.connect_us > CONNECT_BUDGET_MS * 1_000 {
        return Err(format!("{} connection budget exceeded", baseline.transport).into());
    }
    if baseline.rtt_p99_us > RTT_P99_BUDGET_US {
        return Err(format!("{} RTT budget exceeded", baseline.transport).into());
    }
    if baseline.saturated_control_p99_us > CONTROL_P99_BUDGET_US {
        return Err(format!("{} control latency budget exceeded", baseline.transport).into());
    }
    if baseline
        .throughput
        .iter()
        .any(|sample| sample.bytes_per_second < MIN_THROUGHPUT_BYTES_PER_SECOND)
    {
        return Err(format!("{} throughput budget exceeded", baseline.transport).into());
    }
    if baseline.shutdown_us > SHUTDOWN_BUDGET_MS * 1_000 {
        return Err(format!("{} shutdown budget exceeded", baseline.transport).into());
    }
    Ok(())
}
