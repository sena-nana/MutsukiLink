use mutsuki_link_core::{
    ConnectContext, Connection, ConnectionActivityProfile, EndpointId, ExponentialBackoff,
    HeartbeatAction, HeartbeatPolicy, PeerId, ReconnectFailure, ReconnectPolicy, RetryLimit,
    TransportBudget, TransportErrorKind,
};
use mutsuki_link_quic::QuicOptions;
use mutsuki_link_runtime::{
    DuplicatePeerPolicy, LinkEndpointConfig, PeerSessionPool, PoolError, PoolEvent,
};
use quinn::{ClientConfig, ServerConfig};
use rustls::RootCertStore;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn crypto_configs() -> (ServerConfig, ClientConfig) {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = generated.cert.der().clone();
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
    let server =
        ServerConfig::with_single_cert(vec![certificate.clone()], private_key.into()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    (server, client)
}

fn test_budget(max_connections: usize) -> TransportBudget {
    TransportBudget {
        max_connections,
        idle_timeout: None,
        ..TransportBudget::default()
    }
}

fn listener_config(max_peers: usize, max_connections: usize) -> LinkEndpointConfig {
    LinkEndpointConfig {
        local_endpoint: EndpointId::from_bytes([0x10; 16]),
        bind: "127.0.0.1:0".parse().unwrap(),
        quic: QuicOptions {
            budget: test_budget(max_connections),
            enable_datagrams: false,
            ..QuicOptions::default()
        },
        max_peers,
        server_name: "localhost".to_owned(),
        reconnect: ReconnectPolicy::ExponentialBackoff(ExponentialBackoff {
            initial_delay_ms: 10,
            maximum_delay_ms: 1_000,
            multiplier_per_thousand: 2_000,
            jitter_per_thousand: 0,
            limit: RetryLimit {
                max_attempts: 4,
                max_elapsed_ms: 60_000,
            },
        }),
        heartbeat: HeartbeatPolicy {
            idle_interval_ms: 1_000,
            active_interval_ms: 500,
            mobile_interval_ms: 1_000,
            background_interval_ms: 2_000,
            local_ipc_interval_ms: 1_000,
            unreachable_after_ms: 5_000,
            dead_after_ms: 10_000,
        },
        ..LinkEndpointConfig::default()
    }
}

fn client_config(local: EndpointId) -> LinkEndpointConfig {
    LinkEndpointConfig {
        local_endpoint: local,
        bind: "127.0.0.1:0".parse().unwrap(),
        quic: QuicOptions {
            budget: test_budget(8),
            enable_datagrams: false,
            ..QuicOptions::default()
        },
        max_peers: 8,
        server_name: "localhost".to_owned(),
        ..LinkEndpointConfig::default()
    }
}

fn peer(byte: u8) -> PeerId {
    PeerId::from_bytes([byte; 32])
}

fn endpoint(byte: u8) -> EndpointId {
    EndpointId::from_bytes([byte; 16])
}

async fn wait_recv(connection: &mut mutsuki_link_quic::QuicConnection, expected: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match connection.try_receive() {
            Ok(Some(message)) => {
                assert_eq!(message, expected);
                return;
            }
            Ok(None) => panic!("connection closed before payload"),
            Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "timed out waiting for payload");
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("receive failed: {error}"),
        }
    }
}

async fn dial_pair(
    hub: &mut PeerSessionPool,
    server_config: &ServerConfig,
    client_config_tls: &ClientConfig,
    address: std::net::SocketAddr,
    remote_peer: PeerId,
    remote_endpoint: EndpointId,
) -> PeerSessionPool {
    let mut client = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        client_config(remote_endpoint),
    )
    .unwrap();
    let accept = hub.accept_inbound(remote_endpoint);
    let connect =
        client.connect_outbound(peer(0x10), address, endpoint(0x10), Some("localhost"), None);
    let (inbound, connected) = tokio::join!(accept, connect);
    connected.expect("outbound connect");
    hub.admit_inbound(
        inbound.expect("inbound accept"),
        remote_peer,
        remote_endpoint,
    )
    .expect("admit inbound");
    client
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_outbound_connects_exchange_independently() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        listener_config(8, 8),
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    let peers = [peer(1), peer(2), peer(3)];
    let endpoints = [endpoint(1), endpoint(2), endpoint(3)];
    let mut client_pools = Vec::new();
    for (index, peer_id) in peers.iter().enumerate() {
        let mut client_pool = dial_pair(
            &mut hub,
            &server_config,
            &client_config_tls,
            address,
            *peer_id,
            endpoints[index],
        )
        .await;
        let payload = format!("hello-{index}");
        client_pool
            .get_mut(&peer(0x10))
            .unwrap()
            .connection_mut()
            .try_send(payload.as_bytes())
            .unwrap();
        client_pools.push((client_pool, payload, *peer_id));
    }

    assert_eq!(hub.session_count(), 3);
    for (_, payload, peer_id) in &client_pools {
        wait_recv(
            hub.get_mut(peer_id).unwrap().connection_mut(),
            payload.as_bytes(),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_inbound_accepts_reach_n() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        listener_config(4, 4),
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    let mut clients = Vec::new();
    for index in 1..=3_u8 {
        clients.push(
            dial_pair(
                &mut hub,
                &server_config,
                &client_config_tls,
                address,
                peer(index),
                endpoint(index),
            )
            .await,
        );
    }

    assert_eq!(hub.session_count(), 3);
    assert_eq!(hub.listener_active_connections(), 3);
    assert_eq!(clients.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_budget_enforced_and_recovers_after_drop() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        listener_config(8, 2),
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    let mut keep = Vec::new();
    for index in 1..=2_u8 {
        keep.push(
            dial_pair(
                &mut hub,
                &server_config,
                &client_config_tls,
                address,
                peer(index),
                endpoint(index),
            )
            .await,
        );
    }
    assert_eq!(hub.listener_active_connections(), 2);

    // At the listener budget, accept fails immediately on permit acquisition (no client dial).
    let rejected = hub.accept_inbound(endpoint(9)).await.unwrap_err();
    match rejected {
        PoolError::Transport(error) => assert_eq!(error.kind, TransportErrorKind::WouldBlock),
        other => panic!("unexpected reject: {other}"),
    }
    assert_eq!(hub.listener_active_connections(), 2);

    drop(keep.remove(0));
    assert!(hub.remove(&peer(1)));
    tokio::task::yield_now().await;
    assert_eq!(hub.listener_active_connections(), 1);

    let _recovered = dial_pair(
        &mut hub,
        &server_config,
        &client_config_tls,
        address,
        peer(3),
        endpoint(3),
    )
    .await;
    assert_eq!(hub.session_count(), 2);
    assert_eq!(hub.listener_active_connections(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_peer_replace_closes_previous_session() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        LinkEndpointConfig {
            duplicate_peer: DuplicatePeerPolicy::ReplaceExisting,
            ..listener_config(4, 4)
        },
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    let _first = dial_pair(
        &mut hub,
        &server_config,
        &client_config_tls,
        address,
        peer(1),
        endpoint(1),
    )
    .await;
    assert_eq!(hub.session_count(), 1);

    let _second = dial_pair(
        &mut hub,
        &server_config,
        &client_config_tls,
        address,
        peer(1),
        endpoint(2),
    )
    .await;
    assert_eq!(hub.session_count(), 1);
    assert_eq!(hub.get(&peer(1)).unwrap().remote_endpoint(), endpoint(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_peers_limit_rejects_additional_admission() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        listener_config(1, 8),
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    let _first = dial_pair(
        &mut hub,
        &server_config,
        &client_config_tls,
        address,
        peer(1),
        endpoint(1),
    )
    .await;

    let mut second = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        client_config(endpoint(2)),
    )
    .unwrap();
    let accept = hub.accept_inbound(endpoint(2));
    let connect =
        second.connect_outbound(peer(0xAA), address, endpoint(0x10), Some("localhost"), None);
    let (inbound, connected) = tokio::join!(accept, connect);
    connected.unwrap();
    let error = hub
        .admit_inbound(inbound.unwrap(), peer(2), endpoint(2))
        .err()
        .unwrap();
    assert_eq!(error, PoolError::PeerLimit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_peer_reconnect_and_heartbeat_are_independent() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        listener_config(4, 4),
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    for index in 1..=2_u8 {
        let client = dial_pair(
            &mut hub,
            &server_config,
            &client_config_tls,
            address,
            peer(index),
            endpoint(index),
        )
        .await;
        std::mem::forget(client);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let events = hub
        .note_transport_failure(&peer(1), ReconnectFailure::TemporarilyUnreachable, now, 0)
        .unwrap();
    assert!(matches!(
        events.as_slice(),
        [PoolEvent::ReconnectScheduled {
            peer_id,
            attempt: 1,
            ..
        }] if *peer_id == peer(1)
    ));

    let heartbeat_events = hub.maintenance_tick(now + 1_600, ConnectionActivityProfile::Idle);
    assert!(heartbeat_events.iter().all(|event| {
        matches!(
            event,
            PoolEvent::Heartbeat { peer_id, .. } if *peer_id == peer(1) || *peer_id == peer(2)
        )
    }));

    let peer2 = hub
        .note_transport_failure(&peer(2), ReconnectFailure::NetworkChanged, now + 2_000, 0)
        .unwrap();
    assert!(matches!(
        peer2.as_slice(),
        [PoolEvent::ReconnectScheduled {
            peer_id,
            attempt: 1,
            ..
        }] if *peer_id == peer(2)
    ));

    let action = hub
        .get_mut(&peer(1))
        .unwrap()
        .tick_heartbeat(now + 10_000, ConnectionActivityProfile::Idle);
    assert_ne!(action, HeartbeatAction::None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_accept_and_connect_four_peers() {
    let (server_config, client_config_tls) = crypto_configs();
    let mut hub = PeerSessionPool::bind(
        server_config.clone(),
        client_config_tls.clone(),
        listener_config(8, 8),
    )
    .unwrap();
    let address = hub.local_addr().unwrap();

    let mut clients = Vec::new();
    for index in 1..=4_u8 {
        let context = ConnectContext {
            deadline: Some(Instant::now() + Duration::from_secs(5)),
            ..ConnectContext::default()
        };
        let mut client = PeerSessionPool::bind(
            server_config.clone(),
            client_config_tls.clone(),
            client_config(endpoint(index)),
        )
        .unwrap();
        let accept = hub.accept_inbound(endpoint(index));
        let connect = client.connect_outbound(
            peer(0xAA),
            address,
            endpoint(0x10),
            Some("localhost"),
            Some(&context),
        );
        let (inbound, connected) = tokio::join!(accept, connect);
        connected.unwrap();
        hub.admit_inbound(inbound.unwrap(), peer(index), endpoint(index))
            .unwrap();
        clients.push(client);
    }

    assert_eq!(hub.session_count(), 4);
    assert_eq!(clients.len(), 4);
    for peer_id in hub.active_peers() {
        assert!(
            *peer_id == peer(1)
                || *peer_id == peer(2)
                || *peer_id == peer(3)
                || *peer_id == peer(4)
        );
    }
}
