//! Opt-in reliable TCP transport.
//!
//! TCP is explicitly plaintext at this layer. Remote production use must add
//! an authenticated encrypted Link session; this crate never claims otherwise.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

use mutsuki_link_core::{
    ConnectContext, Connection, ConnectionMetadata, EndpointId, SecurityLevel, TransportBudget,
    TransportError, TransportErrorKind,
};
use mutsuki_link_io::{
    ConnectionCounter, ConnectionPermit, FramedConnection, spawn_framed_connection,
};
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpConfig {
    pub budget: TransportBudget,
    pub connect_timeout: Duration,
    pub keepalive: Option<Duration>,
    pub no_delay: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            budget: TransportBudget::default(),
            connect_timeout: Duration::from_secs(10),
            keepalive: Some(Duration::from_secs(30)),
            no_delay: true,
        }
    }
}

#[derive(Debug)]
pub struct TcpConnection {
    inner: FramedConnection,
    peer_address: SocketAddr,
}

impl TcpConnection {
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    pub const fn security_level(&self) -> SecurityLevel {
        SecurityLevel::Plaintext
    }
}

impl Connection for TcpConnection {
    fn metadata(&self) -> &ConnectionMetadata {
        self.inner.metadata()
    }

    fn try_send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.inner.try_send(message)
    }

    fn try_send_control(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.inner.try_send_control(message)
    }

    fn try_receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        self.inner.try_receive()
    }

    fn close_write(&mut self) -> Result<(), TransportError> {
        self.inner.close_write()
    }

    fn close_read(&mut self) -> Result<(), TransportError> {
        self.inner.close_read()
    }

    fn abort(&mut self) {
        self.inner.abort();
    }
}

#[derive(Debug)]
pub struct TcpListener {
    listener: TokioTcpListener,
    local_endpoint: EndpointId,
    config: TcpConfig,
    connections: ConnectionCounter,
}

impl TcpListener {
    pub async fn bind(
        address: SocketAddr,
        local_endpoint: EndpointId,
        config: TcpConfig,
    ) -> Result<Self, TransportError> {
        config.budget.validate()?;
        let listener = TokioTcpListener::bind(address).await.map_err(tcp_error)?;
        Ok(Self {
            listener,
            local_endpoint,
            config,
            connections: ConnectionCounter::default(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.listener.local_addr().map_err(tcp_error)
    }

    pub async fn accept(
        &self,
        remote_endpoint: EndpointId,
    ) -> Result<TcpConnection, TransportError> {
        let permit = self
            .connections
            .try_acquire(self.config.budget.max_connections)
            .ok_or_else(connection_limit)?;
        let (stream, peer_address) = self.listener.accept().await.map_err(tcp_error)?;
        configure_stream(&stream, self.config)?;
        make_connection(
            stream,
            peer_address,
            self.local_endpoint,
            remote_endpoint,
            self.config.budget,
            Some(permit),
        )
    }

    pub fn active_connections(&self) -> usize {
        self.connections.active()
    }
}

pub async fn connect(
    address: SocketAddr,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
    config: TcpConfig,
    context: &ConnectContext,
) -> Result<TcpConnection, TransportError> {
    config.budget.validate()?;
    context.check(Instant::now())?;
    let timeout = context
        .deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()))
        .map_or(config.connect_timeout, |deadline| {
            deadline.min(config.connect_timeout)
        });
    let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| TransportError::new(TransportErrorKind::TimedOut, "TCP connection timed out"))?
        .map_err(tcp_error)?;
    context.check(Instant::now())?;
    configure_stream(&stream, config)?;
    make_connection(
        stream,
        address,
        local_endpoint,
        remote_endpoint,
        config.budget,
        None,
    )
}

fn configure_stream(stream: &TcpStream, config: TcpConfig) -> Result<(), TransportError> {
    stream.set_nodelay(config.no_delay).map_err(tcp_error)?;
    if let Some(keepalive) = config.keepalive {
        let socket = SockRef::from(stream);
        socket
            .set_tcp_keepalive(&TcpKeepalive::new().with_time(keepalive))
            .map_err(tcp_error)?;
    }
    Ok(())
}

fn make_connection(
    stream: TcpStream,
    peer_address: SocketAddr,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
    budget: TransportBudget,
    permit: Option<ConnectionPermit>,
) -> Result<TcpConnection, TransportError> {
    let metadata = ConnectionMetadata {
        local_endpoint,
        remote_endpoint,
        peer_hint: None,
        reliable: true,
        datagrams: false,
    };
    Ok(TcpConnection {
        inner: spawn_framed_connection(stream, metadata, budget, permit)?,
        peer_address,
    })
}

fn connection_limit() -> TransportError {
    TransportError::new(
        TransportErrorKind::WouldBlock,
        "TCP connection limit reached",
    )
}

fn tcp_error(error: std::io::Error) -> TransportError {
    let kind = match error.kind() {
        std::io::ErrorKind::AddrInUse => TransportErrorKind::AddressInUse,
        std::io::ErrorKind::TimedOut => TransportErrorKind::TimedOut,
        std::io::ErrorKind::WouldBlock => TransportErrorKind::WouldBlock,
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset => {
            TransportErrorKind::Aborted
        }
        std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::UnexpectedEof => TransportErrorKind::Closed,
        _ => TransportErrorKind::Other,
    };
    TransportError::new(kind, "TCP transport operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_round_trip_backpressure_and_graceful_half_close() {
        let config = TcpConfig {
            budget: TransportBudget {
                control_queue_capacity: 1,
                data_queue_capacity: 1,
                idle_timeout: None,
                ..TransportBudget::default()
            },
            keepalive: Some(Duration::from_secs(15)),
            ..TcpConfig::default()
        };
        let listener = TcpListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            EndpointId::from_bytes([2; 16]),
            config,
        )
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let context = ConnectContext::default();
        let (server, client) = tokio::join!(
            listener.accept(EndpointId::from_bytes([1; 16])),
            connect(
                address,
                EndpointId::from_bytes([1; 16]),
                EndpointId::from_bytes([2; 16]),
                config,
                &context,
            )
        );
        let mut server = server.unwrap();
        let mut client = client.unwrap();
        assert_eq!(client.security_level(), SecurityLevel::Plaintext);
        mutsuki_link_transport_testkit::run_session_transport_suite(&mut client, &mut server).await;
        client.try_send_control(b"ping").unwrap();
        client.close_write().unwrap();
        assert_eq!(
            client.try_send(b"after-close").unwrap_err().kind,
            TransportErrorKind::Closed
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match server.try_receive() {
                Ok(Some(message)) => {
                    assert_eq!(message, b"ping");
                    break;
                }
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                    assert!(tokio::time::Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
                result => panic!("unexpected receive result: {result:?}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_ipv6_loopback_round_trip() {
        let config = TcpConfig {
            budget: TransportBudget {
                idle_timeout: None,
                ..TransportBudget::default()
            },
            ..TcpConfig::default()
        };
        let listener = TcpListener::bind(
            "[::1]:0".parse().unwrap(),
            EndpointId::from_bytes([2; 16]),
            config,
        )
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();
        let context = ConnectContext::default();
        let (server, client) = tokio::join!(
            listener.accept(EndpointId::from_bytes([1; 16])),
            connect(
                address,
                EndpointId::from_bytes([1; 16]),
                EndpointId::from_bytes([2; 16]),
                config,
                &context,
            )
        );
        let (mut server, mut client) = (server.unwrap(), client.unwrap());
        mutsuki_link_transport_testkit::run_session_transport_suite(&mut client, &mut server).await;
    }
}
