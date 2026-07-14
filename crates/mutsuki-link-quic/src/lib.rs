//! Opt-in authenticated encrypted QUIC transport with injected TLS identity policy.
//!
//! Client and server crypto configurations are supplied by the caller. This
//! crate does not embed a `DistributedHost` trust model. It intentionally uses a
//! full handshake and never sends Link control operations as 0-RTT data.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

use bytes::Bytes;
use mutsuki_link_core::{
    ConnectContext, Connection, ConnectionMetadata, ConnectionQuality, EndpointId, SecurityLevel,
    TransportBudget, TransportError, TransportErrorKind,
};
use mutsuki_link_io::{ConnectionCounter, ConnectionPermit, FramedConnection, spawn_framed_halves};
use quinn::{ClientConfig, Endpoint, ServerConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const CONTROL_STREAM_PREFACE: &[u8; 9] = b"MLINK\0\x01\0C";
const DATA_STREAM_PREFACE: &[u8; 9] = b"MLINK\0\x01\0D";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicOptions {
    pub budget: TransportBudget,
    pub connect_timeout: Duration,
    pub enable_datagrams: bool,
    /// Reserved for future replay-safe application data. Link control frames
    /// reject this option and currently require a full handshake.
    pub enable_zero_rtt: bool,
}

impl Default for QuicOptions {
    fn default() -> Self {
        Self {
            budget: TransportBudget::default(),
            connect_timeout: Duration::from_secs(10),
            enable_datagrams: true,
            enable_zero_rtt: false,
        }
    }
}

impl QuicOptions {
    fn validate(self) -> Result<Self, TransportError> {
        self.budget.validate()?;
        if self.enable_zero_rtt {
            return Err(TransportError::new(
                TransportErrorKind::Unsupported,
                "0-RTT is disabled for replay-sensitive Link control operations",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub struct QuicConnection {
    control: FramedConnection,
    data: FramedConnection,
    connection: quinn::Connection,
    _endpoint: Endpoint,
    datagram_rx: mpsc::Receiver<Vec<u8>>,
    datagram_reader: JoinHandle<()>,
    datagrams_enabled: bool,
    max_datagram_bytes: usize,
}

impl QuicConnection {
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn quality(&self) -> ConnectionQuality {
        let millis = self.connection.rtt().as_millis();
        ConnectionQuality {
            round_trip_millis: Some(u32::try_from(millis).unwrap_or(u32::MAX)),
            loss_per_million: None,
            consecutive_failures: 0,
        }
    }

    pub const fn security_level(&self) -> SecurityLevel {
        SecurityLevel::AuthenticatedEncrypted
    }

    pub const fn supports_connection_migration(&self) -> bool {
        true
    }
}

impl Connection for QuicConnection {
    fn metadata(&self) -> &ConnectionMetadata {
        self.data.metadata()
    }

    fn try_send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.data.try_send(message)
    }

    fn try_send_control(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.control.try_send_control(message)
    }

    fn try_receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        match self.control.try_receive() {
            Ok(message) => Ok(message),
            Err(error) if error.kind == TransportErrorKind::WouldBlock => self.data.try_receive(),
            Err(error) => Err(error),
        }
    }

    fn try_send_datagram(&mut self, message: &[u8]) -> Result<(), TransportError> {
        if !self.datagrams_enabled {
            return Err(unsupported_datagram());
        }
        if message.len() > self.max_datagram_bytes {
            return Err(TransportError::new(
                TransportErrorKind::MessageTooLarge,
                "QUIC datagram exceeds configured limit",
            ));
        }
        self.connection
            .send_datagram(Bytes::copy_from_slice(message))
            .map_err(|error| match error {
                quinn::SendDatagramError::TooLarge => TransportError::new(
                    TransportErrorKind::MessageTooLarge,
                    "QUIC datagram exceeds path limit",
                ),
                quinn::SendDatagramError::UnsupportedByPeer
                | quinn::SendDatagramError::Disabled => unsupported_datagram(),
                quinn::SendDatagramError::ConnectionLost(_) => {
                    TransportError::new(TransportErrorKind::Closed, "QUIC connection is closed")
                }
            })
    }

    fn try_receive_datagram(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if !self.datagrams_enabled {
            return Err(unsupported_datagram());
        }
        match self.datagram_rx.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(mpsc::error::TryRecvError::Empty) => Err(TransportError::new(
                TransportErrorKind::WouldBlock,
                "no QUIC datagram is ready",
            )),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(TransportError::new(
                TransportErrorKind::Closed,
                "QUIC datagram receiver is closed",
            )),
        }
    }

    fn close_write(&mut self) -> Result<(), TransportError> {
        let control = self.control.close_write();
        let data = self.data.close_write();
        control.and(data)
    }

    fn close_read(&mut self) -> Result<(), TransportError> {
        let control = self.control.close_read();
        let data = self.data.close_read();
        control.and(data)
    }

    fn abort(&mut self) {
        self.control.abort();
        self.data.abort();
        self.datagram_reader.abort();
        self.connection
            .close(VarInt::from_u32(1), b"link connection aborted");
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        self.abort();
    }
}

#[derive(Debug)]
pub struct QuicListener {
    endpoint: Endpoint,
    local_endpoint: EndpointId,
    options: QuicOptions,
    connections: ConnectionCounter,
}

impl QuicListener {
    pub fn bind(
        address: SocketAddr,
        local_endpoint: EndpointId,
        mut server_config: ServerConfig,
        options: QuicOptions,
    ) -> Result<Self, TransportError> {
        let options = options.validate()?;
        apply_server_budget(&mut server_config, options)?;
        let endpoint = Endpoint::server(server_config, address).map_err(quic_io_error)?;
        Ok(Self {
            endpoint,
            local_endpoint,
            options,
            connections: ConnectionCounter::default(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(quic_io_error)
    }

    pub async fn accept(
        &self,
        remote_endpoint: EndpointId,
    ) -> Result<QuicConnection, TransportError> {
        let permit = self
            .connections
            .try_acquire(self.options.budget.max_connections)
            .ok_or_else(connection_limit)?;
        let incoming = self.endpoint.accept().await.ok_or_else(|| {
            TransportError::new(TransportErrorKind::Closed, "QUIC listener is closed")
        })?;
        let connection = incoming.await.map_err(quic_connection_error)?;
        let streams = accept_streams(&connection).await?;
        make_connection(
            self.endpoint.clone(),
            connection,
            streams,
            self.local_endpoint,
            remote_endpoint,
            self.options,
            Some(permit),
        )
    }

    pub fn active_connections(&self) -> usize {
        self.connections.active()
    }
}

#[derive(Debug)]
pub struct QuicConnector {
    endpoint: Endpoint,
    options: QuicOptions,
}

impl QuicConnector {
    pub fn new(
        bind_address: SocketAddr,
        mut client_config: ClientConfig,
        options: QuicOptions,
    ) -> Result<Self, TransportError> {
        let options = options.validate()?;
        apply_client_budget(&mut client_config, options)?;
        let mut endpoint = Endpoint::client(bind_address).map_err(quic_io_error)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint, options })
    }

    /// Rebinds the client endpoint to a new UDP socket while established
    /// connections keep their stable Link identity and may migrate paths.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> Result<(), TransportError> {
        self.endpoint.rebind(socket).map_err(quic_io_error)
    }

    pub async fn connect(
        &self,
        address: SocketAddr,
        server_name: &str,
        local_endpoint: EndpointId,
        remote_endpoint: EndpointId,
        context: &ConnectContext,
    ) -> Result<QuicConnection, TransportError> {
        context.check(Instant::now())?;
        let timeout = context
            .deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .map_or(self.options.connect_timeout, |deadline| {
                deadline.min(self.options.connect_timeout)
            });
        let connecting = self
            .endpoint
            .connect(address, server_name)
            .map_err(quic_connect_error)?;
        // Deliberately await a full handshake; never call `into_0rtt` here.
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| {
                TransportError::new(TransportErrorKind::TimedOut, "QUIC connection timed out")
            })?
            .map_err(quic_connection_error)?;
        context.check(Instant::now())?;
        let streams = open_streams(&connection).await?;
        make_connection(
            self.endpoint.clone(),
            connection,
            streams,
            local_endpoint,
            remote_endpoint,
            self.options,
            None,
        )
    }
}

#[allow(clippy::too_many_arguments)]
struct QuicStreams {
    control_send: quinn::SendStream,
    control_receive: quinn::RecvStream,
    data_send: quinn::SendStream,
    data_receive: quinn::RecvStream,
}

async fn open_streams(connection: &quinn::Connection) -> Result<QuicStreams, TransportError> {
    let (mut control_send, control_receive) =
        connection.open_bi().await.map_err(quic_connection_error)?;
    control_send
        .write_all(CONTROL_STREAM_PREFACE)
        .await
        .map_err(quic_stream_error)?;
    let (mut data_send, data_receive) =
        connection.open_bi().await.map_err(quic_connection_error)?;
    data_send
        .write_all(DATA_STREAM_PREFACE)
        .await
        .map_err(quic_stream_error)?;
    Ok(QuicStreams {
        control_send,
        control_receive,
        data_send,
        data_receive,
    })
}

async fn accept_streams(connection: &quinn::Connection) -> Result<QuicStreams, TransportError> {
    let mut control = None;
    let mut data = None;
    for _ in 0..2 {
        let (send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(quic_connection_error)?;
        match receive_preface(&mut receive).await? {
            StreamKind::Control => control = Some((send, receive)),
            StreamKind::Data => data = Some((send, receive)),
        }
    }
    let (control_send, control_receive) = control.ok_or_else(invalid_stream_set)?;
    let (data_send, data_receive) = data.ok_or_else(invalid_stream_set)?;
    Ok(QuicStreams {
        control_send,
        control_receive,
        data_send,
        data_receive,
    })
}

fn make_connection(
    endpoint: Endpoint,
    connection: quinn::Connection,
    streams: QuicStreams,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
    options: QuicOptions,
    permit: Option<ConnectionPermit>,
) -> Result<QuicConnection, TransportError> {
    let datagrams_enabled = options.enable_datagrams && connection.max_datagram_size().is_some();
    let metadata = ConnectionMetadata {
        local_endpoint,
        remote_endpoint,
        peer_hint: None,
        reliable: true,
        datagrams: datagrams_enabled,
    };
    let control = spawn_framed_halves(
        streams.control_receive,
        streams.control_send,
        metadata.clone(),
        options.budget,
        None,
    )?;
    let data = spawn_framed_halves(
        streams.data_receive,
        streams.data_send,
        metadata,
        options.budget,
        permit,
    )?;
    let (datagram_tx, datagram_rx) = mpsc::channel(options.budget.receive_queue_capacity);
    let datagram_connection = connection.clone();
    let datagram_reader = tokio::spawn(async move {
        while let Ok(message) = datagram_connection.read_datagram().await {
            if datagram_tx.send(message.to_vec()).await.is_err() {
                return;
            }
        }
    });
    Ok(QuicConnection {
        control,
        data,
        connection,
        _endpoint: endpoint,
        datagram_rx,
        datagram_reader,
        datagrams_enabled,
        max_datagram_bytes: options.budget.max_frame_bytes,
    })
}

enum StreamKind {
    Control,
    Data,
}

async fn receive_preface(receive: &mut quinn::RecvStream) -> Result<StreamKind, TransportError> {
    let mut preface = [0; CONTROL_STREAM_PREFACE.len()];
    receive
        .read_exact(&mut preface)
        .await
        .map_err(quic_stream_error)?;
    match &preface {
        value if value == CONTROL_STREAM_PREFACE => Ok(StreamKind::Control),
        value if value == DATA_STREAM_PREFACE => Ok(StreamKind::Data),
        _ => Err(TransportError::new(
            TransportErrorKind::Other,
            "QUIC Link stream preface is invalid",
        )),
    }
}

fn invalid_stream_set() -> TransportError {
    TransportError::new(
        TransportErrorKind::Other,
        "QUIC Link control/data stream set is incomplete",
    )
}

fn transport_config(options: QuicOptions) -> Result<Arc<quinn::TransportConfig>, TransportError> {
    if options.budget.max_concurrent_streams < 2 {
        return Err(TransportError::new(
            TransportErrorKind::Other,
            "QUIC requires at least two streams for independent control and data",
        ));
    }
    let mut transport = quinn::TransportConfig::default();
    let streams = u32::try_from(options.budget.max_concurrent_streams).map_err(|_| {
        TransportError::new(
            TransportErrorKind::Other,
            "QUIC stream limit exceeds protocol range",
        )
    })?;
    transport.max_concurrent_bidi_streams(VarInt::from_u32(streams));
    let buffer = options
        .budget
        .max_frame_bytes
        .saturating_mul(options.budget.receive_queue_capacity);
    if options.enable_datagrams {
        transport.datagram_receive_buffer_size(Some(buffer));
        transport.datagram_send_buffer_size(buffer);
    } else {
        transport.datagram_receive_buffer_size(None);
        transport.datagram_send_buffer_size(0);
    }
    if let Some(idle_timeout) = options.budget.idle_timeout {
        let keep_alive = idle_timeout / 3;
        let protocol_timeout = idle_timeout.try_into().map_err(|_| {
            TransportError::new(
                TransportErrorKind::Other,
                "QUIC idle timeout exceeds protocol range",
            )
        })?;
        transport.max_idle_timeout(Some(protocol_timeout));
        transport.keep_alive_interval(Some(keep_alive));
    }
    Ok(Arc::new(transport))
}

fn apply_server_budget(
    config: &mut ServerConfig,
    options: QuicOptions,
) -> Result<(), TransportError> {
    config.transport_config(transport_config(options)?);
    Ok(())
}

fn apply_client_budget(
    config: &mut ClientConfig,
    options: QuicOptions,
) -> Result<(), TransportError> {
    config.transport_config(transport_config(options)?);
    Ok(())
}

fn unsupported_datagram() -> TransportError {
    TransportError::new(
        TransportErrorKind::Unsupported,
        "QUIC datagrams are not available",
    )
}

fn connection_limit() -> TransportError {
    TransportError::new(
        TransportErrorKind::WouldBlock,
        "QUIC connection limit reached",
    )
}

fn quic_io_error(_error: std::io::Error) -> TransportError {
    TransportError::new(TransportErrorKind::Other, "QUIC endpoint operation failed")
}

fn quic_stream_error<T>(_error: T) -> TransportError {
    TransportError::new(TransportErrorKind::Closed, "QUIC stream operation failed")
}

fn quic_connect_error(_error: quinn::ConnectError) -> TransportError {
    TransportError::new(TransportErrorKind::Other, "QUIC connection setup failed")
}

fn quic_connection_error(error: quinn::ConnectionError) -> TransportError {
    let kind = match error {
        quinn::ConnectionError::TimedOut => TransportErrorKind::TimedOut,
        quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::ConnectionClosed(_) => TransportErrorKind::Closed,
        _ => TransportErrorKind::Aborted,
    };
    TransportError::new(kind, "QUIC connection failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::RootCertStore;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_round_trip_datagram_and_quality_summary() {
        let (server_config, client_config) = crypto_configs();
        let options = QuicOptions {
            budget: TransportBudget {
                idle_timeout: None,
                ..TransportBudget::default()
            },
            ..QuicOptions::default()
        };
        let listener = QuicListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            EndpointId::from_bytes([2; 16]),
            server_config,
            options,
        )
        .unwrap();
        let connector =
            QuicConnector::new("127.0.0.1:0".parse().unwrap(), client_config, options).unwrap();
        let address = listener.local_addr().unwrap();
        let context = ConnectContext::default();
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
        let mut server = server.unwrap();
        let mut client = client.unwrap();
        assert_eq!(
            client.security_level(),
            SecurityLevel::AuthenticatedEncrypted
        );
        assert!(client.supports_connection_migration());
        assert!(client.quality().round_trip_millis.is_some());

        let rebound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        connector.rebind(rebound).unwrap();

        mutsuki_link_transport_testkit::run_session_transport_suite(&mut client, &mut server).await;

        client.try_send_control(b"ping").unwrap();
        client.try_send_datagram(b"event").unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut stream_seen = false;
        let mut datagram_seen = false;
        while !stream_seen || !datagram_seen {
            match server.try_receive() {
                Ok(Some(message)) => {
                    assert_eq!(message, b"ping");
                    stream_seen = true;
                }
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {}
                Err(error) => panic!("stream receive failed: {error}"),
                Ok(None) => panic!("stream closed early"),
            }
            match server.try_receive_datagram() {
                Ok(Some(message)) => {
                    assert_eq!(message, b"event");
                    datagram_seen = true;
                }
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {}
                Err(error) => panic!("datagram receive failed: {error}"),
                Ok(None) => panic!("datagram closed early"),
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        client.close_write().unwrap();
        assert_eq!(
            client.try_send(b"after-close").unwrap_err().kind,
            TransportErrorKind::Closed
        );
    }

    #[test]
    fn zero_rtt_control_is_rejected() {
        let error = QuicOptions {
            enable_zero_rtt: true,
            ..QuicOptions::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(error.kind, TransportErrorKind::Unsupported);
    }
}
