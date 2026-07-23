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
    ConnectContext, Connection, ConnectionMetadata, ConnectionQuality, EndpointId,
    REALTIME_DATAGRAM_HEADER_LEN, RealtimeDatagram, RealtimeEvent, RealtimeFlowId,
    RealtimeFlowTelemetry, RealtimeQueueConfig, RealtimeSendQueue, RealtimeTelemetry,
    ReceivedRealtimeDatagram, SecurityLevel, SendOutcome, TransportBudget, TransportError,
    TransportErrorKind, decode_realtime_datagram, encode_realtime_datagram,
    realtime_flow_from_wire,
};
use mutsuki_link_io::{ConnectionCounter, ConnectionPermit, FramedConnection, spawn_framed_halves};
use quinn::{ClientConfig, Endpoint, ServerConfig, VarInt};
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const CONTROL_STREAM_PREFACE: &[u8; 9] = b"MLINK\0\x01\0C";
const DATA_STREAM_PREFACE: &[u8; 9] = b"MLINK\0\x01\0D";
const MAX_REALTIME_DATAGRAMS_PER_POLL: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicOptions {
    pub budget: TransportBudget,
    pub connect_timeout: Duration,
    pub enable_datagrams: bool,
    pub realtime_queue: RealtimeQueueConfig,
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
            realtime_queue: RealtimeQueueConfig::default(),
            enable_zero_rtt: false,
        }
    }
}

impl QuicOptions {
    fn validate(self) -> Result<Self, TransportError> {
        self.budget.validate()?;
        if !self.realtime_queue.is_valid() {
            return Err(TransportError::new(
                TransportErrorKind::Other,
                "realtime queue limits must be positive",
            ));
        }
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
    datagram_receive: Arc<Mutex<DatagramReceiveState>>,
    datagram_reader: JoinHandle<()>,
    datagrams_enabled: bool,
    max_datagram_bytes: usize,
    realtime_send: RealtimeSendQueue,
    realtime_events: VecDeque<RealtimeEvent>,
    last_remote_address: SocketAddr,
}

#[derive(Debug)]
struct RawReceivedDatagram {
    received_at: Instant,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct DatagramReceiveState {
    queue: VecDeque<RawReceivedDatagram>,
    capacity: usize,
    overflow: u64,
    flow_stats: BTreeMap<RealtimeFlowId, RealtimeFlowTelemetry>,
}

impl DatagramReceiveState {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            overflow: 0,
            flow_stats: BTreeMap::new(),
        }
    }

    fn push(&mut self, payload: Vec<u8>, received_at: Instant) {
        if let Some(flow) = realtime_flow_from_wire(&payload) {
            let stats = self.flow_stats.entry(flow).or_default();
            stats.received = stats.received.saturating_add(1);
            stats.received_bytes = stats
                .received_bytes
                .saturating_add(payload.len().saturating_sub(REALTIME_DATAGRAM_HEADER_LEN) as u64);
        }
        if self.queue.len() >= self.capacity {
            if let Some(dropped) = self.queue.pop_front() {
                self.overflow = self.overflow.saturating_add(1);
                if let Some(flow) = realtime_flow_from_wire(&dropped.payload) {
                    let stats = self.flow_stats.entry(flow).or_default();
                    stats.receive_queue_overflow = stats.receive_queue_overflow.saturating_add(1);
                }
            }
        }
        self.queue.push_back(RawReceivedDatagram {
            received_at,
            payload,
        });
    }

    fn pop(&mut self) -> Option<RawReceivedDatagram> {
        self.queue.pop_front()
    }

    fn clear(&mut self) {
        self.queue.clear();
    }
}

impl QuicConnection {
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn quality(&self) -> ConnectionQuality {
        let millis = self.connection.rtt().as_millis();
        ConnectionQuality {
            round_trip_millis: Some(u32::try_from(millis).unwrap_or(u32::MAX)),
            transport: Some(mutsuki_link_core::TransportKind::Quic),
            ..ConnectionQuality::default()
        }
    }

    pub const fn security_level(&self) -> SecurityLevel {
        SecurityLevel::AuthenticatedEncrypted
    }

    pub const fn supports_connection_migration(&self) -> bool {
        true
    }

    fn current_raw_datagram_limit(&self) -> usize {
        self.connection
            .max_datagram_size()
            .unwrap_or(0)
            .min(self.max_datagram_bytes)
    }

    fn current_realtime_payload_limit(&self) -> usize {
        self.current_raw_datagram_limit()
            .saturating_sub(REALTIME_DATAGRAM_HEADER_LEN)
    }

    fn refresh_realtime_state(&mut self) -> Result<(), TransportError> {
        if !self.datagrams_enabled {
            return Ok(());
        }
        let payload_limit = self.current_realtime_payload_limit();
        if payload_limit == 0 {
            return Err(unsupported_datagram());
        }
        let previous = self.realtime_send.max_payload();
        if self.realtime_send.set_max_payload(payload_limit)? {
            self.realtime_events
                .push_back(RealtimeEvent::DatagramPayloadChanged {
                    previous,
                    current: payload_limit,
                });
        }
        let remote_address = self.connection.remote_address();
        if remote_address != self.last_remote_address {
            self.last_remote_address = remote_address;
            self.realtime_send.note_migration();
            self.realtime_events.push_back(RealtimeEvent::PathMigrated);
        }
        let stats = self.connection.stats();
        let rtt_us = u64::try_from(stats.path.rtt.as_micros()).unwrap_or(u64::MAX);
        let estimated_send_rate_bps = (rtt_us > 0).then(|| {
            let rate = u128::from(stats.path.cwnd)
                .saturating_mul(8_000_000)
                .checked_div(u128::from(rtt_us))
                .unwrap_or(0);
            u64::try_from(rate).unwrap_or(u64::MAX)
        });
        self.realtime_send.note_network_metrics(
            rtt_us,
            estimated_send_rate_bps,
            stats.path.congestion_events,
        );
        Ok(())
    }

    fn pop_raw_datagram(&mut self) -> Result<Option<RawReceivedDatagram>, TransportError> {
        let message = self
            .datagram_receive
            .lock()
            .expect("QUIC datagram receive lock")
            .pop();
        if message.is_some() {
            return Ok(message);
        }
        if self.datagram_reader.is_finished() {
            Err(TransportError::new(
                TransportErrorKind::Closed,
                "QUIC datagram receiver is closed",
            ))
        } else {
            Err(TransportError::new(
                TransportErrorKind::WouldBlock,
                "no QUIC datagram is ready",
            ))
        }
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

    fn try_receive_control(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        self.control.try_receive_control()
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
        if message.len() > self.current_raw_datagram_limit() {
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
        self.pop_raw_datagram()
            .map(|message| message.map(|item| item.payload))
    }

    fn max_datagram_payload(&self) -> Option<usize> {
        self.datagrams_enabled
            .then(|| self.current_realtime_payload_limit())
            .filter(|payload| *payload > 0)
    }

    fn try_send_latest(
        &mut self,
        datagram: RealtimeDatagram<'_>,
    ) -> Result<SendOutcome, TransportError> {
        if !self.datagrams_enabled {
            return Ok(SendOutcome::Unsupported);
        }
        self.refresh_realtime_state()?;
        let now = Instant::now();
        let drops_before = self
            .realtime_send
            .congestion_dropped_for_flow(datagram.flow);
        let outcome = self.realtime_send.enqueue(datagram, now)?;
        self.poll_realtime(now)?;
        let drops_after = self
            .realtime_send
            .congestion_dropped_for_flow(datagram.flow);
        Ok(if drops_after > drops_before {
            SendOutcome::DroppedCongested
        } else {
            outcome
        })
    }

    fn poll_realtime(&mut self, now: Instant) -> Result<usize, TransportError> {
        if !self.datagrams_enabled {
            return Err(unsupported_datagram());
        }
        self.refresh_realtime_state()?;
        let mut sent = 0usize;
        loop {
            if sent >= MAX_REALTIME_DATAGRAMS_PER_POLL {
                return Ok(sent);
            }
            let available = self.connection.datagram_send_buffer_space();
            if let Some(datagram) = self.realtime_send.pop_next_fitting(now, available) {
                let encoded = encode_realtime_datagram(&datagram)?;
                self.connection
                    .send_datagram(Bytes::from(encoded))
                    .map_err(map_datagram_error)?;
                self.realtime_send.note_sent(&datagram);
                sent = sent.saturating_add(1);
                continue;
            }
            if self.realtime_send.pending_datagrams() > 0 {
                self.realtime_send.note_transport_congestion();
                if self.realtime_send.drop_disposable_for_congestion() > 0 {
                    continue;
                }
            }
            return Ok(sent);
        }
    }

    fn try_receive_realtime(&mut self) -> Result<Option<ReceivedRealtimeDatagram>, TransportError> {
        if !self.datagrams_enabled {
            return Err(unsupported_datagram());
        }
        let message = self.pop_raw_datagram()?;
        message
            .map(|item| decode_realtime_datagram(&item.payload, item.received_at))
            .transpose()
    }

    fn realtime_telemetry(&self) -> RealtimeTelemetry {
        let mut telemetry = self.realtime_send.telemetry();
        let receive = self
            .datagram_receive
            .lock()
            .expect("QUIC datagram receive lock");
        telemetry.receive_queue_overflow = receive.overflow;
        for (flow, receive_stats) in &receive.flow_stats {
            let stats = telemetry.flows.entry(*flow).or_default();
            stats.received = receive_stats.received;
            stats.received_bytes = receive_stats.received_bytes;
            stats.receive_queue_overflow = receive_stats.receive_queue_overflow;
        }
        telemetry
    }

    fn take_realtime_events(&mut self) -> Vec<RealtimeEvent> {
        self.realtime_events.drain(..).collect()
    }

    fn reset_realtime_session(&mut self) {
        self.realtime_send.reset_for_reconnect();
        self.datagram_receive
            .lock()
            .expect("QUIC datagram receive lock")
            .clear();
        self.realtime_events.push_back(RealtimeEvent::SessionReset);
    }

    fn close_write(&mut self) -> Result<(), TransportError> {
        self.realtime_send.clear_pending();
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
        self.realtime_send.clear_pending();
        self.datagram_receive
            .lock()
            .expect("QUIC datagram receive lock")
            .clear();
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
    let datagram_receive = Arc::new(Mutex::new(DatagramReceiveState::new(
        options.budget.receive_queue_capacity,
    )));
    let datagram_receive_task = Arc::clone(&datagram_receive);
    let datagram_connection = connection.clone();
    let datagram_reader = tokio::spawn(async move {
        while let Ok(message) = datagram_connection.read_datagram().await {
            datagram_receive_task
                .lock()
                .expect("QUIC datagram receive lock")
                .push(message.to_vec(), Instant::now());
        }
    });
    let max_datagram_bytes = options.budget.max_frame_bytes;
    let realtime_payload = connection
        .max_datagram_size()
        .unwrap_or(0)
        .min(max_datagram_bytes)
        .saturating_sub(REALTIME_DATAGRAM_HEADER_LEN)
        .max(1);
    let realtime_send = RealtimeSendQueue::new(options.realtime_queue, realtime_payload)?;
    let last_remote_address = connection.remote_address();
    Ok(QuicConnection {
        control,
        data,
        connection,
        _endpoint: endpoint,
        datagram_receive,
        datagram_reader,
        datagrams_enabled,
        max_datagram_bytes,
        realtime_send,
        realtime_events: VecDeque::new(),
        last_remote_address,
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

fn map_datagram_error(error: quinn::SendDatagramError) -> TransportError {
    match error {
        quinn::SendDatagramError::TooLarge => TransportError::new(
            TransportErrorKind::MessageTooLarge,
            "QUIC datagram exceeds path limit",
        ),
        quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => {
            unsupported_datagram()
        }
        quinn::SendDatagramError::ConnectionLost(_) => {
            TransportError::new(TransportErrorKind::Closed, "QUIC connection is closed")
        }
    }
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
    async fn concurrent_accepts_respect_connection_budget() {
        let (server_config, client_config) = crypto_configs();
        let options = QuicOptions {
            budget: TransportBudget {
                max_connections: 2,
                idle_timeout: None,
                ..TransportBudget::default()
            },
            enable_datagrams: false,
            ..QuicOptions::default()
        };
        let listener = QuicListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            EndpointId::from_bytes([2; 16]),
            server_config,
            options,
        )
        .unwrap();
        let address = listener.local_addr().unwrap();
        let connector =
            QuicConnector::new("127.0.0.1:0".parse().unwrap(), client_config, options).unwrap();
        let context = ConnectContext::default();

        let mut servers = Vec::new();
        let mut clients = Vec::new();
        for index in 0..2_u8 {
            let accept = listener.accept(EndpointId::from_bytes([index; 16]));
            let connect = connector.connect(
                address,
                "localhost",
                EndpointId::from_bytes([index; 16]),
                EndpointId::from_bytes([2; 16]),
                &context,
            );
            let (server, client) = tokio::join!(accept, connect);
            servers.push(server.unwrap());
            clients.push(client.unwrap());
        }
        assert_eq!(listener.active_connections(), 2);
        let rejected = listener
            .accept(EndpointId::from_bytes([9; 16]))
            .await
            .unwrap_err();
        assert_eq!(rejected.kind, TransportErrorKind::WouldBlock);

        drop(servers.remove(0));
        drop(clients.remove(0));
        tokio::task::yield_now().await;
        assert_eq!(listener.active_connections(), 1);

        let accept = listener.accept(EndpointId::from_bytes([3; 16]));
        let connect = connector.connect(
            address,
            "localhost",
            EndpointId::from_bytes([3; 16]),
            EndpointId::from_bytes([2; 16]),
            &context,
        );
        let (server, client) = tokio::join!(accept, connect);
        let _server = server.unwrap();
        let _client = client.unwrap();
        assert_eq!(listener.active_connections(), 2);
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

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn realtime_flows_and_reliable_control_round_trip_with_telemetry() {
        let (server_config, client_config) = crypto_configs();
        let options = QuicOptions {
            budget: TransportBudget {
                receive_queue_capacity: 8,
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
        let (mut server, mut client) = (server.unwrap(), client.unwrap());

        let protocol = mutsuki_link_core::ProtocolId::new("mutsuki.realtime-test").unwrap();
        let mut control = client.open_control_stream(protocol.clone()).unwrap();
        assert_eq!(control.protocol(), &protocol);
        control.try_send(b"configure").unwrap();
        drop(control);
        let mut server_control = server.open_control_stream(protocol).unwrap();
        assert_eq!(wait_for_control(&mut server_control).await, b"configure");
        drop(server_control);

        let max_payload = client.max_datagram_payload().unwrap();
        assert!(max_payload >= 1_100);
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(
            client
                .try_send_latest(RealtimeDatagram {
                    flow: RealtimeFlowId(1),
                    generation: 4,
                    sequence: 10,
                    deadline,
                    priority: mutsuki_link_core::RealtimePriority::High,
                    payload: b"sensor-a",
                })
                .unwrap(),
            SendOutcome::Enqueued
        );
        assert_eq!(
            client
                .try_send_latest(RealtimeDatagram {
                    flow: RealtimeFlowId(2),
                    generation: 4,
                    sequence: 10,
                    deadline,
                    priority: mutsuki_link_core::RealtimePriority::Normal,
                    payload: b"sensor-b",
                })
                .unwrap(),
            SendOutcome::Enqueued
        );
        assert_eq!(
            client
                .try_send_latest(RealtimeDatagram {
                    flow: RealtimeFlowId(3),
                    generation: 4,
                    sequence: 10,
                    deadline: Instant::now(),
                    priority: mutsuki_link_core::RealtimePriority::Disposable,
                    payload: b"expired",
                })
                .unwrap(),
            SendOutcome::DroppedExpired
        );
        assert_eq!(
            client
                .try_send_latest(RealtimeDatagram {
                    flow: RealtimeFlowId(1),
                    generation: 4,
                    sequence: 11,
                    deadline,
                    priority: mutsuki_link_core::RealtimePriority::Normal,
                    payload: &vec![0; max_payload + 65_536],
                })
                .unwrap_err()
                .kind,
            TransportErrorKind::MessageTooLarge
        );

        let first = wait_for_realtime(&mut server).await;
        let second = wait_for_realtime(&mut server).await;
        let messages_by_flow: BTreeMap<_, _> = [first, second]
            .into_iter()
            .map(|message| (message.flow, message))
            .collect();
        assert_eq!(messages_by_flow[&RealtimeFlowId(1)].payload, b"sensor-a");
        assert_eq!(messages_by_flow[&RealtimeFlowId(2)].payload, b"sensor-b");
        assert!(
            messages_by_flow
                .values()
                .all(|message| message.sequence == 10)
        );

        let sender = client.realtime_telemetry();
        assert_eq!(sender.sent, 2);
        assert_eq!(sender.expired, 1);
        assert!(sender.rtt_us.is_some());
        assert!(sender.estimated_send_rate_bps.is_some());
        let receive_telemetry = server.realtime_telemetry();
        assert_eq!(receive_telemetry.flows[&RealtimeFlowId(1)].received, 1);
        assert_eq!(receive_telemetry.flows[&RealtimeFlowId(2)].received, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receive_overflow_drops_oldest_and_reconnect_reset_clears_state() {
        let (server_config, client_config) = crypto_configs();
        let options = QuicOptions {
            budget: TransportBudget {
                receive_queue_capacity: 2,
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
        let (mut server, mut client) = (server.unwrap(), client.unwrap());
        let deadline = Instant::now() + Duration::from_secs(1);
        for sequence in 0..8 {
            client
                .try_send_latest(RealtimeDatagram {
                    flow: RealtimeFlowId(5),
                    generation: 1,
                    sequence,
                    deadline,
                    priority: mutsuki_link_core::RealtimePriority::Disposable,
                    payload: &[u8::try_from(sequence).unwrap()],
                })
                .unwrap();
        }
        let wait_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while server.realtime_telemetry().receive_queue_overflow < 6 {
            assert!(tokio::time::Instant::now() < wait_deadline);
            tokio::task::yield_now().await;
        }
        assert_eq!(server.realtime_telemetry().receive_queue_overflow, 6);
        let received = [
            wait_for_realtime(&mut server).await,
            wait_for_realtime(&mut server).await,
        ];
        assert!(
            received
                .iter()
                .all(|message| message.flow == RealtimeFlowId(5))
        );

        server.reset_realtime_session();
        assert_eq!(server.realtime_telemetry().reconnect_count, 1);
        assert_eq!(
            server.take_realtime_events(),
            vec![RealtimeEvent::SessionReset]
        );
    }

    // GitHub's Windows runner has IPv6 TCP but no bindable IPv6 UDP loopback
    // for Quinn. Windows still exercises QUIC over IPv4 and TCP over IPv6.
    #[cfg(not(windows))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_ipv6_loopback_round_trip() {
        let (server_config, client_config) = crypto_configs();
        let options = QuicOptions {
            budget: TransportBudget {
                idle_timeout: None,
                ..TransportBudget::default()
            },
            ..QuicOptions::default()
        };
        let listener = QuicListener::bind(
            "[::1]:0".parse().unwrap(),
            EndpointId::from_bytes([2; 16]),
            server_config,
            options,
        )
        .unwrap();
        let connector =
            QuicConnector::new("[::1]:0".parse().unwrap(), client_config, options).unwrap();
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
        let (mut server, mut client) = (server.unwrap(), client.unwrap());
        mutsuki_link_transport_testkit::run_session_transport_suite(&mut client, &mut server).await;
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

    #[test]
    fn bounded_receive_queue_drops_oldest_datagram_and_tracks_flow() {
        let now = Instant::now();
        let mut receive = DatagramReceiveState::new(2);
        for sequence in 0..8 {
            let queued = mutsuki_link_core::QueuedRealtimeDatagram {
                flow: RealtimeFlowId(5),
                generation: 1,
                sequence,
                deadline: now + Duration::from_secs(1),
                priority: mutsuki_link_core::RealtimePriority::Disposable,
                payload: vec![u8::try_from(sequence).unwrap()],
            };
            receive.push(encode_realtime_datagram(&queued).unwrap(), now);
        }
        assert_eq!(receive.overflow, 6);
        assert_eq!(
            receive.flow_stats[&RealtimeFlowId(5)].receive_queue_overflow,
            6
        );
        let remaining: Vec<_> = [receive.pop().unwrap(), receive.pop().unwrap()]
            .into_iter()
            .map(|message| {
                decode_realtime_datagram(&message.payload, message.received_at)
                    .unwrap()
                    .sequence
            })
            .collect();
        assert_eq!(remaining, vec![6, 7]);
    }

    async fn wait_for_control(
        connection: &mut mutsuki_link_core::ControlStream<'_, QuicConnection>,
    ) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match connection.try_receive() {
                Ok(Some(message)) => return message,
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                    assert!(tokio::time::Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
                result => panic!("unexpected control receive result: {result:?}"),
            }
        }
    }

    async fn wait_for_realtime(connection: &mut QuicConnection) -> ReceivedRealtimeDatagram {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match connection.try_receive_realtime() {
                Ok(Some(message)) => return message,
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                    assert!(tokio::time::Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
                result => panic!("unexpected realtime receive result: {result:?}"),
            }
        }
    }
}
