use crate::{EndpointId, PeerId};
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    WouldBlock,
    TimedOut,
    Cancelled,
    Closed,
    Aborted,
    MessageTooLarge,
    Unsupported,
    AddressInUse,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    pub kind: TransportErrorKind,
    pub public_message: &'static str,
}

impl TransportError {
    pub const fn new(kind: TransportErrorKind, public_message: &'static str) -> Self {
        Self {
            kind,
            public_message,
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for TransportError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointAddress {
    pub scheme: String,
    pub address: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionMetadata {
    pub local_endpoint: EndpointId,
    pub remote_endpoint: EndpointId,
    pub peer_hint: Option<PeerId>,
    pub reliable: bool,
    pub datagrams: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug, Default)]
pub struct OperationContext {
    pub deadline: Option<Instant>,
    pub cancellation: CancellationToken,
}

impl OperationContext {
    pub fn check(&self, now: Instant) -> Result<(), TransportError> {
        if self.cancellation.is_cancelled() {
            return Err(TransportError::new(
                TransportErrorKind::Cancelled,
                "connection attempt cancelled",
            ));
        }
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            return Err(TransportError::new(
                TransportErrorKind::TimedOut,
                "connection attempt timed out",
            ));
        }
        Ok(())
    }
}

pub type ConnectContext = OperationContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportBudget {
    pub max_connections: usize,
    pub max_concurrent_streams: usize,
    pub control_queue_capacity: usize,
    pub data_queue_capacity: usize,
    pub receive_queue_capacity: usize,
    pub max_frame_bytes: usize,
    /// `None` means unlimited. Control and data use separate token budgets.
    pub control_bytes_per_second: Option<u64>,
    pub data_bytes_per_second: Option<u64>,
    pub receive_bytes_per_second: Option<u64>,
    pub idle_timeout: Option<Duration>,
}

impl Default for TransportBudget {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_concurrent_streams: 64,
            control_queue_capacity: 32,
            data_queue_capacity: 128,
            receive_queue_capacity: 128,
            max_frame_bytes: 1024 * 1024,
            control_bytes_per_second: None,
            data_bytes_per_second: None,
            receive_bytes_per_second: None,
            idle_timeout: Some(Duration::from_secs(60)),
        }
    }
}

impl TransportBudget {
    pub fn validate(self) -> Result<Self, TransportError> {
        if self.max_connections == 0
            || self.max_concurrent_streams == 0
            || self.control_queue_capacity == 0
            || self.data_queue_capacity == 0
            || self.receive_queue_capacity == 0
            || self.max_frame_bytes == 0
            || self.control_bytes_per_second == Some(0)
            || self.data_bytes_per_second == Some(0)
            || self.receive_bytes_per_second == Some(0)
        {
            return Err(TransportError::new(
                TransportErrorKind::Other,
                "transport budget values must be positive",
            ));
        }
        Ok(self)
    }
}

/// Non-blocking, runtime-neutral reliable message connection. `WouldBlock`
/// explicitly signals backpressure; adapters decide how readiness is awaited.
pub trait Connection {
    fn metadata(&self) -> &ConnectionMetadata;
    fn try_send(&mut self, message: &[u8]) -> Result<(), TransportError>;
    fn try_receive(&mut self) -> Result<Option<Vec<u8>>, TransportError>;

    /// Queues a control-plane message using reserved transport capacity when
    /// the implementation supports independent queues.
    fn try_send_control(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.try_send(message)
    }

    fn try_send_with_context(
        &mut self,
        message: &[u8],
        context: &OperationContext,
        now: Instant,
    ) -> Result<(), TransportError> {
        context.check(now)?;
        self.try_send(message)
    }

    fn try_receive_with_context(
        &mut self,
        context: &OperationContext,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        context.check(now)?;
        self.try_receive()
    }

    fn try_send_datagram(&mut self, _message: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::new(
            TransportErrorKind::Unsupported,
            "datagrams are not supported",
        ))
    }

    fn try_receive_datagram(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        Err(TransportError::new(
            TransportErrorKind::Unsupported,
            "datagrams are not supported",
        ))
    }

    fn close_write(&mut self) -> Result<(), TransportError>;
    fn close_read(&mut self) -> Result<(), TransportError>;
    fn abort(&mut self);
}

pub trait Listener {
    type Connection: Connection;
    fn local_address(&self) -> &EndpointAddress;
    fn try_accept(&mut self) -> Result<Option<Self::Connection>, TransportError>;
    fn close(&mut self) -> Result<(), TransportError>;
}

pub trait Transport {
    type Connection: Connection;
    type Listener: Listener<Connection = Self::Connection>;

    fn connect(
        &self,
        endpoint: &EndpointAddress,
        context: &ConnectContext,
    ) -> Result<Self::Connection, TransportError>;
    fn listen(&self, endpoint: &EndpointAddress) -> Result<Self::Listener, TransportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryTransportConfig {
    pub queue_capacity: usize,
    pub max_message_bytes: usize,
    pub datagram_capacity: usize,
}

impl Default for MemoryTransportConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 16,
            max_message_bytes: 64 * 1024,
            datagram_capacity: 8,
        }
    }
}

#[derive(Debug)]
struct MemorySide {
    reliable: VecDeque<Vec<u8>>,
    datagrams: VecDeque<Vec<u8>>,
    write_closed: bool,
    read_closed: bool,
    aborted: bool,
}

impl MemorySide {
    fn new() -> Self {
        Self {
            reliable: VecDeque::new(),
            datagrams: VecDeque::new(),
            write_closed: false,
            read_closed: false,
            aborted: false,
        }
    }
}

#[derive(Debug)]
pub struct MemoryConnection {
    metadata: ConnectionMetadata,
    local: Arc<Mutex<MemorySide>>,
    remote: Arc<Mutex<MemorySide>>,
    config: MemoryTransportConfig,
}

pub fn memory_transport_pair(
    left: EndpointId,
    right: EndpointId,
    config: MemoryTransportConfig,
) -> (MemoryConnection, MemoryConnection) {
    assert!(config.queue_capacity > 0, "queue capacity must be positive");
    assert!(
        config.max_message_bytes > 0,
        "message limit must be positive"
    );
    let left_side = Arc::new(Mutex::new(MemorySide::new()));
    let right_side = Arc::new(Mutex::new(MemorySide::new()));
    let left_connection = MemoryConnection {
        metadata: ConnectionMetadata {
            local_endpoint: left,
            remote_endpoint: right,
            peer_hint: None,
            reliable: true,
            datagrams: config.datagram_capacity > 0,
        },
        local: Arc::clone(&left_side),
        remote: Arc::clone(&right_side),
        config,
    };
    let right_connection = MemoryConnection {
        metadata: ConnectionMetadata {
            local_endpoint: right,
            remote_endpoint: left,
            peer_hint: None,
            reliable: true,
            datagrams: config.datagram_capacity > 0,
        },
        local: right_side,
        remote: left_side,
        config,
    };
    (left_connection, right_connection)
}

impl MemoryConnection {
    fn send_to_remote(&mut self, message: &[u8], datagram: bool) -> Result<(), TransportError> {
        if message.len() > self.config.max_message_bytes {
            return Err(TransportError::new(
                TransportErrorKind::MessageTooLarge,
                "message exceeds transport limit",
            ));
        }
        if self
            .local
            .lock()
            .expect("memory transport lock")
            .write_closed
        {
            return Err(TransportError::new(
                TransportErrorKind::Closed,
                "write side is closed",
            ));
        }
        let mut remote = self.remote.lock().expect("memory transport lock");
        if remote.aborted {
            return Err(TransportError::new(
                TransportErrorKind::Aborted,
                "remote connection aborted",
            ));
        }
        if remote.read_closed {
            return Err(TransportError::new(
                TransportErrorKind::Closed,
                "remote read side is closed",
            ));
        }
        let (queue, capacity) = if datagram {
            (&mut remote.datagrams, self.config.datagram_capacity)
        } else {
            (&mut remote.reliable, self.config.queue_capacity)
        };
        if queue.len() >= capacity {
            return Err(TransportError::new(
                TransportErrorKind::WouldBlock,
                "transport queue is full",
            ));
        }
        queue.push_back(message.to_vec());
        Ok(())
    }

    fn receive_local(&mut self, datagram: bool) -> Result<Option<Vec<u8>>, TransportError> {
        let mut local = self.local.lock().expect("memory transport lock");
        if local.aborted {
            return Err(TransportError::new(
                TransportErrorKind::Aborted,
                "connection aborted",
            ));
        }
        if local.read_closed {
            return Err(TransportError::new(
                TransportErrorKind::Closed,
                "read side is closed",
            ));
        }
        let message = if datagram {
            local.datagrams.pop_front()
        } else {
            local.reliable.pop_front()
        };
        if message.is_some() {
            return Ok(message);
        }
        drop(local);
        let remote = self.remote.lock().expect("memory transport lock");
        if remote.write_closed {
            Ok(None)
        } else {
            Err(TransportError::new(
                TransportErrorKind::WouldBlock,
                "no message is ready",
            ))
        }
    }
}

impl Connection for MemoryConnection {
    fn metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }

    fn try_send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        self.send_to_remote(message, false)
    }

    fn try_receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        self.receive_local(false)
    }

    fn try_send_datagram(&mut self, message: &[u8]) -> Result<(), TransportError> {
        if self.config.datagram_capacity == 0 {
            return Err(TransportError::new(
                TransportErrorKind::Unsupported,
                "datagrams are not supported",
            ));
        }
        self.send_to_remote(message, true)
    }

    fn try_receive_datagram(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.config.datagram_capacity == 0 {
            return Err(TransportError::new(
                TransportErrorKind::Unsupported,
                "datagrams are not supported",
            ));
        }
        self.receive_local(true)
    }

    fn close_write(&mut self) -> Result<(), TransportError> {
        self.local
            .lock()
            .expect("memory transport lock")
            .write_closed = true;
        Ok(())
    }

    fn close_read(&mut self) -> Result<(), TransportError> {
        self.local
            .lock()
            .expect("memory transport lock")
            .read_closed = true;
        Ok(())
    }

    fn abort(&mut self) {
        self.local.lock().expect("memory transport lock").aborted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(value: u8) -> EndpointId {
        EndpointId::from_bytes([value; 16])
    }

    #[test]
    fn memory_transport_is_bounded_and_supports_half_close() {
        let config = MemoryTransportConfig {
            queue_capacity: 1,
            max_message_bytes: 4,
            datagram_capacity: 1,
        };
        let (mut left, mut right) = memory_transport_pair(endpoint(1), endpoint(2), config);
        left.try_send(b"ping").unwrap();
        assert_eq!(
            left.try_send(b"more").unwrap_err().kind,
            TransportErrorKind::WouldBlock
        );
        assert_eq!(right.try_receive().unwrap(), Some(b"ping".to_vec()));
        left.close_write().unwrap();
        assert_eq!(right.try_receive().unwrap(), None);
        assert_eq!(
            left.try_send(b"x").unwrap_err().kind,
            TransportErrorKind::Closed
        );
    }

    #[test]
    fn cancellation_and_deadline_are_explicit() {
        let token = CancellationToken::default();
        token.cancel();
        let context = ConnectContext {
            deadline: None,
            cancellation: token,
        };
        assert_eq!(
            context.check(Instant::now()).unwrap_err().kind,
            TransportErrorKind::Cancelled
        );
    }
}
