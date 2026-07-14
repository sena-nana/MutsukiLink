//! Internal bounded framing bridge shared by opt-in Tokio transports.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

use mutsuki_link_core::{
    Connection, ConnectionMetadata, TransportBudget, TransportError, TransportErrorKind,
};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

#[derive(Clone, Debug, Default)]
pub struct ConnectionCounter(Arc<AtomicUsize>);

impl ConnectionCounter {
    pub fn try_acquire(&self, limit: usize) -> Option<ConnectionPermit> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then_some(current + 1)
            })
            .ok()
            .map(|_| ConnectionPermit(Arc::clone(&self.0)))
    }

    pub fn active(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct ConnectionPermit(Arc<AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub struct FramedConnection {
    metadata: ConnectionMetadata,
    budget: TransportBudget,
    control_tx: mpsc::Sender<Vec<u8>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    receive_rx: mpsc::Receiver<Vec<u8>>,
    close_write_tx: watch::Sender<bool>,
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
    terminal_error: Arc<Mutex<Option<TransportError>>>,
    _permit: Option<ConnectionPermit>,
    write_closed: bool,
    read_closed: bool,
}

pub fn spawn_framed_connection<S>(
    stream: S,
    metadata: ConnectionMetadata,
    budget: TransportBudget,
    permit: Option<ConnectionPermit>,
) -> Result<FramedConnection, TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    spawn_framed_halves(reader, writer, metadata, budget, permit)
}

pub fn spawn_framed_halves<R, W>(
    reader: R,
    writer: W,
    metadata: ConnectionMetadata,
    budget: TransportBudget,
    permit: Option<ConnectionPermit>,
) -> Result<FramedConnection, TransportError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let budget = budget.validate()?;
    tokio::runtime::Handle::try_current().map_err(|_| {
        TransportError::new(
            TransportErrorKind::Other,
            "a Tokio runtime is required to start this transport",
        )
    })?;
    let (control_tx, control_rx) = mpsc::channel(budget.control_queue_capacity);
    let (data_tx, data_rx) = mpsc::channel(budget.data_queue_capacity);
    let (receive_tx, receive_rx) = mpsc::channel(budget.receive_queue_capacity);
    let (close_write_tx, close_write_rx) = watch::channel(false);
    let terminal_error = Arc::new(Mutex::new(None));
    let writer_error = Arc::clone(&terminal_error);
    let reader_error = Arc::clone(&terminal_error);

    let writer_task = tokio::spawn(write_loop(
        writer,
        control_rx,
        data_rx,
        close_write_rx,
        budget,
        writer_error,
    ));
    let reader_task = tokio::spawn(read_loop(reader, receive_tx, budget, reader_error));

    Ok(FramedConnection {
        metadata,
        budget,
        control_tx,
        data_tx,
        receive_rx,
        close_write_tx,
        writer: writer_task,
        reader: reader_task,
        terminal_error,
        _permit: permit,
        write_closed: false,
        read_closed: false,
    })
}

impl FramedConnection {
    fn enqueue(
        sender: &mpsc::Sender<Vec<u8>>,
        message: &[u8],
        max_frame_bytes: usize,
    ) -> Result<(), TransportError> {
        if message.len() > max_frame_bytes {
            return Err(TransportError::new(
                TransportErrorKind::MessageTooLarge,
                "message exceeds transport frame limit",
            ));
        }
        sender
            .try_send(message.to_vec())
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TransportError::new(
                    TransportErrorKind::WouldBlock,
                    "transport send queue is full",
                ),
                mpsc::error::TrySendError::Closed(_) => TransportError::new(
                    TransportErrorKind::Closed,
                    "transport write side is closed",
                ),
            })
    }

    fn terminal_or(&self, fallback: TransportError) -> TransportError {
        self.terminal_error
            .lock()
            .expect("transport terminal lock")
            .clone()
            .unwrap_or(fallback)
    }
}

impl Connection for FramedConnection {
    fn metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }

    fn try_send(&mut self, message: &[u8]) -> Result<(), TransportError> {
        if self.write_closed {
            return Err(TransportError::new(
                TransportErrorKind::Closed,
                "transport write side is closed",
            ));
        }
        Self::enqueue(&self.data_tx, message, self.budget.max_frame_bytes)
    }

    fn try_send_control(&mut self, message: &[u8]) -> Result<(), TransportError> {
        if self.write_closed {
            return Err(TransportError::new(
                TransportErrorKind::Closed,
                "transport write side is closed",
            ));
        }
        Self::enqueue(&self.control_tx, message, self.budget.max_frame_bytes)
    }

    fn try_receive(&mut self) -> Result<Option<Vec<u8>>, TransportError> {
        if self.read_closed {
            return Err(TransportError::new(
                TransportErrorKind::Closed,
                "transport read side is closed",
            ));
        }
        match self.receive_rx.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(mpsc::error::TryRecvError::Empty) => {
                if self.reader.is_finished() {
                    Err(self.terminal_or(TransportError::new(
                        TransportErrorKind::Closed,
                        "transport read side is closed",
                    )))
                } else {
                    Err(TransportError::new(
                        TransportErrorKind::WouldBlock,
                        "no transport message is ready",
                    ))
                }
            }
            Err(mpsc::error::TryRecvError::Disconnected) => Err(self.terminal_or(
                TransportError::new(TransportErrorKind::Closed, "transport read side is closed"),
            )),
        }
    }

    fn close_write(&mut self) -> Result<(), TransportError> {
        if self.write_closed {
            return Ok(());
        }
        self.write_closed = true;
        self.close_write_tx.send(true).map_err(|_| {
            self.terminal_or(TransportError::new(
                TransportErrorKind::Closed,
                "transport write side is closed",
            ))
        })
    }

    fn close_read(&mut self) -> Result<(), TransportError> {
        self.read_closed = true;
        self.reader.abort();
        Ok(())
    }

    fn abort(&mut self) {
        self.write_closed = true;
        self.read_closed = true;
        self.writer.abort();
        self.reader.abort();
    }
}

impl Drop for FramedConnection {
    fn drop(&mut self) {
        self.abort();
    }
}

async fn write_loop<W>(
    mut writer: W,
    mut control_rx: mpsc::Receiver<Vec<u8>>,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    mut close_rx: watch::Receiver<bool>,
    budget: TransportBudget,
    terminal_error: Arc<Mutex<Option<TransportError>>>,
) where
    W: AsyncWrite + Unpin,
{
    loop {
        let next = tokio::select! {
            biased;
            changed = close_rx.changed() => {
                if changed.is_err() || *close_rx.borrow() {
                    while let Ok(message) = control_rx.try_recv() {
                        if write_frame(&mut writer, &message, budget.control_bytes_per_second).await.is_err() {
                            break;
                        }
                    }
                    while let Ok(message) = data_rx.try_recv() {
                        if write_frame(&mut writer, &message, budget.data_bytes_per_second).await.is_err() {
                            break;
                        }
                    }
                    let _ = writer.shutdown().await;
                    return;
                }
                continue;
            }
            message = control_rx.recv() => message.map(|message| (message, true)),
            message = data_rx.recv() => message.map(|message| (message, false)),
        };
        let Some((message, control)) = next else {
            let _ = writer.shutdown().await;
            return;
        };
        let rate = if control {
            budget.control_bytes_per_second
        } else {
            budget.data_bytes_per_second
        };
        if let Err(error) = write_frame(&mut writer, &message, rate).await {
            set_terminal_error(&terminal_error, io_error(error));
            return;
        }
    }
}

async fn write_frame<W>(writer: &mut W, message: &[u8], rate: Option<u64>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    throttle(rate, message.len()).await;
    let length = u32::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_u32(length).await?;
    writer.write_all(message).await?;
    writer.flush().await
}

async fn read_loop<R>(
    mut reader: R,
    receive_tx: mpsc::Sender<Vec<u8>>,
    budget: TransportBudget,
    terminal_error: Arc<Mutex<Option<TransportError>>>,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let length = match with_idle_timeout(budget.idle_timeout, reader.read_u32()).await {
            Ok(length) => length as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(error) => {
                set_terminal_error(&terminal_error, io_error(error));
                return;
            }
        };
        if length > budget.max_frame_bytes {
            set_terminal_error(
                &terminal_error,
                TransportError::new(
                    TransportErrorKind::MessageTooLarge,
                    "received frame exceeds transport limit",
                ),
            );
            return;
        }
        let mut message = vec![0; length];
        if let Err(error) =
            with_idle_timeout(budget.idle_timeout, reader.read_exact(&mut message)).await
        {
            set_terminal_error(&terminal_error, io_error(error));
            return;
        }
        throttle(budget.receive_bytes_per_second, length).await;
        if receive_tx.send(message).await.is_err() {
            return;
        }
    }
}

async fn with_idle_timeout<F, T>(timeout: Option<Duration>, future: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, future)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "transport idle timeout"))?,
        None => future.await,
    }
}

async fn throttle(rate: Option<u64>, bytes: usize) {
    let Some(rate) = rate else {
        return;
    };
    let nanos = (u128::from(bytes as u64) * 1_000_000_000).div_ceil(u128::from(rate));
    let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
    tokio::time::sleep(Duration::from_nanos(nanos)).await;
}

fn io_error(error: io::Error) -> TransportError {
    let kind = match error.kind() {
        io::ErrorKind::TimedOut => TransportErrorKind::TimedOut,
        io::ErrorKind::WouldBlock => TransportErrorKind::WouldBlock,
        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset => {
            TransportErrorKind::Aborted
        }
        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof => TransportErrorKind::Closed,
        _ => TransportErrorKind::Other,
    };
    TransportError::new(kind, "transport I/O failed")
}

fn set_terminal_error(target: &Mutex<Option<TransportError>>, error: TransportError) {
    let mut target = target.lock().expect("transport terminal lock");
    if target.is_none() {
        *target = Some(error);
    }
}

use std::future::Future;

#[cfg(test)]
mod tests {
    use super::*;
    use mutsuki_link_core::EndpointId;
    use tokio::io::{AsyncWriteExt, duplex};

    fn metadata(left: bool) -> ConnectionMetadata {
        ConnectionMetadata {
            local_endpoint: EndpointId::from_bytes([u8::from(left); 16]),
            remote_endpoint: EndpointId::from_bytes([u8::from(!left); 16]),
            peer_hint: None,
            reliable: true,
            datagrams: false,
        }
    }

    #[tokio::test]
    async fn control_capacity_is_independent_from_saturated_data() {
        let (left, right) = duplex(1024);
        let budget = TransportBudget {
            data_queue_capacity: 1,
            control_queue_capacity: 1,
            idle_timeout: None,
            ..TransportBudget::default()
        };
        let mut sender = spawn_framed_connection(left, metadata(true), budget, None).unwrap();
        let mut receiver = spawn_framed_connection(right, metadata(false), budget, None).unwrap();
        sender.try_send(b"data").unwrap();
        sender.try_send_control(b"ping").unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut messages = Vec::new();
        while messages.len() < 2 {
            match receiver.try_receive() {
                Ok(Some(message)) => messages.push(message),
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                    assert!(tokio::time::Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
                result => panic!("unexpected receive result: {result:?}"),
            }
        }
        assert_eq!(messages[0], b"ping");
        assert_eq!(messages[1], b"data");
    }

    #[tokio::test]
    async fn oversized_and_truncated_frames_fail_without_unbounded_allocation() {
        let budget = TransportBudget {
            max_frame_bytes: 16,
            idle_timeout: None,
            ..TransportBudget::default()
        };
        let (mut attacker, victim) = duplex(128);
        let mut receiver = spawn_framed_connection(victim, metadata(false), budget, None).unwrap();
        attacker.write_u32(17).await.unwrap();
        attacker.flush().await.unwrap();
        assert_eq!(
            wait_for_error(&mut receiver).await,
            TransportErrorKind::MessageTooLarge
        );

        let (mut attacker, victim) = duplex(128);
        let mut receiver = spawn_framed_connection(victim, metadata(false), budget, None).unwrap();
        attacker.write_u32(8).await.unwrap();
        attacker.write_all(b"cut").await.unwrap();
        attacker.shutdown().await.unwrap();
        assert_eq!(
            wait_for_error(&mut receiver).await,
            TransportErrorKind::Closed
        );
    }

    #[tokio::test]
    async fn bandwidth_fault_does_not_delay_already_queued_control() {
        let (left, right) = duplex(1024);
        let budget = TransportBudget {
            data_bytes_per_second: Some(100),
            idle_timeout: None,
            ..TransportBudget::default()
        };
        let mut sender = spawn_framed_connection(left, metadata(true), budget, None).unwrap();
        let mut receiver = spawn_framed_connection(right, metadata(false), budget, None).unwrap();
        sender.try_send(&[1; 100]).unwrap();
        sender.try_send_control(b"cancel").unwrap();
        let started = tokio::time::Instant::now();
        assert_eq!(wait_for_message(&mut receiver).await, b"cancel");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(wait_for_message(&mut receiver).await, vec![1; 100]);
        assert!(started.elapsed() >= Duration::from_millis(900));
    }

    #[test]
    fn connection_permits_return_after_repeated_disconnects() {
        let counter = ConnectionCounter::default();
        for _ in 0..10_000 {
            let permit = counter.try_acquire(1).unwrap();
            assert_eq!(counter.active(), 1);
            drop(permit);
        }
        assert_eq!(counter.active(), 0);
    }

    async fn wait_for_message(connection: &mut FramedConnection) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match connection.try_receive() {
                Ok(Some(message)) => return message,
                Err(error) if error.kind == TransportErrorKind::WouldBlock => {
                    assert!(tokio::time::Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
                result => panic!("unexpected receive result: {result:?}"),
            }
        }
    }

    async fn wait_for_error(connection: &mut FramedConnection) -> TransportErrorKind {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            match connection.try_receive() {
                Err(error) if error.kind != TransportErrorKind::WouldBlock => return error.kind,
                Err(_) => {
                    assert!(tokio::time::Instant::now() < deadline);
                    tokio::task::yield_now().await;
                }
                result => panic!("unexpected receive result: {result:?}"),
            }
        }
    }
}
