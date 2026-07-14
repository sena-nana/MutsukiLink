//! Opt-in local IPC transport backed by Unix-domain sockets or Windows named pipes.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

use interprocess::local_socket::{
    GenericNamespaced, ListenerOptions,
    tokio::{Listener as IpcListener, Stream as IpcStream, prelude::*},
    traits::StreamCommon,
};
use mutsuki_link_core::{
    ConnectContext, Connection, ConnectionMetadata, EndpointId, TransportBudget, TransportError,
    TransportErrorKind,
};
use mutsuki_link_io::{ConnectionCounter, FramedConnection, spawn_framed_connection};
use std::time::Instant;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAddress(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPeerCredentials {
    pub process_id: Option<u32>,
    #[cfg(unix)]
    pub effective_user_id: Option<u32>,
    #[cfg(unix)]
    pub effective_group_id: Option<u32>,
}

#[derive(Debug)]
pub struct LocalConnection {
    inner: FramedConnection,
    peer_credentials: Option<LocalPeerCredentials>,
}

impl LocalConnection {
    pub fn peer_credentials(&self) -> Option<&LocalPeerCredentials> {
        self.peer_credentials.as_ref()
    }
}

impl Connection for LocalConnection {
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
pub struct LocalListener {
    listener: IpcListener,
    local_endpoint: EndpointId,
    budget: TransportBudget,
    connections: ConnectionCounter,
}

impl LocalListener {
    pub fn bind(
        address: &LocalAddress,
        local_endpoint: EndpointId,
        budget: TransportBudget,
    ) -> Result<Self, TransportError> {
        let budget = budget.validate()?;
        let name = address
            .0
            .as_str()
            .to_ns_name::<GenericNamespaced>()
            .map_err(local_error)?;
        let listener = ListenerOptions::new()
            .name(name)
            .create_tokio()
            .map_err(local_error)?;
        Ok(Self {
            listener,
            local_endpoint,
            budget,
            connections: ConnectionCounter::default(),
        })
    }

    pub async fn accept(
        &self,
        remote_endpoint: EndpointId,
    ) -> Result<LocalConnection, TransportError> {
        let permit = self
            .connections
            .try_acquire(self.budget.max_connections)
            .ok_or_else(|| {
                TransportError::new(
                    TransportErrorKind::WouldBlock,
                    "local connection limit reached",
                )
            })?;
        let stream = self.listener.accept().await.map_err(local_error)?;
        make_connection(
            stream,
            self.local_endpoint,
            remote_endpoint,
            self.budget,
            Some(permit),
        )
    }

    pub fn active_connections(&self) -> usize {
        self.connections.active()
    }
}

pub async fn connect(
    address: &LocalAddress,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
    budget: TransportBudget,
    context: &ConnectContext,
) -> Result<LocalConnection, TransportError> {
    context.check(Instant::now())?;
    let name = address
        .0
        .as_str()
        .to_ns_name::<GenericNamespaced>()
        .map_err(local_error)?;
    let connect = IpcStream::connect(name);
    let stream = match context.deadline {
        Some(deadline) => {
            let duration = deadline.saturating_duration_since(Instant::now());
            tokio::time::timeout(duration, connect)
                .await
                .map_err(|_| {
                    TransportError::new(TransportErrorKind::TimedOut, "local connection timed out")
                })?
                .map_err(local_error)?
        }
        None => connect.await.map_err(local_error)?,
    };
    context.check(Instant::now())?;
    make_connection(stream, local_endpoint, remote_endpoint, budget, None)
}

fn make_connection(
    stream: IpcStream,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
    budget: TransportBudget,
    permit: Option<mutsuki_link_io::ConnectionPermit>,
) -> Result<LocalConnection, TransportError> {
    let peer_credentials = stream
        .peer_creds()
        .ok()
        .map(|credentials| LocalPeerCredentials {
            process_id: credentials
                .pid()
                .and_then(|value| u32::try_from(value).ok()),
            #[cfg(unix)]
            effective_user_id: credentials.euid(),
            #[cfg(unix)]
            effective_group_id: credentials.egid(),
        });
    let metadata = ConnectionMetadata {
        local_endpoint,
        remote_endpoint,
        peer_hint: None,
        reliable: true,
        datagrams: false,
    };
    Ok(LocalConnection {
        inner: spawn_framed_connection(stream, metadata, budget, permit)?,
        peer_credentials,
    })
}

fn local_error(error: std::io::Error) -> TransportError {
    let kind = match error.kind() {
        std::io::ErrorKind::AddrInUse => TransportErrorKind::AddressInUse,
        std::io::ErrorKind::TimedOut => TransportErrorKind::TimedOut,
        std::io::ErrorKind::WouldBlock => TransportErrorKind::WouldBlock,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            TransportErrorKind::Closed
        }
        _ => TransportErrorKind::Other,
    };
    TransportError::new(kind, "local transport operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_round_trip_has_bounded_connection_and_peer_credentials() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let address = LocalAddress(format!("mutsuki-link-{unique}"));
        let budget = TransportBudget {
            idle_timeout: None,
            ..TransportBudget::default()
        };
        let listener =
            LocalListener::bind(&address, EndpointId::from_bytes([2; 16]), budget).unwrap();
        let server = listener.accept(EndpointId::from_bytes([1; 16]));
        let context = ConnectContext::default();
        let client = connect(
            &address,
            EndpointId::from_bytes([1; 16]),
            EndpointId::from_bytes([2; 16]),
            budget,
            &context,
        );
        let (mut server, mut client) = tokio::try_join!(server, client).unwrap();
        assert!(server.peer_credentials().is_some());
        mutsuki_link_transport_testkit::run_session_transport_suite(&mut client, &mut server).await;
        client.try_send_control(b"ping").unwrap();

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
        client.close_write().unwrap();
        assert_eq!(
            client.try_send(b"after-close").unwrap_err().kind,
            TransportErrorKind::Closed
        );
    }
}
