use crate::config::{DuplicatePeerPolicy, LinkEndpointConfig};
use crate::error::PoolError;
use crate::events::PoolEvent;
use crate::peer_session::{now_unix_ms, PeerSessionHandle};
use mutsuki_link_core::{
    CloseReason, ConnectContext, Connection, ConnectionActivityProfile, ConnectionId, EndpointId,
    PeerId, ReconnectAction,
};
use mutsuki_link_quic::{QuicConnection, QuicConnector, QuicListener};
use quinn::{ClientConfig, ServerConfig};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Unauthenticated inbound QUIC connection awaiting host trust admission.
///
/// Dropping without [`PeerSessionPool::admit_inbound`] aborts the connection and releases the
/// listener connection budget permit.
#[derive(Debug)]
pub struct InboundConnect {
    connection_id: ConnectionId,
    remote_addr: SocketAddr,
    provisional_remote_endpoint: EndpointId,
    connection: Option<QuicConnection>,
}

impl InboundConnect {
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub const fn provisional_remote_endpoint(&self) -> EndpointId {
        self.provisional_remote_endpoint
    }

    fn take_connection(&mut self) -> Option<QuicConnection> {
        self.connection.take()
    }
}

impl Drop for InboundConnect {
    fn drop(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            connection.abort();
        }
    }
}

/// Multi-peer authenticated QUIC session pool.
///
/// The pool does not spawn an accept loop, does not auto-trust peers, and never interprets
/// application protocol payloads.
#[derive(Debug)]
pub struct PeerSessionPool {
    config: LinkEndpointConfig,
    listener: QuicListener,
    connector: QuicConnector,
    sessions: BTreeMap<PeerId, PeerSessionHandle>,
    inbound_seq: AtomicU64,
}

impl PeerSessionPool {
    /// Bind a listener and connector. Does not accept or dial until called explicitly.
    pub fn bind(
        server_config: ServerConfig,
        client_config: ClientConfig,
        config: LinkEndpointConfig,
    ) -> Result<Self, PoolError> {
        config.validate().map_err(PoolError::InvalidConfig)?;
        let listener = QuicListener::bind(
            config.bind,
            config.local_endpoint,
            server_config,
            config.quic,
        )?;
        let connector = QuicConnector::new(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            client_config,
            config.quic,
        )?;
        Ok(Self {
            config,
            listener,
            connector,
            sessions: BTreeMap::new(),
            inbound_seq: AtomicU64::new(1),
        })
    }

    pub fn config(&self) -> &LinkEndpointConfig {
        &self.config
    }

    pub fn local_addr(&self) -> Result<SocketAddr, PoolError> {
        Ok(self.listener.local_addr()?)
    }

    pub fn listener_active_connections(&self) -> usize {
        self.listener.active_connections()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn active_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.sessions.keys()
    }

    pub fn get(&self, peer: &PeerId) -> Option<&PeerSessionHandle> {
        self.sessions.get(peer)
    }

    pub fn get_mut(&mut self, peer: &PeerId) -> Option<&mut PeerSessionHandle> {
        self.sessions.get_mut(peer)
    }

    /// Accept one inbound QUIC connection. Host must authenticate before [`Self::admit_inbound`].
    pub async fn accept_inbound(
        &self,
        provisional_remote_endpoint: EndpointId,
    ) -> Result<InboundConnect, PoolError> {
        let connection = self.listener.accept(provisional_remote_endpoint).await?;
        let remote_addr = connection.remote_address();
        let connection_id = next_connection_id(&self.inbound_seq);
        Ok(InboundConnect {
            connection_id,
            remote_addr,
            provisional_remote_endpoint,
            connection: Some(connection),
        })
    }

    /// Admit a host-authenticated inbound connection into the peer session map.
    pub fn admit_inbound(
        &mut self,
        mut inbound: InboundConnect,
        peer_id: PeerId,
        remote_endpoint: EndpointId,
    ) -> Result<&mut PeerSessionHandle, PoolError> {
        let connection = inbound
            .take_connection()
            .ok_or(PoolError::InvalidConfig("inbound connection already consumed"))?;
        let remote_addr = inbound.remote_addr();
        self.insert_session(peer_id, remote_endpoint, remote_addr, connection)
    }

    /// Dial a trusted peer and insert the authenticated session.
    pub async fn connect_outbound(
        &mut self,
        peer_id: PeerId,
        address: SocketAddr,
        remote_endpoint: EndpointId,
        server_name: Option<&str>,
        context: Option<&ConnectContext>,
    ) -> Result<&mut PeerSessionHandle, PoolError> {
        self.ensure_capacity_for(&peer_id)?;
        let default_context;
        let context = if let Some(context) = context {
            context
        } else {
            default_context = ConnectContext {
                deadline: Some(Instant::now() + self.config.connect_timeout),
                ..ConnectContext::default()
            };
            &default_context
        };
        let name = server_name.unwrap_or(self.config.server_name.as_str());
        let connection = self
            .connector
            .connect(
                address,
                name,
                self.config.local_endpoint,
                remote_endpoint,
                context,
            )
            .await?;
        let remote_addr = connection.remote_address();
        self.insert_session(peer_id, remote_endpoint, remote_addr, connection)
    }

    /// Remove and abort a peer session, dropping the connection so inbound permits are released.
    pub fn remove(&mut self, peer: &PeerId) -> bool {
        let Some(mut handle) = self.sessions.remove(peer) else {
            return false;
        };
        handle.disconnect();
        drop(handle);
        true
    }

    /// Tick heartbeat (and surface reconnect controller state already advanced by the host).
    pub fn maintenance_tick(
        &mut self,
        now_unix_ms: u64,
        profile: ConnectionActivityProfile,
    ) -> Vec<PoolEvent> {
        let peers: Vec<PeerId> = self.sessions.keys().copied().collect();
        let mut events = Vec::new();
        for peer_id in peers {
            let Some(handle) = self.sessions.get_mut(&peer_id) else {
                continue;
            };
            let action = handle.tick_heartbeat(now_unix_ms, profile);
            if action != mutsuki_link_core::HeartbeatAction::None {
                events.push(PoolEvent::Heartbeat {
                    peer_id,
                    action,
                    profile,
                });
            }
        }
        events
    }

    /// Record a transport failure against one peer and emit reconnect scheduling events.
    pub fn note_transport_failure(
        &mut self,
        peer_id: &PeerId,
        failure: mutsuki_link_core::ReconnectFailure,
        now_unix_ms: u64,
        jitter_sample: u16,
    ) -> Result<Vec<PoolEvent>, PoolError> {
        let handle = self
            .sessions
            .get_mut(peer_id)
            .ok_or(PoolError::UnknownPeer(*peer_id))?;
        let action = handle.after_transport_failure(failure, now_unix_ms, jitter_sample);
        Ok(match action {
            ReconnectAction::AttemptAt { unix_ms, attempt } => {
                vec![PoolEvent::ReconnectScheduled {
                    peer_id: *peer_id,
                    unix_ms,
                    attempt,
                }]
            }
            other => vec![PoolEvent::ReconnectStopped {
                peer_id: *peer_id,
                action: other,
            }],
        })
    }

    fn ensure_capacity_for(&self, peer_id: &PeerId) -> Result<(), PoolError> {
        if self.sessions.contains_key(peer_id) {
            return match self.config.duplicate_peer {
                DuplicatePeerPolicy::ReplaceExisting => Ok(()),
                DuplicatePeerPolicy::Reject => Err(PoolError::DuplicatePeer(*peer_id)),
            };
        }
        if self.sessions.len() >= self.config.max_peers {
            return Err(PoolError::PeerLimit);
        }
        Ok(())
    }

    fn insert_session(
        &mut self,
        peer_id: PeerId,
        remote_endpoint: EndpointId,
        remote_addr: SocketAddr,
        connection: QuicConnection,
    ) -> Result<&mut PeerSessionHandle, PoolError> {
        self.ensure_capacity_for(&peer_id)?;
        if self.sessions.contains_key(&peer_id) {
            match self.config.duplicate_peer {
                DuplicatePeerPolicy::ReplaceExisting => {
                    if let Some(mut previous) = self.sessions.remove(&peer_id) {
                        previous.disconnect();
                    }
                }
                DuplicatePeerPolicy::Reject => {
                    return Err(PoolError::DuplicatePeer(peer_id));
                }
            }
        } else if self.sessions.len() >= self.config.max_peers {
            return Err(PoolError::PeerLimit);
        }

        let handle = PeerSessionHandle::new(
            peer_id,
            remote_endpoint,
            remote_addr,
            connection,
            self.config.heartbeat,
            self.config.reconnect,
        )?;
        self.sessions.insert(peer_id, handle);
        Ok(self
            .sessions
            .get_mut(&peer_id)
            .expect("session just inserted"))
    }
}

fn next_connection_id(seq: &AtomicU64) -> ConnectionId {
    let value = seq.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    let millis = now_unix_ms();
    bytes[8..].copy_from_slice(&millis.to_be_bytes());
    ConnectionId::from_bytes(bytes)
}

/// Helper event describing an inbound that is awaiting authentication.
pub fn inbound_awaiting_auth_event(inbound: &InboundConnect) -> PoolEvent {
    PoolEvent::InboundAwaitingAuth {
        connection_id: inbound.connection_id(),
        remote_addr: inbound.remote_addr(),
    }
}

/// Emit a disconnect event helper for hosts that remove sessions.
pub fn peer_disconnected_event(peer_id: PeerId, reason: CloseReason) -> PoolEvent {
    PoolEvent::PeerDisconnected { peer_id, reason }
}
