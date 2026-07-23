use crate::PoolError;
use mutsuki_link_core::{
    CancellationToken, Connection, ConnectionActivityProfile, EndpointId, HeartbeatAction,
    HeartbeatController, HeartbeatPolicy, PeerId, ReconnectAction, ReconnectController,
    ReconnectFailure, ReconnectPolicy,
};
use mutsuki_link_quic::QuicConnection;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Authenticated peer session handle owned by [`crate::PeerSessionPool`].
///
/// Controllers are per-peer and independent. The pool never interprets payload bytes.
#[derive(Debug)]
pub struct PeerSessionHandle {
    peer_id: PeerId,
    remote_endpoint: EndpointId,
    remote_addr: SocketAddr,
    connection: QuicConnection,
    heartbeat: HeartbeatController,
    reconnect: ReconnectController,
}

impl PeerSessionHandle {
    pub(crate) fn new(
        peer_id: PeerId,
        remote_endpoint: EndpointId,
        remote_addr: SocketAddr,
        connection: QuicConnection,
        heartbeat: HeartbeatPolicy,
        reconnect: ReconnectPolicy,
    ) -> Result<Self, PoolError> {
        let now = now_unix_ms();
        let heartbeat =
            HeartbeatController::new(heartbeat, now).map_err(PoolError::InvalidConfig)?;
        let reconnect = ReconnectController::new(reconnect, CancellationToken::default())
            .map_err(PoolError::InvalidConfig)?;
        Ok(Self {
            peer_id,
            remote_endpoint,
            remote_addr,
            connection,
            heartbeat,
            reconnect,
        })
    }

    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub const fn remote_endpoint(&self) -> EndpointId {
        self.remote_endpoint
    }

    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn connection(&self) -> &QuicConnection {
        &self.connection
    }

    pub fn connection_mut(&mut self) -> &mut QuicConnection {
        &mut self.connection
    }

    pub fn tick_heartbeat(
        &mut self,
        now_unix_ms: u64,
        profile: ConnectionActivityProfile,
    ) -> HeartbeatAction {
        self.heartbeat.tick(now_unix_ms, profile)
    }

    pub fn observe_transport_ack(&mut self, now_unix_ms: u64) {
        self.heartbeat.observe_transport_ack(now_unix_ms);
    }

    pub fn observe_probe_ack(&mut self, now_unix_ms: u64) {
        self.heartbeat.observe_probe_ack(now_unix_ms);
    }

    pub fn after_transport_failure(
        &mut self,
        failure: ReconnectFailure,
        now_unix_ms: u64,
        jitter_sample: u16,
    ) -> ReconnectAction {
        self.reconnect
            .after_failure(failure, now_unix_ms, jitter_sample)
    }

    pub fn reset_reconnect(&mut self) {
        self.reconnect.reset();
    }

    pub fn disconnect(&mut self) {
        self.connection.abort();
    }
}

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}
