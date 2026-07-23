use mutsuki_link_core::{EndpointId, HeartbeatPolicy, ReconnectPolicy};
use mutsuki_link_quic::QuicOptions;
use std::net::SocketAddr;
use std::time::Duration;

/// How the pool treats a second authenticated session for the same [`PeerId`](mutsuki_link_core::PeerId).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DuplicatePeerPolicy {
    /// Abort and replace the existing session.
    #[default]
    ReplaceExisting,
    /// Reject the new session and keep the existing one.
    Reject,
}

/// Endpoint-level pool configuration. Construction never starts an accept loop.
#[derive(Clone, Debug)]
pub struct LinkEndpointConfig {
    pub local_endpoint: EndpointId,
    pub bind: SocketAddr,
    pub quic: QuicOptions,
    pub heartbeat: HeartbeatPolicy,
    pub reconnect: ReconnectPolicy,
    /// Hard cap on authenticated peer sessions in the pool.
    pub max_peers: usize,
    pub duplicate_peer: DuplicatePeerPolicy,
    /// Default SNI / TLS server name used by outbound connect when not overridden.
    pub server_name: String,
    pub connect_timeout: Duration,
}

impl Default for LinkEndpointConfig {
    fn default() -> Self {
        Self {
            local_endpoint: EndpointId::from_bytes([1; 16]),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            quic: QuicOptions {
                enable_datagrams: false,
                ..QuicOptions::default()
            },
            heartbeat: HeartbeatPolicy::default(),
            reconnect: ReconnectPolicy::Disabled,
            max_peers: 8,
            duplicate_peer: DuplicatePeerPolicy::ReplaceExisting,
            server_name: "localhost".to_owned(),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

impl LinkEndpointConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_peers == 0 {
            return Err("max_peers must be positive");
        }
        if !self.heartbeat.is_valid() {
            return Err("heartbeat policy is invalid");
        }
        if self.server_name.is_empty() {
            return Err("server_name must not be empty");
        }
        if self.connect_timeout.is_zero() {
            return Err("connect_timeout must be positive");
        }
        let reconnect_valid = match self.reconnect {
            ReconnectPolicy::Disabled | ReconnectPolicy::ApplicationControlled => true,
            ReconnectPolicy::Immediate(limit) => limit.is_valid(),
            ReconnectPolicy::ExponentialBackoff(config) => config.is_valid(),
        };
        if !reconnect_valid {
            return Err("reconnect policy is invalid");
        }
        Ok(())
    }
}
