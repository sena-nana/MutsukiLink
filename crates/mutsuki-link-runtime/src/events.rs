use mutsuki_link_core::{
    CloseReason, ConnectionActivityProfile, ConnectionId, HeartbeatAction, PeerId, ReconnectAction,
};
use std::net::SocketAddr;

/// Lifecycle and maintenance signals emitted by the pool. Never carries application payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolEvent {
    /// An inbound QUIC connection is ready for host-side trust / identity checks.
    InboundAwaitingAuth {
        connection_id: ConnectionId,
        remote_addr: SocketAddr,
    },
    PeerConnected(PeerId),
    PeerDisconnected {
        peer_id: PeerId,
        reason: CloseReason,
    },
    /// Host should schedule a later [`crate::PeerSessionPool::connect_outbound`] for this peer.
    ReconnectScheduled {
        peer_id: PeerId,
        unix_ms: u64,
        attempt: u32,
    },
    Heartbeat {
        peer_id: PeerId,
        action: HeartbeatAction,
        profile: ConnectionActivityProfile,
    },
    BudgetExceeded,
    ReconnectStopped {
        peer_id: PeerId,
        action: ReconnectAction,
    },
}
