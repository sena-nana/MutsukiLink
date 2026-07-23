//! Optional multi-peer QUIC session pool for `MutsukiLink`.
//!
//! Construction never binds sockets until [`PeerSessionPool::bind`]. The pool never starts an
//! accept loop, never auto-trusts peers, and never interprets application protocol payloads.
//! Hosts authenticate inbound connections before [`PeerSessionPool::admit_inbound`].

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::module_name_repetitions
)]

mod config;
mod error;
mod events;
mod peer_session;
mod pool;

pub use config::{DuplicatePeerPolicy, LinkEndpointConfig};
pub use error::PoolError;
pub use events::PoolEvent;
pub use peer_session::PeerSessionHandle;
pub use pool::{
    InboundConnect, PeerSessionPool, inbound_awaiting_auth_event, peer_disconnected_event,
};
