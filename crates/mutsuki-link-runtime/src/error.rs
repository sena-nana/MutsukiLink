use mutsuki_link_core::{PeerId, TransportError, TransportErrorKind};
use std::fmt;

/// Errors raised by [`crate::PeerSessionPool`] orchestration (not payload codecs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolError {
    InvalidConfig(&'static str),
    Transport(TransportError),
    PeerLimit,
    DuplicatePeer(PeerId),
    UnknownPeer(PeerId),
}

impl PoolError {
    pub fn kind(&self) -> Option<TransportErrorKind> {
        match self {
            Self::Transport(error) => Some(error.kind),
            Self::PeerLimit => Some(TransportErrorKind::WouldBlock),
            _ => None,
        }
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid pool config: {reason}"),
            Self::Transport(error) => write!(formatter, "transport error: {error}"),
            Self::PeerLimit => formatter.write_str("authenticated peer session limit reached"),
            Self::DuplicatePeer(peer) => write!(formatter, "duplicate peer session: {peer}"),
            Self::UnknownPeer(peer) => write!(formatter, "unknown peer session: {peer}"),
        }
    }
}

impl std::error::Error for PoolError {}

impl From<TransportError> for PoolError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}
