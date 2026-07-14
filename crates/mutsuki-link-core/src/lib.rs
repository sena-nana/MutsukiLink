//! Runtime-neutral connection contracts for `MutsukiLink`.
//!
//! The core owns identities, handshake and session state machines, bounded
//! multiplexing, and transport-neutral frames. It intentionally does not own an
//! async runtime, sockets, discovery, cryptography, or product protocols.

#![forbid(unsafe_code)]
// Public fallible operations expose self-describing error enums; repeating every
// variant in rustdoc would make the transport/state-machine API harder to scan.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]

mod error;
mod handshake;
mod identity;
mod mux;
mod session;
mod transport;

pub use error::{HandshakeError, HandshakeErrorKind, LimitKind, LinkError};
pub use handshake::{
    AuthPath, HandshakeConfig, HandshakeFrame, HandshakeMachine, HandshakeOutput, HandshakePolicy,
    HandshakeRole, HandshakeState, IdentityProof, NegotiatedSession, ProofDecision, ProtocolOffer,
    ProtocolSelection, VerificationRequest,
};
pub use identity::{
    ConnectionId, EndpointId, Identity, PeerId, ProtocolVersion, SessionId, VersionRange,
};
pub use mux::{
    CONTROL_CHANNEL_ID, ChannelConfig, ChannelId, ChannelKey, ChannelMode, Envelope, EnvelopeFlags,
    Multiplexer, MultiplexerLimits, OutboundFrame,
};
pub use session::{
    CloseReason, ConnectionQuality, EventSubscriberId, Session, SessionEvent, SessionEventBus,
    SessionInfo, SessionState,
};
pub use transport::{
    CancellationToken, ConnectContext, Connection, ConnectionMetadata, EndpointAddress, Listener,
    MemoryConnection, MemoryTransportConfig, OperationContext, Transport, TransportError,
    TransportErrorKind, memory_transport_pair,
};

/// Current wire protocol major version.
pub const LINK_PROTOCOL_VERSION: u16 = 1;

/// Oldest wire protocol major version accepted by this release.
pub const MIN_COMPATIBLE_LINK_PROTOCOL_VERSION: u16 = 1;

/// Reports whether a peer's major version is in this release's compatibility window.
#[must_use]
pub const fn protocol_version_is_compatible(version: u16) -> bool {
    version >= MIN_COMPATIBLE_LINK_PROTOCOL_VERSION && version <= LINK_PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_window_is_explicit() {
        assert!(protocol_version_is_compatible(1));
        assert!(!protocol_version_is_compatible(0));
        assert!(!protocol_version_is_compatible(2));
    }
}
