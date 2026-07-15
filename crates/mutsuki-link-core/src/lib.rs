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

mod budget;
mod error;
mod handshake;
mod identity;
mod liveness;
mod mux;
mod protocol;
mod realtime;
mod reconnect;
mod resume;
mod security;
mod selection;
mod session;
mod transport;

pub use budget::{ConnectionBudget, MaintenanceBudget, MaintenanceMode};
pub use error::{HandshakeError, HandshakeErrorKind, LimitKind, LinkError};
pub use handshake::{
    AuthPath, HandshakeConfig, HandshakeFrame, HandshakeMachine, HandshakeOutput, HandshakePolicy,
    HandshakeRole, HandshakeState, IdentityProof, NegotiatedSession, ProofDecision, ProtocolOffer,
    ProtocolSelection, VerificationRequest,
};
pub use identity::{
    ConnectionId, EndpointId, Identity, PeerId, ProtocolVersion, SessionId, VersionRange,
};
pub use liveness::{
    ConnectionActivityProfile, ConnectionQuality, HeartbeatAction, HeartbeatController,
    HeartbeatPolicy, LivenessState, QualityAccumulator, QualityChangeDetector,
    QualityChangeThreshold, QualityObservation,
};
pub use mux::{
    CONTROL_CHANNEL_ID, ChannelConfig, ChannelId, ChannelKey, ChannelMode, Envelope, EnvelopeFlags,
    Multiplexer, MultiplexerLimits, MultiplexerStorageSnapshot, OutboundFrame, QueueAdmission,
};
pub use protocol::{
    ActiveProtocolSet, ChannelOpenRequest, FrozenProtocolRegistry, ProtocolChannel,
    ProtocolDescriptor, ProtocolId, ProtocolRegistry, ProtocolRegistryError,
    ProtocolRegistryErrorKind, ProtocolRegistryLimits, ValidatedChannel,
};
pub use realtime::{
    QueuedRealtimeDatagram, REALTIME_DATAGRAM_HEADER_LEN, RealtimeDatagram, RealtimeEvent,
    RealtimeFlowId, RealtimeFlowTelemetry, RealtimePriority, RealtimeQueueConfig,
    RealtimeSendQueue, RealtimeTelemetry, ReceivedRealtimeDatagram, SendOutcome,
    decode_realtime_datagram, encode_realtime_datagram, realtime_flow_from_wire,
};
pub use reconnect::{
    ExponentialBackoff, ReconnectAction, ReconnectController, ReconnectFailure, ReconnectPolicy,
    ReconnectStopReason, RetryLimit,
};
pub use resume::{
    ChannelCursor, NewSessionReason, ReplayPlan, RequestReplay, ResumeCoordinator, ResumeError,
    ResumeErrorKind, ResumeLimits, ResumeOffer, ResumeTokenVerifier, SessionContinuity,
};
pub use security::{
    AuthenticatedSession, ForwardSecrecyPolicy, IdentityEvidence, IdentityStatus,
    LocalPeerCredentialPolicy, RemoteSecurityPolicy, SecurityError, SecurityErrorKind,
    SecurityExpectation, SecurityPolicy, SessionKeyBinding, TransportSecurityEvidence,
    authenticate_session, validate_transport_security,
};
pub use selection::{
    AttemptFailure, FallbackPlan, FallbackPolicy, SecurityLevel, SelectionError, TransportAttempt,
    TransportCandidate, TransportKind, TransportSelection,
};
pub use session::{
    CloseReason, EventSubscriberId, Session, SessionEvent, SessionEventBus, SessionInfo,
    SessionState,
};
pub use transport::{
    CancellationToken, ConnectContext, Connection, ConnectionMetadata, ControlStream,
    EndpointAddress, Listener, MemoryConnection, MemoryTransportConfig, OperationContext,
    Transport, TransportBudget, TransportError, TransportErrorKind, memory_transport_pair,
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
