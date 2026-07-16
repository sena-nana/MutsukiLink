use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    FrameBytes,
    NestingDepth,
    Channels,
    PendingFrames,
    ProtocolOffers,
    IdentityProofBytes,
    EventSubscribers,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkError {
    InvalidInput(&'static str),
    InvalidState(&'static str),
    LimitExceeded { kind: LimitKind, limit: usize },
    Backpressure { channel: u32, capacity: usize },
    UnknownChannel(u32),
    ChannelCancelled(u32),
    NamespaceConflict,
    Closed,
}

impl fmt::Display for LinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for LinkError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeErrorKind {
    UnexpectedMessage,
    IncompatibleVersion,
    NoSharedProtocol,
    ProtocolConflict,
    PairingDisabled,
    PeerNotTrusted,
    IdentityRejected,
    LimitExceeded,
    InvalidConfirmation,
}

/// A deliberately sanitized handshake error. Secret material and backend TLS
/// details never enter this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeError {
    pub kind: HandshakeErrorKind,
    pub public_message: &'static str,
}

impl HandshakeError {
    pub(crate) const fn new(kind: HandshakeErrorKind, public_message: &'static str) -> Self {
        Self {
            kind,
            public_message,
        }
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for HandshakeError {}
