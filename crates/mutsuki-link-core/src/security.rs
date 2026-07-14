use crate::{EndpointAddress, PeerId, ProtocolVersion, SecurityLevel, SessionInfo, TransportKind};
use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityStatus {
    Active { valid_until_unix_ms: u64 },
    Revoked,
    Rotated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityEvidence {
    pub peer_id: PeerId,
    pub public_key_fingerprint: [u8; 32],
    pub key_epoch: u64,
    pub status: IdentityStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionKeyBinding {
    /// A backend-owned identifier or exporter digest, never raw session key material.
    pub key_id: [u8; 32],
    pub forward_secure: bool,
    pub handshake_transcript_hash: [u8; 32],
    pub local_endpoint: EndpointAddress,
    pub remote_endpoint: EndpointAddress,
    pub link_version: ProtocolVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportSecurityEvidence {
    pub transport: TransportKind,
    pub security_level: SecurityLevel,
    pub mutually_authenticated: bool,
    pub local_peer_credential_verified: bool,
    /// Must be true only for an explicitly configured development connection.
    pub development_plaintext: bool,
    pub identity: IdentityEvidence,
    pub session_key: Option<SessionKeyBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityExpectation {
    pub peer_id: PeerId,
    pub public_key_fingerprint: [u8; 32],
    pub minimum_key_epoch: u64,
    pub handshake_transcript_hash: [u8; 32],
    pub local_endpoint: EndpointAddress,
    pub remote_endpoint: EndpointAddress,
    pub link_version: ProtocolVersion,
    pub now_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteSecurityPolicy {
    AuthenticatedEncrypted,
    AllowExplicitDevelopmentPlaintext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForwardSecrecyPolicy {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalPeerCredentialPolicy {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityPolicy {
    pub remote: RemoteSecurityPolicy,
    pub forward_secrecy: ForwardSecrecyPolicy,
    /// Local IPC may use OS peer credentials in addition to long-term identity proof.
    pub local_peer_credential: LocalPeerCredentialPolicy,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            remote: RemoteSecurityPolicy::AuthenticatedEncrypted,
            forward_secrecy: ForwardSecrecyPolicy::Required,
            local_peer_credential: LocalPeerCredentialPolicy::Required,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityErrorKind {
    PlaintextForbidden,
    EncryptionRequired,
    MutualAuthenticationRequired,
    ForwardSecrecyRequired,
    LocalPeerCredentialRequired,
    PeerMismatch,
    KeyMismatch,
    KeyRotated,
    IdentityRevoked,
    IdentityExpired,
    TranscriptMismatch,
    EndpointMismatch,
    ProtocolMismatch,
    MissingSessionKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityError {
    pub kind: SecurityErrorKind,
    pub public_message: &'static str,
}

impl SecurityError {
    const fn new(kind: SecurityErrorKind, public_message: &'static str) -> Self {
        Self {
            kind,
            public_message,
        }
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message)
    }
}

impl std::error::Error for SecurityError {}

/// A type-level view available only after transport and long-term identity
/// evidence has passed the configured security policy.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedSession<'a> {
    session: &'a SessionInfo,
    evidence: &'a TransportSecurityEvidence,
}

impl<'a> AuthenticatedSession<'a> {
    pub fn info(&self) -> &'a SessionInfo {
        self.session
    }

    pub fn security(&self) -> &'a TransportSecurityEvidence {
        self.evidence
    }
}

pub fn authenticate_session<'a>(
    session: &'a SessionInfo,
    evidence: &'a TransportSecurityEvidence,
    expected: &SecurityExpectation,
    policy: SecurityPolicy,
) -> Result<AuthenticatedSession<'a>, SecurityError> {
    if session.peer_id != expected.peer_id {
        return Err(error(SecurityErrorKind::PeerMismatch));
    }
    validate_transport_security(evidence, expected, policy)?;
    Ok(AuthenticatedSession { session, evidence })
}

/// Validates backend evidence without depending on a particular TLS, QUIC, keychain,
/// or local-credential implementation. The backend must create the evidence from
/// authenticated exporter data rather than self-asserted connection metadata.
pub fn validate_transport_security(
    evidence: &TransportSecurityEvidence,
    expected: &SecurityExpectation,
    policy: SecurityPolicy,
) -> Result<(), SecurityError> {
    if evidence.identity.peer_id != expected.peer_id {
        return Err(error(SecurityErrorKind::PeerMismatch));
    }
    if evidence.identity.public_key_fingerprint != expected.public_key_fingerprint {
        return Err(error(SecurityErrorKind::KeyMismatch));
    }
    if evidence.identity.key_epoch < expected.minimum_key_epoch {
        return Err(error(SecurityErrorKind::KeyRotated));
    }
    match evidence.identity.status {
        IdentityStatus::Revoked => return Err(error(SecurityErrorKind::IdentityRevoked)),
        IdentityStatus::Rotated => return Err(error(SecurityErrorKind::KeyRotated)),
        IdentityStatus::Active {
            valid_until_unix_ms,
        } if expected.now_unix_ms >= valid_until_unix_ms => {
            return Err(error(SecurityErrorKind::IdentityExpired));
        }
        IdentityStatus::Active { .. } => {}
    }
    if !evidence.mutually_authenticated {
        return Err(error(SecurityErrorKind::MutualAuthenticationRequired));
    }

    if evidence.transport == TransportKind::Local {
        if policy.local_peer_credential == LocalPeerCredentialPolicy::Required
            && !evidence.local_peer_credential_verified
        {
            return Err(error(SecurityErrorKind::LocalPeerCredentialRequired));
        }
        return validate_binding(evidence, expected, false, requires_forward_secrecy(policy));
    }

    if evidence.security_level == SecurityLevel::Plaintext {
        if policy.remote != RemoteSecurityPolicy::AllowExplicitDevelopmentPlaintext
            || !evidence.development_plaintext
        {
            return Err(error(SecurityErrorKind::PlaintextForbidden));
        }
        return validate_binding(evidence, expected, false, false);
    }
    if policy.remote == RemoteSecurityPolicy::AuthenticatedEncrypted
        && evidence.security_level != SecurityLevel::AuthenticatedEncrypted
    {
        return Err(error(SecurityErrorKind::EncryptionRequired));
    }
    validate_binding(evidence, expected, true, requires_forward_secrecy(policy))
}

const fn requires_forward_secrecy(policy: SecurityPolicy) -> bool {
    matches!(policy.forward_secrecy, ForwardSecrecyPolicy::Required)
}

fn validate_binding(
    evidence: &TransportSecurityEvidence,
    expected: &SecurityExpectation,
    remote_requires_key: bool,
    require_forward_secrecy: bool,
) -> Result<(), SecurityError> {
    let Some(binding) = &evidence.session_key else {
        if remote_requires_key || require_forward_secrecy {
            return Err(error(SecurityErrorKind::MissingSessionKey));
        }
        return Ok(());
    };
    if require_forward_secrecy && !binding.forward_secure {
        return Err(error(SecurityErrorKind::ForwardSecrecyRequired));
    }
    if binding.handshake_transcript_hash != expected.handshake_transcript_hash {
        return Err(error(SecurityErrorKind::TranscriptMismatch));
    }
    if binding.local_endpoint != expected.local_endpoint
        || binding.remote_endpoint != expected.remote_endpoint
    {
        return Err(error(SecurityErrorKind::EndpointMismatch));
    }
    if binding.link_version != expected.link_version {
        return Err(error(SecurityErrorKind::ProtocolMismatch));
    }
    Ok(())
}

const fn error(kind: SecurityErrorKind) -> SecurityError {
    let public_message = match kind {
        SecurityErrorKind::PlaintextForbidden => "plaintext transport is not permitted",
        SecurityErrorKind::EncryptionRequired => "encrypted transport is required",
        SecurityErrorKind::MutualAuthenticationRequired => "mutual authentication is required",
        SecurityErrorKind::ForwardSecrecyRequired => "forward-secure session keys are required",
        SecurityErrorKind::LocalPeerCredentialRequired => "local peer credential is required",
        SecurityErrorKind::PeerMismatch => "authenticated peer does not match",
        SecurityErrorKind::KeyMismatch => "authenticated identity key does not match",
        SecurityErrorKind::KeyRotated => "authenticated identity key has been rotated",
        SecurityErrorKind::IdentityRevoked => "authenticated identity has been revoked",
        SecurityErrorKind::IdentityExpired => "authenticated identity has expired",
        SecurityErrorKind::TranscriptMismatch => "session key is not bound to this handshake",
        SecurityErrorKind::EndpointMismatch => "session key is not bound to these endpoints",
        SecurityErrorKind::ProtocolMismatch => "session key is not bound to this protocol version",
        SecurityErrorKind::MissingSessionKey => "session key binding is missing",
    };
    SecurityError::new(kind, public_message)
}
