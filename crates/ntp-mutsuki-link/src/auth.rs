use mutsuki_link_core::{AuthenticatedSession, PeerId, SessionId as LinkSessionId};
use mutsuki_link_pairing::{LinkPermission, TrustRecord};
use std::fmt;

use crate::BindingError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtpRole {
    Publisher,
    Subscriber,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtpPermission {
    Publish,
    Subscribe,
    Negotiate,
    CalibrationWrite,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NtpPermissions(u8);

impl NtpPermissions {
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn with(self, permission: NtpPermission) -> Self {
        let flag = match permission {
            NtpPermission::Publish => 1 << 0,
            NtpPermission::Subscribe => 1 << 1,
            NtpPermission::Negotiate => 1 << 2,
            NtpPermission::CalibrationWrite => 1 << 3,
        };
        Self(self.0 | flag)
    }

    #[must_use]
    pub const fn contains(self, permission: NtpPermission) -> bool {
        let flag = match permission {
            NtpPermission::Publish => 1 << 0,
            NtpPermission::Subscribe => 1 << 1,
            NtpPermission::Negotiate => 1 << 2,
            NtpPermission::CalibrationWrite => 1 << 3,
        };
        self.0 & flag != 0
    }

    pub fn from_link_permissions<'a>(
        permissions: impl IntoIterator<Item = &'a LinkPermission>,
    ) -> Self {
        let mut resolved = Self::default();
        for permission in permissions {
            match permission {
                LinkPermission::TrackingPublish => {
                    resolved = resolved.with(NtpPermission::Publish);
                }
                LinkPermission::TrackingSubscribe => {
                    resolved = resolved.with(NtpPermission::Subscribe);
                }
                LinkPermission::TrackingNegotiate => {
                    resolved = resolved.with(NtpPermission::Negotiate);
                }
                LinkPermission::TrackingCalibrationWrite => {
                    resolved = resolved.with(NtpPermission::CalibrationWrite);
                }
                LinkPermission::Connect
                | LinkPermission::OpenNamespace(_)
                | LinkPermission::Datagram => {}
            }
        }
        resolved
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NtpPermissionGrant {
    pub permissions: NtpPermissions,
    /// Monotonic owner-defined trust revision. A permission or trust change must
    /// create a new revision and reauthorize the adapter.
    pub revision: u64,
}

/// Opaque proof that a Link session passed transport authentication and the
/// application granted the minimum NTP role permissions.
#[derive(Eq, PartialEq)]
pub struct NtpAuthorization {
    peer_id: PeerId,
    link_session_id: LinkSessionId,
    key_epoch: u64,
    grant_revision: u64,
    role: NtpRole,
}

impl fmt::Debug for NtpAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "NtpAuthorization {{ peer_id: {}, link_session_id: {}, key_epoch: {}, grant_revision: {}, role: {:?} }}",
            self.peer_id, self.link_session_id, self.key_epoch, self.grant_revision, self.role
        )
    }
}

impl NtpAuthorization {
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    #[must_use]
    pub const fn link_session_id(&self) -> LinkSessionId {
        self.link_session_id
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub const fn grant_revision(&self) -> u64 {
        self.grant_revision
    }

    #[must_use]
    pub const fn role(&self) -> NtpRole {
        self.role
    }
}

pub fn authorize_ntp_session(
    session: AuthenticatedSession<'_>,
    role: NtpRole,
    grant: NtpPermissionGrant,
) -> Result<NtpAuthorization, BindingError> {
    let allowed = grant.permissions.contains(NtpPermission::Negotiate)
        && match role {
            NtpRole::Publisher => grant.permissions.contains(NtpPermission::Publish),
            NtpRole::Subscriber => grant.permissions.contains(NtpPermission::Subscribe),
        };
    if !allowed {
        return Err(BindingError::Unauthorized);
    }
    Ok(NtpAuthorization {
        peer_id: session.info().peer_id,
        link_session_id: session.info().session_id,
        key_epoch: session.security().identity.key_epoch,
        grant_revision: grant.revision,
        role,
    })
}

pub fn authorize_trusted_ntp_session(
    session: AuthenticatedSession<'_>,
    role: NtpRole,
    record: &TrustRecord,
    grant_revision: u64,
) -> Result<NtpAuthorization, BindingError> {
    if !record.is_active() {
        return Err(BindingError::PeerRevoked);
    }
    if record.peer_id != session.info().peer_id
        || record.public_key_fingerprint() != session.security().identity.public_key_fingerprint
    {
        return Err(BindingError::Unauthorized);
    }
    authorize_ntp_session(
        session,
        role,
        NtpPermissionGrant {
            permissions: NtpPermissions::from_link_permissions(&record.permissions),
            revision: grant_revision,
        },
    )
}
