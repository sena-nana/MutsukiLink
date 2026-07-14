//! Headless pairing commands/events and persistent Link-level trust records.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod ceremony;
mod file_store;
#[cfg(feature = "system-keyring")]
mod keyring_store;
mod rate_limit;
mod trust;

pub use ceremony::{
    LongTermIdentity, PairingConfirmation, PairingCrypto, PairingError, PairingErrorKind,
    PairingEvent, PairingId, PairingMethod, PairingOffer, PairingPresentation, PairingResponse,
    PairingRole, PairingSession, PairingState, PairingTermination, PairingTerminationReason,
    ReplayGuard,
};
pub use file_store::FileTrustStore;
#[cfg(feature = "system-keyring")]
pub use keyring_store::SystemKeyringTrustStore;
pub use rate_limit::{PairingAttemptLimiter, PairingRateLimit};
pub use trust::{
    KeyState, LinkPermission, TrustRecord, TrustStore, TrustStoreError, TrustStoreErrorKind,
    authorize_trusted_reconnect,
};
