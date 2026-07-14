//! Runtime-neutral connection contracts for `MutsukiLink`.
//!
//! This crate intentionally has no async runtime, transport, discovery, TLS, QUIC, Mutsuki Core,
//! `ServiceHost`, `DistributedHost`, or product dependency. Concrete connection contracts are added
//! in later phases without changing this dependency direction.

#![forbid(unsafe_code)]

/// Current `MutsukiLink` protocol family version.
pub const LINK_PROTOCOL_VERSION: u16 = 1;

/// Oldest protocol family version accepted by this release.
pub const MIN_COMPATIBLE_LINK_PROTOCOL_VERSION: u16 = 1;

/// Reports whether a peer's protocol family version is in this release's compatibility window.
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
