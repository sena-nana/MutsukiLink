//! Minimal facade for the reusable `MutsukiLink` connection runtime.
//!
//! The default feature set only re-exports `mutsuki-link-core`; concrete transports and discovery
//! providers remain separate opt-in crates when implemented.

#![forbid(unsafe_code)]

pub use mutsuki_link_core::*;

#[cfg(feature = "discovery")]
pub use mutsuki_link_discovery as discovery;
#[cfg(feature = "local")]
pub use mutsuki_link_local as local;
#[cfg(feature = "pairing")]
pub use mutsuki_link_pairing as pairing;
#[cfg(feature = "quic")]
pub use mutsuki_link_quic as quic;
#[cfg(feature = "runtime")]
pub use mutsuki_link_runtime as runtime;
#[cfg(feature = "tcp")]
pub use mutsuki_link_tcp as tcp;
