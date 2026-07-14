//! Minimal facade for the reusable `MutsukiLink` connection runtime.
//!
//! The default feature set only re-exports `mutsuki-link-core`; concrete transports and discovery
//! providers remain separate opt-in crates when implemented.

#![forbid(unsafe_code)]

pub use mutsuki_link_core::*;
