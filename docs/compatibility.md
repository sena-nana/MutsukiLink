# Compatibility policy

## Rust and platforms

- MSRV: Rust 1.85 (first stable Rust release with Edition 2024 support).
- Tier 1 desktop targets: Windows x86_64, macOS arm64/x86_64, Linux x86_64.
- Mobile compile targets enforced in CI for the runtime-neutral core, pairing core, and pairing-only
  facade: iOS arm64 (`aarch64-apple-ios`) and Android arm64 (`aarch64-linux-android`). Mobile builds
  intentionally exclude the desktop system-keyring backend.
- A platform-specific transport is available only on platforms where its crate documents support;
  the runtime-neutral core remains portable.

Desktop CI runs the complete workspace on Windows, macOS, and Linux. The local transport test uses
the platform implementation selected by `interprocess`: Unix-domain sockets on macOS/Linux and a
Windows named pipe on Windows. TCP and QUIC loopback tests cover IPv4 and IPv6. QUIC additionally
tests endpoint rebinding for address changes. LAN routing, Wi-Fi changes, sleep/wake, and actual
mobile background/foreground transitions remain hardware/OS acceptance items in the release
checklist; the equivalent bounded state transitions are deterministic core tests.

## Wire protocol

`LINK_PROTOCOL_VERSION` is the current wire family version and
`MIN_COMPATIBLE_LINK_PROTOCOL_VERSION` is the oldest accepted version. Handshake negotiation must
select an intersection or return a structured incompatibility error. Unknown versions are never
silently interpreted as the current version.

The Phase 6 release suite exercises the current compatible minor, the previous compatible minor,
an incompatible major, duplicate and out-of-order handshake frames, unknown protocols/channels,
frame/nesting limits, truncation, and bounded reconnect/discovery/pairing storms.

## Semver

- Public Rust API follows Cargo semver.
- Before 1.0, a minor release may change Rust APIs but must document migration.
- Wire compatibility is independent of crate semver and changes only through explicit protocol
  version negotiation.
- Adding an opt-in transport/discovery feature is additive; changing the default feature set to pull
  in a network/runtime dependency is breaking and requires explicit review.
