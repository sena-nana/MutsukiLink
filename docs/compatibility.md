# Compatibility policy

## Rust and platforms

- MSRV: Rust 1.85 (first stable Rust release with Edition 2024 support).
- Tier 1 desktop targets: Windows x86_64, macOS arm64/x86_64, Linux x86_64.
- Mobile compile targets planned for the core/pairing layers: iOS arm64 and Android arm64.
- A platform-specific transport is available only on platforms where its crate documents support;
  the runtime-neutral core remains portable.

## Wire protocol

`LINK_PROTOCOL_VERSION` is the current wire family version and
`MIN_COMPATIBLE_LINK_PROTOCOL_VERSION` is the oldest accepted version. Handshake negotiation must
select an intersection or return a structured incompatibility error. Unknown versions are never
silently interpreted as the current version.

## Semver

- Public Rust API follows Cargo semver.
- Before 1.0, a minor release may change Rust APIs but must document migration.
- Wire compatibility is independent of crate semver and changes only through explicit protocol
  version negotiation.
- Adding an opt-in transport/discovery feature is additive; changing the default feature set to pull
  in a network/runtime dependency is breaking and requires explicit review.
