# Crate layout

The crate family is split by dependency weight and runtime ownership:

| crate | ownership | default/runtime dependencies |
|---|---|---|
| `mutsuki-link-core` | identities, protocol negotiation, session/channel contracts and pure state machines | none |
| `mutsuki-link-local` | optional platform local IPC | platform-specific, opt-in |
| `mutsuki-link-tcp` | optional reliable TCP transport | async/runtime adapter, opt-in |
| `mutsuki-link-quic` | optional QUIC transport | QUIC/TLS/runtime stack, opt-in |
| `mutsuki-link-discovery` | optional manual/mDNS discovery providers | provider-specific, opt-in |
| `mutsuki-link-pairing` | optional pairing ceremony and trust-store contracts/backends | crypto/storage backend, opt-in |
| `mutsuki-link` | feature-gated convenience facade | core only by default |

The current workspace contains `mutsuki-link-core` and the minimal aggregate facade. Other crates
enter the workspace with their implementing issue, so their names do not become placeholder APIs.

Concrete features must be additive and independent. For example, selecting local IPC must not pull
in QUIC/TLS or discovery, and selecting TCP must not initialize mDNS. Applications may depend on
individual crates instead of the aggregate facade.
