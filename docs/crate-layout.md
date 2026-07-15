# Crate layout

The crate family is split by dependency weight and runtime ownership:

| crate | ownership | default/runtime dependencies |
|---|---|---|
| `mutsuki-link-core` | identities, protocol negotiation, authentication evidence, reconnect/resume, liveness, quality, session/channel contracts and pure state machines | none |
| `mutsuki-link-io` | internal bounded Tokio framing bridge shared by concrete transports | Tokio, never exposed by the facade |
| `mutsuki-link-local` | optional platform local IPC | platform-specific, opt-in |
| `mutsuki-link-tcp` | optional reliable TCP transport | async/runtime adapter, opt-in |
| `mutsuki-link-quic` | optional QUIC transport | QUIC/TLS/runtime stack, opt-in |
| `mutsuki-link-discovery` | optional manual/mDNS discovery providers | provider-specific, opt-in |
| `mutsuki-link-pairing` | optional pairing ceremony and trust-store contracts/backends | crypto/storage backend, opt-in |
| `mutsuki-link` | feature-gated convenience facade | core only by default |
| `mutsuki-link-transport-testkit` | internal shared Session acceptance suite | test only |
| `ntp-mutsuki-link` | independent NanaTracking Protocol control/session and realtime-flow binding | Link core plus pinned framework-neutral NTP protocol crate |

The current workspace contains core, the minimal aggregate facade, local/TCP/QUIC transports,
discovery, and pairing/trust-store crates. Future provider crates enter with their implementing issue,
so their names do not become placeholder APIs.

Concrete features must be additive and independent. For example, selecting local IPC must not pull
in QUIC/TLS or discovery, and selecting TCP must not initialize mDNS. Applications may depend on
individual crates instead of the aggregate facade.
