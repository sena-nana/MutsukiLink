# MutsukiLink

MutsukiLink is a reusable connection runtime/library for peer discovery, pairing, authenticated
sessions, reconnect, and multiplexed application channels. It answers **how peers connect safely**.
It does not decide what an application does after connecting.

The default build is intentionally minimal:

```bash
cargo check -p mutsuki-link-core --no-default-features
cargo check -p mutsuki-link --no-default-features
```

No default feature starts a thread, opens a port, scans a network, loads a TLS/QUIC stack, or pulls
in a Mutsuki runtime repository.

Concrete transports are selected independently:

```bash
cargo check -p mutsuki-link --features local
cargo check -p mutsuki-link --features tcp
cargo check -p mutsuki-link --features quic
cargo check -p mutsuki-link --features discovery
cargo check -p mutsuki-link --features mdns
cargo check -p mutsuki-link --features pairing
cargo check -p mutsuki-link --features system-keyring
```

See [architecture](docs/architecture.md), [compatibility](docs/compatibility.md), and the planned
[crate layout](docs/crate-layout.md). The runtime-neutral [core contracts](docs/core-contracts.md)
document handshake, transport, session, multiplexing, and bounded-memory semantics. See
[transport deployment](docs/transports.md) for security, fallback, budgets, and platform behavior.
Headless discovery, pairing, and trust persistence are documented in
[discovery and pairing](docs/discovery-pairing.md). Authentication evidence, bounded reconnect,
connection-only session resume, heartbeat, and quality management are documented in
[connection resilience](docs/connection-resilience.md).
