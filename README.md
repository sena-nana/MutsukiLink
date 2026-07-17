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
cargo check -p ntp-mutsuki-link
```

See [architecture](docs/architecture.md), [compatibility](docs/compatibility.md), and the planned
[crate layout](docs/crate-layout.md). The runtime-neutral [core contracts](docs/core-contracts.md)
document handshake, transport, session, multiplexing, and bounded-memory semantics. See
[transport deployment](docs/transports.md) for security, fallback, budgets, and platform behavior.
Headless discovery, pairing, and trust persistence are documented in
[discovery and pairing](docs/discovery-pairing.md). Authentication evidence, bounded reconnect,
connection-only session resume, heartbeat, and quality management are documented in
[connection resilience](docs/connection-resilience.md).

Protocol owners can register independent versioned namespaces and run the product-neutral examples:

```bash
cargo run -p mutsuki-link --example peer_echo
cargo run -p mutsuki-link --example manual_server --features local -- my-link-address
cargo run -p mutsuki-link --example headless_pairing --features pairing
cargo run -p mutsuki-link --example discovery_pairing --features discovery,pairing
cargo run -p mutsuki-link --example local_sidecar --features local
cargo run -p mutsuki-link --example multiplex
cargo run --release -p mutsuki-link --example release_baseline --features local,tcp,quic
python3 scripts/run-performance-model.py --mode smoke
```

The Python entry point emits the shared Mutsuki Performance Model v1 report for the local, TCP,
QUIC, multiplex, backpressure, latest-only Datagram, and reconnect fixtures. See
[performance measurement](docs/performance-model.md) for the exact boundaries and for the
difference between public correctness smoke runs and fixed-machine reference history.

See [upper protocol integration](docs/protocol-integration.md) for owner-crate boundaries and
gradual migration guidance.

Realtime applications can keep their business protocol outside MutsukiLink while using the generic
`RealtimeDatagram` API. QUIC exposes protocol-bound reliable control handles, multiple independent
Datagram flows, latest-sequence replacement, deadlines, priority, current path payload limits,
bounded drop-oldest receive queues, reconnect reset, and per-flow telemetry. MutsukiLink does not
interpret media, tracking, sensor, or other application payloads.

NanaTracking producers use the independent `ntp-mutsuki-link` adapter rather than adding tracking
types to Link core. It negotiates the NTP descriptor and compact layout over a reserved reliable
control protocol, sends a one-Datagram compact Rig plus latest-only absolute result fragments, and
returns canonical `NanaTrackingResult` values to remote consumers. Dense geometry is a separate
low-frequency or on-demand flow. See [NTP remote producer binding](docs/ntp-remote-producer.md).

Before deployment or release, follow [security deployment](docs/security-deployment.md) and the
[release checklist](docs/release-checklist.md). The checklist includes the enforced
local/TCP/QUIC performance baseline, mobile/desktop matrix, hardware lifecycle cases, standalone
packaging, and owner-repository integration gates.
