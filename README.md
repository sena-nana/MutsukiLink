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

See [architecture](docs/architecture.md), [compatibility](docs/compatibility.md), and the planned
[crate layout](docs/crate-layout.md).
