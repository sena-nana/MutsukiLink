# Release checklist

## Automated gate

Run from a clean independent checkout with no sibling Mutsuki repositories:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo metadata --locked --format-version 1
bash scripts/check-boundaries.sh
cargo run --release -p mutsuki-link --example release_baseline --features local,tcp,quic
cargo run --release -p mutsuki-link --example mux_baseline
cargo package -p mutsuki-link-core
cargo package -p mutsuki-link --list
cargo package -p ntp-mutsuki-link --list
```

The facade package uses `--list` until its version-matched internal Link crates are published; Cargo
cannot verify an unpublished dependency from its local archive. The manifest still requires
versioned internal crates and contains no repository-external paths. After publishing the internal
crates, replace the list check with a normal `cargo package -p mutsuki-link`. The transport baseline
fails when a loopback transport exceeds 5 seconds to connect, control or RTT P99 exceeds 50 ms, any
1 KiB/16 KiB/64 KiB/1 MiB case falls below 4 MiB/s, or shutdown exceeds 2 seconds. It uses warm-up
and 128 RTT samples and emits structured machine/transport JSON. The separate mux baseline covers
1/16/64 active channels across the same payload sizes, verifies retained queue storage does not grow
after warm-up, and measures reserved control latency under 64 saturated data channels. Set
`MUTSUKI_LINK_BASELINE=artifacts/performance/mux-reference-v1-smoke.json` to apply the historical 2x
relative latency/throughput/fixed-size gate; a 5 us timer-jitter floor avoids turning sub-microsecond
scheduler noise into CI failures. Both reports are loopback/in-memory smoke-only evidence and do not
represent LAN or Wi-Fi performance.

CI additionally verifies:

- complete tests on Windows, macOS, and Linux;
- Android arm64 and iOS arm64 core/pairing-only compilation;
- Unix-domain socket or Windows named-pipe local IPC according to the runner;
- TCP IPv4/IPv6 on every desktop, QUIC IPv4 on every desktop, QUIC IPv6 on macOS/Linux, and QUIC
  endpoint rebinding;
- minimal, individual, and representative combined facade features;
- MSRV 1.85 and standalone Cargo packages with no Mutsuki product dependency.

## Hardware and network gate

Record the platform, OS, network, commands, and observed results for:

- remote localhost and two-device LAN TCP/QUIC, including IPv4 and IPv6 where the network supports
  them;
- Wi-Fi to cellular/Wi-Fi address change, transient offline recovery, and QUIC migration;
- Android/iOS foreground, background, resume, force-stop, and process recreation;
- desktop sleep/wake, peer process kill, reset, and half-close;
- identity revoke, key rotation, duplicate pairing, invalid-pairing storm, and discovery storm;
- concurrent large resource transfer and control requests, confirming no control starvation;
- repeated connect/disconnect with OS task, socket/file-descriptor, and memory observations stable
  after settling.

Any authentication downgrade, non-idempotent request replay, deadlock, unbounded growth, control
starvation, or shutdown beyond the configured deadline blocks release.

## Owner integration gate

Run LiliaCode and MutsukiDistributedHost independently against the proposed Link revision. Each
owner must pin only MutsukiLink and its own protocol crate; neither product may depend on the other.
Verify the `lilia.code` and `mutsuki.distributed.cluster` namespaces do not share channels, payload
types, trust policy, or reconnect ownership. The Link repository's protocol integration acceptance
test is the product-neutral prerequisite, not a substitute for each owner's repository CI.

## Feature and example gate

Confirm `--no-default-features` opens no port, starts no thread, initializes no discovery/keyring,
and does not load Tokio, QUIC/TLS, mDNS, or a Mutsuki product runtime. Run:

```bash
cargo run -p mutsuki-link --example peer_echo
cargo run -p mutsuki-link --example manual_server --features local -- my-link-address
cargo run -p mutsuki-link --example discovery_pairing --features discovery,pairing
cargo run -p mutsuki-link --example local_sidecar --features local
cargo run -p mutsuki-link --example multiplex
```

Review the dependency trees for `local`, `tcp`, `quic`, `discovery`, `mdns`, `pairing`, and
`system-keyring` separately. An unrequested transport, discovery provider, runtime, or credential
backend is a release blocker.
