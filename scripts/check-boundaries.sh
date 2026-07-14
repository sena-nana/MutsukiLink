#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if rg -n 'MutsukiCore|MutsukiServiceHost|MutsukiDistributedHost|mutsuki-runtime|tokio|quinn|rustls|mdns' crates/mutsuki-link-core/Cargo.toml; then
  echo "forbidden runtime, product, or concrete network dependency in link-core" >&2
  exit 1
fi

if rg -n --glob '*.rs' 'GlobalTaskId|AssignmentLease|NodeCapabilities|DistributedContext|LeaderTerm|TaskLease|LiliaCode|TrustLevel' crates; then
  echo "forbidden upper-layer execution type in MutsukiLink source" >&2
  exit 1
fi

cargo metadata --no-deps --format-version 1 >/dev/null
cargo check -p mutsuki-link-core --no-default-features
cargo check -p mutsuki-link --no-default-features

if cargo tree -p mutsuki-link --no-default-features --features local | rg 'quinn|rustls|mdns-sd|mutsuki-link-quic|mutsuki-link-tcp|mutsuki-link-discovery'; then
  echo "local feature unexpectedly includes TCP or QUIC/TLS" >&2
  exit 1
fi

if cargo tree -p mutsuki-link --no-default-features --features tcp | rg 'quinn|rustls|mdns-sd|mutsuki-link-quic|interprocess|mutsuki-link-local|mutsuki-link-discovery'; then
  echo "TCP feature unexpectedly includes local IPC or QUIC/TLS" >&2
  exit 1
fi

if cargo tree -p mutsuki-link --no-default-features --features discovery | rg 'mdns-sd'; then
  echo "discovery feature unexpectedly includes the mDNS backend" >&2
  exit 1
fi

if cargo tree -p mutsuki-link --no-default-features --features pairing | rg 'keyring|security-framework|linux-keyutils'; then
  echo "pairing feature unexpectedly includes a system credential backend" >&2
  exit 1
fi

if rg -n 'tauri|slint|egui|clap|dialog' crates/mutsuki-link-pairing/Cargo.toml crates/mutsuki-link-pairing/src; then
  echo "pairing core unexpectedly depends on a UI or CLI layer" >&2
  exit 1
fi
