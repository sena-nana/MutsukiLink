#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if rg -n 'MutsukiCore|MutsukiServiceHost|MutsukiDistributedHost|mutsuki-runtime|tokio|quinn|rustls|mdns' crates/mutsuki-link-core/Cargo.toml; then
  echo "forbidden runtime, product, or concrete network dependency in link-core" >&2
  exit 1
fi

if rg -n --glob '*.rs' 'GlobalTaskId|AssignmentLease|NodeCapabilities|DistributedContext' crates; then
  echo "forbidden upper-layer execution type in MutsukiLink source" >&2
  exit 1
fi

cargo metadata --no-deps --format-version 1 >/dev/null
cargo check -p mutsuki-link-core --no-default-features
cargo check -p mutsuki-link --no-default-features

if cargo tree -p mutsuki-link --no-default-features --features local | rg 'quinn|rustls|mutsuki-link-quic|mutsuki-link-tcp'; then
  echo "local feature unexpectedly includes TCP or QUIC/TLS" >&2
  exit 1
fi

if cargo tree -p mutsuki-link --no-default-features --features tcp | rg 'quinn|rustls|mutsuki-link-quic|interprocess|mutsuki-link-local'; then
  echo "TCP feature unexpectedly includes local IPC or QUIC/TLS" >&2
  exit 1
fi
