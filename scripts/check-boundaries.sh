#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if rg -n --glob 'Cargo.toml' 'MutsukiCore|MutsukiServiceHost|MutsukiDistributedHost|mutsuki-runtime|tokio|quinn|rustls|mdns' crates; then
  echo "forbidden runtime, product, or concrete network dependency in Phase 0 crates" >&2
  exit 1
fi

if rg -n --glob '*.rs' 'GlobalTaskId|AssignmentLease|NodeCapabilities|DistributedContext' crates; then
  echo "forbidden upper-layer execution type in MutsukiLink source" >&2
  exit 1
fi

cargo metadata --no-deps --format-version 1 >/dev/null
cargo check -p mutsuki-link-core --no-default-features
cargo check -p mutsuki-link --no-default-features
