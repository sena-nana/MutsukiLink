# Performance measurement

`scripts/run-performance-model.py` is the Link entry point for Mutsuki Performance Model v1. It
builds release binaries once, runs each binary in a fresh process, preserves raw samples, and emits
median, P95, P99, MAD, process CPU, peak RSS, allocation, and bounded-queue counters.

The matrix is product-neutral:

- local IPC, TCP, and QUIC use the same connect, RTT, saturated-control, throughput, and shutdown
  cases with 256 B, 4 KiB, 64 KiB, and 1 MiB payloads;
- multiplex scheduling uses 1, 16, and 56 logical flows with the same payload sizes;
- the realtime lane verifies latest-only replacement, expired-Datagram rejection, disposable
  congestion drops, and reconnect reset;
- the QUIC integration fixture proves a capacity-two receive queue retains the newest two of eight
  frames and reports six drop-oldest events;
- reconnect evaluation exercises bounded retry storms and records attempts and budget stops.

Run a quick correctness report with:

```bash
python3 scripts/run-performance-model.py \
  --mode smoke \
  --output target/mutsuki-benchmarks/link-smoke.json
```

Run a candidate fixed-machine report with:

```bash
python3 scripts/run-performance-model.py \
  --mode reference \
  --output artifacts/performance/issue21-macos-arm64-provisional/report.json
```

Every transport profile produced here is single-machine loopback. The QUIC drop-oldest case is
labelled diagnostic because its elapsed value is the complete release-mode integration-test process,
not an operation latency. Neither result may be used as a LAN, Wi-Fi, mobile, or production-network
claim.

Public CI uploads smoke reports and blocks only on build or correctness failures. This repository
owns Link's fixed macOS ARM64 and Windows x64 reports, analysis, approval and history under
`artifacts/performance/`. A local or public-hosted report may seed investigation, but cannot replace
an exact-byte approved same-machine baseline.
