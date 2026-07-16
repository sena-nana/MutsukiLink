# NTP remote producer binding

`ntp-mutsuki-link` is an application adapter between generic MutsukiLink connections and the
framework-neutral NanaTracking Protocol crate. MutsukiLink core remains unaware of NTP, Signal IDs,
tracking SDKs, camera formats, and product consumers.

## Session and control

The reliable protocol namespace is `nana.tracking.remote.v2`. An adapter can be constructed only
from an opaque authorization derived from `AuthenticatedSession`; the grant must contain
`tracking.negotiate` plus the direction-specific `tracking.publish` or `tracking.subscribe`
permission. Pairing stores those scopes separately from `tracking.calibration.write`. Hello binds
both peers to the same authenticated Link session ID before any descriptor or layout is decoded.
`authorize_trusted_ntp_session` also checks the active trust state, peer ID, and key fingerprint;
revoked or rotated trust cannot mint the one-use adapter authorization.

Control messages use a bounded binary frame and carry protocol Hello/version, the canonical
`NanaTrackingDescriptor`, compact-layout
proposal/accept/confirm, session readiness, Start/Stop/Pause/Resume, topology metadata, geometry
request, receiver report, Ping/Pong, error, and close reason. The descriptor already owns the
calibration, schema, Signal Registry, normalization, and feature revisions.

Activation is deliberately four-way:

```text
Publisher          Subscriber
Proposal       ->
               <-  Accept
Confirm        ->
               <-  Ready
```

The publisher cannot send a result before `Ready`. Reconfiguration must use a newer generation for
the same session. Reconnect requires a new connection and freshly authenticated authorization for a
different Link session, then resets control, realtime queues, clock synchronization, fragment,
sequence, fuse, and descriptor state before negotiation. The descriptor is session state and
therefore never changes merely because a face or joint is temporarily occluded.

The control outbox and every decoded control payload have explicit hard limits. Backpressure retains
the bounded message for a later poll; it never diverts control messages to a Datagram or lets result
traffic consume the reliable control budget.

## Realtime flows

| Flow | Priority | Contents | Recovery |
|---|---:|---|---|
| `COMPACT_RIG_FLOW` | Critical | one negotiated NTP compact frame with absolute values/state/confidence | the next frame is independent |
| `CORE_RESULT_FLOW` | High | canonical absolute `NanaTrackingResult`, with dense landmarks omitted, explicitly fragmented to the current path payload | incomplete groups are discarded when a newer sequence arrives |
| `GEOMETRY_FLOW` | Disposable | low-frequency or explicitly requested canonical geometry snapshot | loss never blocks core Rig/skeleton results |

In Datagram mode the adapter adds only an 18-byte fragment header and MutsukiLink adds its generic
20-byte realtime header. Datagram reassembly is bounded by bytes and fragment count, accepts
out-of-order fragments, rejects overlap/inconsistent metadata, remembers the last completed
sequence, and retains at most one incomplete `(generation, sequence)` per flow. Any fragment loss
discards that logical result; the next absolute result needs no delta chain.

When Datagram is unavailable, `ReliableLatestOnly` uses a 23-byte explicit envelope and one reusable
pending buffer per logical flow. A newer unsent sequence replaces the old one, the receiver keeps
only the latest complete message per flow, and the received transport buffer moves into validation
without a second payload copy. Transport mode, replacements, and steady buffer growth are exposed in
`TrackingTelemetry`; fallback is never reported as Datagram.

Reliable control and data use distinct bounded receive lanes on memory, local IPC, TCP, and QUIC.
A saturated fallback data lane therefore cannot consume or corrupt the control lane. The publisher
reuses its compact sample, compact wire, fragment scratch, and fallback flow buffers. NTP's existing
`CompactFrameCodec::encode_into` remains the hot path, while the canonical codec is used for the
typed full-result interface. Dense geometry cadence is configurable and can be disabled in favor of
explicit requests.

## Time, reports, and consumer interface

Ping/Pong estimates producer monotonic time at the receiver and preserves uncertainty. Capture and
produced timestamps remain unchanged; the receiver never replaces them with arrival time. The NTP
compact guard enforces session, generation, layout, sequence, clock uncertainty, age, and capture
continuity. Completed canonical results pass through `ResultStreamGuard`, so the subscriber returns
the same `NanaTrackingResult` type used by a local producer.

Before either NTP parser runs, the adapter validates envelope length, the frame hard limit, active
Link session, generation, flow, and the exact compact length from the immutable `ActiveLayout`.
One-second burst FPS, ten-second sustained target FPS, and reconfiguration windows are bounded.
Repeated malformed frames trip a channel fuse with
aggregate counters instead of per-frame logs.

`ReceiverReport` contains received, dropped, stale, jitter, current result age, and clock
uncertainty. Jitter is a fixed-state EWMA; no per-frame history or global lock is used.

The standard API accepts only NTP descriptors/results. It has no raw RGB, depth image, vendor
dictionary, backend identity, or arbitrary debug payload field. Training/debug capture requires a
different explicitly authorized protocol.

## Verification scope

The checked-in report at `docs/reports/issue-15-ntp-binding.json` records deterministic loopback and
simulation evidence. `docs/reports/issue-17-ntp-security-fallback.json` adds authenticated fallback
and resource-boundary evidence; `artifacts/performance/ntp-security-fallback-macos-aarch64-smoke.json`
preserves the release-mode latency sample. All are smoke-only: localhost QUIC, memory transport, and synthetic
timing do not claim real Wi-Fi, iOS camera, NanaLive recording, or production latency.
Windows-specific validation is intentionally not used for this local acceptance.
