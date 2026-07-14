# Connection authentication and resilience

MutsukiLink owns connection safety and continuity. It does not restore tasks, infer business
idempotency, assign roles, migrate workloads, or grant an application trust level.

## Authentication boundary

Concrete TLS/QUIC and local IPC adapters authenticate peers and return
`TransportSecurityEvidence`. Core validates that evidence against the expected paired `PeerId`,
current key fingerprint and epoch, expiry/revocation state, endpoint pair, Link version, and handshake
transcript. Remote production policy requires authenticated encryption and a forward-secure session
key. Raw keys never enter Core; the evidence contains only a backend key/exporter identifier.

Plain TCP is not a production fallback. It is accepted only when the caller selects
`AllowExplicitDevelopmentPlaintext` and the connection itself carries the explicit development
marker. Both defaults reject it. Local IPC may rely on the same long-term identity proof plus an OS
peer credential supplied by the platform adapter.

## Reconnect

`ReconnectController` contains no executor or timer. A host calls `after_failure`, then schedules the
returned `AttemptAt`. Exponential delay has injected jitter, maximum delay, attempt count, total
elapsed deadline, pause, reset, and cancellation. Network change, sleep/wake, temporary
unreachability, and transport close are retryable. Authentication failure, identity expiry, pairing
revocation, protocol incompatibility, and cancellation stop immediately.

## Session resume and replay

Resume tokens are opaque, authenticated by an injected `ResumeTokenVerifier`, expire, and have hard
byte/channel/cursor limits. A successful token restores only Link channel continuity. Event and
stream cursor bytes are returned to their namespace owner, which decides what history to send.

Every unacknowledged request has an explicit replay classification. `Never` is the default contract
and is failed after reconnect. `Idempotent` can be included in the automatic retry plan only for a
successfully resumed session. `ApplicationDecides` is surfaced to the owner and is never silently
sent by Link. The established `Session` publishes `ContinuityChanged(Resumed | NewSession)`.

## Heartbeat and quality

Heartbeat policy has separate idle, active, mobile, background, and local-IPC intervals. Recent
transport keepalive/ACK evidence suppresses Link probes. The controller distinguishes healthy,
temporarily unreachable, dead, and peer-closed state, and may be paused in the background.

The quality accumulator uses fixed-size counters and integer EWMAs—never per-packet histories. Its
summary includes RTT, jitter, loss, retransmission, queue pressure, throughput, transport, and
liveness. A change detector emits only significant differences for delivery through the bounded
session event bus.

## Overload and budgets

Connection budgets cover memory, bandwidth, channels, send-queue frames, resume cursors, pending
replays, and maintenance operations per tick. Maintenance can run normally, at reduced frequency, or
pause. Discardable event/telemetry frames may be dropped under pressure, while request/response,
streams, close, control, and necessary heartbeat retain explicit backpressure or reserved capacity.
