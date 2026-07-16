# Transport deployment

All concrete transports are opt-in and inert until an application calls `bind` or `connect`. They
run bounded tasks on the caller's Tokio runtime; they do not create a runtime or occupy a dedicated
business/real-time thread pool.

## Local IPC

`mutsuki-link-local` maps a namespaced local address to Unix-domain sockets on Unix-family systems
and named pipes on Windows. It never opens a network port. Accepted connections expose optional
process, user, and group credentials when the platform provides them. These values are authentication
inputs, not an authentication decision; the identity owner must account for PID reuse and platform
semantics.

Local transport does not change Host/plugin execution. A DistributedHost adapter exchanges opaque
Link frames with a ServiceHost or other Host endpoint, while normal plugin invocation remains owned
by that Host.

## TCP

`mutsuki-link-tcp` provides reliable framed streams, connect timeout, socket keepalive, `TCP_NODELAY`,
bounded accept count, independent control/data queues, half-close, and abort. Its
`security_level()` is always `Plaintext`. A production remote deployment must layer an authenticated
encrypted Link session on top; fallback policy cannot relabel TCP as secure.

## QUIC

`mutsuki-link-quic` always receives caller-supplied Quinn client/server crypto configuration, so
certificate issuance and peer trust remain injectable. It reserves separate QUIC bidirectional
streams for Link control and data traffic, but never exposes QUIC stream ids to application
protocols. Optional datagrams and current RTT are available through the transport-neutral connection.
QUIC connection migration remains available through Quinn's stable connection handle.

`Connection::open_control_stream` binds reliable control frames to a negotiated `ProtocolId` while
retaining the reserved control-stream budget. `try_send_latest` uses a bounded, per-flow queue: a
new generation or sequence replaces the unsent group for that flow, an expired group is discarded
before entering QUIC, and critical/high-priority flows drain before disposable work. The adapter
checks Quinn's Datagram send-buffer space before enqueueing into Quinn so congestion does not cause
an unobservable global oldest-packet eviction. Applications fragment payloads themselves according
to `max_datagram_payload`; MutsukiLink never converts an oversized Datagram into a reliable stream.

Received Datagrams retain message boundaries and arrival time. The receive task has a hard queue
limit and drops the oldest queued Datagram on overflow. `realtime_telemetry` reports queue, expiry,
replacement, congestion, receive-overflow, RTT, estimated send rate, path payload, migration, and
reconnect counters, including per-flow packet/byte/drop totals. After reconnect, callers invoke
`reset_realtime_session` and create a new application generation; no queued payload is carried into
the new session.

The current API deliberately rejects `enable_zero_rtt = true`. Link control operations can mutate
state and are not replay-safe; the connector always waits for a full authenticated handshake. A
future 0-RTT API must accept only explicitly replay-safe application data and must never carry pairing,
cancel, close, assignment, or other control frames.

## Selection and fallback

`FallbackPlan` sorts explicit candidates by priority (for example local, then QUIC, then TCP), records
sanitized failure categories, and returns the selected transport with RTT/quality summary. Plaintext,
authenticated, and authenticated-encrypted security levels are explicit. Unless a caller opts into
security downgrade, failure of a stronger candidate prevents trying a weaker one; minimum-security
policy filters unacceptable candidates before the first attempt.

## Resource budgets

`TransportBudget` bounds active connections, concurrent QUIC streams, frame bytes, control/data/send
queues, receive queues, send/receive byte rates, and idle time. Control and data have independent
send and receive lanes. The receiver identifies the control lane from the existing versioned
`MLCS + ProtocolId` envelope, so the outer four-byte length framing remains wire-compatible. The
shared framing bridge always polls reserved control work before data; one full data queue
therefore cannot prevent enqueueing or receiving ping, cancel, drain, or close. A deployment should
also choose a maximum data frame size small enough for its control-latency target on stream transports.

Listeners accept only on demand and refuse work after `max_connections`; there is no unbounded accept
loop or task spawning. Each accepted stream owns one bounded reader and writer task (QUIC owns one pair
per reserved control/data stream), and dropping/aborting the connection cancels those tasks.
