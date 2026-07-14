# Runtime-neutral core contracts

`mutsuki-link-core` is a pure state and framing layer. It does not choose an executor, socket,
cryptographic implementation, discovery provider, or application serializer.

## Identity and handshake

`PeerId` is the long-lived peer identity. `EndpointId` identifies one stable endpoint,
`ConnectionId` one connection attempt, and `SessionId` one negotiated session. Distinct Rust types
prevent accidental substitution.

The handshake negotiates a Link protocol version and one or more namespaced upper protocols. It has
separate first-pairing and trusted-reconnect paths. Identity proofs remain opaque: the state machine
emits a `VerificationRequest`, and an external owner returns `ProofDecision`. Public handshake errors
contain only a stable category and sanitized message.

First pairing advertises only `HandshakePolicy::pairing_protocols`; the full protocol catalog is used
only for a trusted reconnect. An unpaired discovery candidate therefore cannot enumerate sensitive
application namespaces through the handshake.

## Transport readiness and shutdown

`Connection` is a runtime-neutral, non-blocking reliable message interface. `WouldBlock` is the
backpressure signal. A concrete adapter may use any executor to wait for readiness. Optional
datagrams report `Unsupported` when absent. The two half-close methods are independent; `abort`
immediately terminates local work. `OperationContext` carries an explicit deadline and clonable
cancellation token for connect, send, and receive operations (`ConnectContext` is its
connection-facing alias).

The in-memory connection implements the same queue, message-size, datagram, half-close, and abort
semantics without starting a thread.

## Session and multiplexing

Sessions progress through `Connecting`, `Handshaking`, `Established`, `Draining`, and a terminal
`Closed` or `Failed` state. `begin_drain` stops the lifecycle from returning to established;
`finish_drain` requires all queued frames to be sent. `abort` discards them immediately.

Every channel key includes protocol namespace, version, and numeric id. Request-response, event,
and stream modes share only the generic envelope; payload bytes are owned by the upper protocol's
chosen codec. Limits cover frame bytes, declared nesting depth, channels, per-channel queue capacity,
total queued data, and event subscribers.

Control frames use a separate bounded queue with reserved capacity. Data saturation therefore cannot
block drain, close, or heartbeat. Data channels enter a round-robin ready queue, so one slow namespace
does not block another. Session event subscribers are also bounded; a slow subscriber loses oldest
events and receives an `EventsDropped` count instead of blocking network progress.

Discardable telemetry and low-priority events use `enqueue_discardable`. Only event channels may opt
into this behavior; reliable request/response and stream frames retain explicit backpressure. The
control queue remains separately bounded and reserved even when the total data-frame limit is full.

## Authentication, reconnect, and continuity

`validate_transport_security` consumes evidence produced by a concrete TLS/QUIC or local-credential
backend. Remote production connections require mutual authentication, encryption, forward-secure
session keys, the current long-term identity key, and bindings to the handshake transcript, protocol
version, and both endpoints. Plain TCP is accepted only when both the policy and the evidence mark an
explicit development connection; the default is fail-closed. Local IPC can additionally require a
verified platform peer credential without coupling Core to a platform API.

`ReconnectController` implements disabled, immediate, exponential-backoff, and
application-controlled policies with bounded attempts, total deadline, injected jitter, pause, and
cancellation. Revoked/expired identity, failed authentication, and protocol incompatibility are
permanent stop reasons rather than retryable transport failures.

`ResumeCoordinator` validates bounded opaque resume offers through an injected verifier. It restores
only Link session/channel continuity. Cursor bytes remain owned by the upper protocol. An
unacknowledged request defaults to `RequestReplay::Never`; only requests explicitly declared
idempotent enter the automatic replay plan. `SessionContinuity` and `SessionEvent::ContinuityChanged`
tell the upper layer whether it received a resumed or a new session.

## Liveness, quality, and resource budgets

Heartbeat intervals vary for idle, active, mobile, background, and local-IPC profiles. A recent
transport ACK suppresses a redundant Link probe. Heartbeat and reconnect controllers can pause, and
maintenance work has an operation budget per tick. Liveness distinguishes elevated latency,
temporary unreachability, death, and an explicit peer close.

Quality aggregation keeps only fixed-size counters and EWMAs for RTT, jitter, loss/retransmission,
queue pressure, throughput, transport type, and liveness. `QualityChangeDetector` emits only
threshold-crossing summaries, which can be published through the existing bounded session event bus.
`ConnectionBudget` exposes hard connection-level memory, bandwidth, channel, send-queue, resume,
pending-replay, and maintenance limits. These values are observations and limits only; Core never
migrates work or changes application capabilities.
