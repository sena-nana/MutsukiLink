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
