# Multi-peer session pool (`mutsuki-link-runtime`)

`mutsuki-link-runtime` adds an optional, payload-agnostic orchestration layer on top of
`mutsuki-link-quic`. It lets one local endpoint hold **many concurrent authenticated peer
sessions**, keyed by `PeerId`.

Transport primitives already allow repeated `QuicListener::accept` and concurrent
`QuicConnector::connect` calls under `TransportBudget::max_connections`. The runtime crate does
not replace those APIs; it owns the peer map, duplicate-peer policy, and per-peer heartbeat /
reconnect controllers.

## Ownership boundary

| Layer | Owns | Must not own |
| --- | --- | --- |
| `mutsuki-link-core` | Single-session contracts, heartbeat/reconnect state machines | Sockets, accept loops, peer pools |
| `mutsuki-link-quic` | QUIC connections and connection budget permits | Peer trust, multi-peer indexing |
| `mutsuki-link-runtime` | `PeerSessionPool`, admit/connect orchestration | Application payloads / clipboard / tasks |
| Product hosts (e.g. MomoFlow) | Trust verification, protocol negotiation, sync fan-out | Link transport framing |

Enable via the facade feature:

```bash
cargo check -p mutsuki-link --features runtime
```

## Lifecycle

```text
bind(listener + connector)
        |
        |-- accept_inbound(provisional_remote_endpoint)
        |         -> InboundConnect (unauthenticated)
        |         -> host verifies trust / TLS evidence
        |         -> admit_inbound(peer_id, remote_endpoint)
        |
        |-- connect_outbound(peer_id, addr, remote_endpoint)
        |
        v
PeerSessionPool sessions: BTreeMap<PeerId, PeerSessionHandle>
        |
        |-- maintenance_tick / note_transport_failure
        |-- remove(peer) aborts connection and frees inbound permits
```

Construction never starts a background accept loop. Hosts call `accept_inbound` on demand (or
spawn their own loop). Dropping an `InboundConnect` without `admit_inbound` aborts the connection
and releases the listener permit.

## Authentication responsibility

Inbound connections leave the pool as `InboundConnect` / `PoolEvent::InboundAwaitingAuth`.
**Admission is not trust.** The host must validate pairing / certificate / public key evidence
before calling `admit_inbound`. The pool never upserts a trust store and never auto-trusts
discovery candidates.

## Budgets and limits

- **Listener `max_connections`**: concurrent inbound QUIC connections tracked by
  `QuicListener` / `ConnectionCounter` (includes not-yet-admitted connections).
- **`max_peers`**: authenticated sessions stored in the pool map. Exceeding it returns
  `PoolError::PeerLimit` (`WouldBlock`-class for hosts that map kinds).
- Outbound dials do not consume the listener counter; they still count toward `max_peers` once
  inserted.

## Duplicate `PeerId` policy

`DuplicatePeerPolicy` defaults to `ReplaceExisting`: admitting or connecting the same `PeerId`
again aborts the previous session and replaces the map entry. `Reject` returns
`PoolError::DuplicatePeer` and keeps the existing session.

## Heartbeat and reconnect

Each `PeerSessionHandle` owns independent `HeartbeatController` and `ReconnectController`
instances. Controllers still have **no built-in timer**:

- `maintenance_tick` only advances heartbeat state and emits `PoolEvent::Heartbeat`.
- `note_transport_failure` advances reconnect state and emits `ReconnectScheduled` or
  `ReconnectStopped`.
- Hosts schedule later `connect_outbound` calls when they see `ReconnectScheduled`.

Failures on one peer must not mutate another peer's controllers.

## Non-goals

- No implicit broadcast or fan-out of application payloads.
- No clipboard / media / tracking types in this crate.
- No automatic handshake or protocol negotiation inside the pool (hosts may layer that later).
- No changes to MutsukiCore or MutsukiTauriHost contracts.
