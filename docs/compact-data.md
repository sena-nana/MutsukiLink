# Compact session-local data frames

The authenticated typed-control flow freezes protocol identity, version, schema, capabilities, and
channel limits before data starts. `Session::open_validated_channel` is the only Session API that
installs this result. It accepts the sealed `ValidatedChannel` produced by `ActiveProtocolSet`,
creates the #19 `SessionChannelMap` entry, and opens the numeric multiplexer state atomically.

## Channel lifetime

Channel zero is permanently reserved for Link control. Every accepted data channel receives an
initial non-zero `ChannelGeneration(1)`. Within one Session, a closed `ChannelId` is retired and
cannot be rebound, even to a different protocol channel. This deliberately avoids generation wrap
and late-frame ambiguity rather than trying to make reuse safe. A reconnect that produces a new
`SessionId` starts a new empty table; old frames fail the Session ID check before channel lookup.

The Session table and multiplexer state together retain the frozen descriptor: stable protocol ID,
negotiated version, protocol-local channel ID, schema/capabilities from the Session selection, mode,
priority, capacity, frame/stream limits, discard policy, generation, and optional debug metadata.
The enqueue/dequeue hot path indexes only `ChannelId`, then checks generation and limits. Typed
protocol keys remain in an auxiliary management index and are never copied into a data frame.

## Compact data wire v1

The fixed header is 47 bytes and uses explicit big-endian fields:

| Field | Bytes | Rule |
|---|---:|---|
| magic | 4 | ASCII `MLDT` |
| wire version | 2 | `1` |
| frame kind | 1 | `1` for data; control has a separate codec/queue |
| Session ID | 16 | exact current authenticated Session |
| Channel ID | 4 | non-zero session-local ID |
| generation | 4 | non-zero, currently `1` because IDs are not reused |
| sequence | 8 | owner-defined monotonic sequence space |
| nesting depth | 2 | bounded before payload access |
| flags | 2 | end-of-stream and cancelled bits only |
| payload length | 4 | bounded before returning the payload slice |

No protocol ID, readable namespace, version, protocol channel ID/name, schema, capability, or
descriptor field is present. `decode_data_envelope` returns `BorrowedDataEnvelope`, so parsing does
not allocate or copy payload bytes. `encode_data_envelope_into` reuses caller-owned storage; after
one sufficient reserve, repeated frames do not grow the buffer. The owned convenience encoder and
`BorrowedDataEnvelope::into_owned` remain available when ownership is required.

Unknown frame kinds, versions, flags, zero channels/generations, payload limits, truncation, and
trailing bytes fail with `DataCodecErrorKind`. The multiplexer separately rejects unknown, closed,
cancelled, wrong-generation, and wrong-Session frames without revealing protocol descriptors.

## Negotiation and migration

| Typed control | `COMPACT_CHANNEL_ID` | Session data mode | Allowed wire identity |
|---|---|---|---|
| yes | yes | `CompactV1` | compact numeric frame only |
| yes | no | `LegacyFullChannelKey` | owner compatibility adapter only |
| no | either | `LegacyFullChannelKey` | owner compatibility adapter only |

`DataModeGuard` is derived from the authenticated handshake. A compact codec call in legacy mode,
or a legacy adapter call in compact mode, fails. Legacy strings never enter `SessionChannelMap`.
Legacy mode remains only for pre-typed peers and is removed when the supported peer floor requires
typed control plus compact-channel capability.

## Smoke performance evidence

The checked-in macOS arm64 report at
`artifacts/performance/compact-data-macos-aarch64-smoke.json` is explicitly synthetic smoke-only. It
records the 47-byte header, modeled minimum legacy headers across 8/32/128-byte identities, steady
buffer growth, borrowed-decode copies, and local encode/decode throughput for 64/256/1024-byte
payloads at 60/120 FPS equivalents. The existing mux report covers 1/16/64 active channels and
event/request-response/stream scheduling behavior. Neither report proves Wi-Fi, production latency,
or NanaTracking model quality.
