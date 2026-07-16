# Typed control wire contract

MutsukiLink's built-in control plane uses `ControlEnvelope` and `ControlPayload`. Product payloads
remain opaque and are not interpreted by Link Core. This contract is wire-visible and therefore
uses explicit big-endian fields; it never serializes Rust enum layouts or hashes with `std::hash`.

## Identity and schema derivation

`ProtocolStableId` is the first 16 bytes of SHA-256 over:

```text
"mutsuki-link.protocol-stable-id.v1\0" || authority UTF-8 || 0x00 || name UTF-8
```

`SchemaId` uses the same construction with domain
`"mutsuki-link.schema-id.v1\0"`. There is no Unicode or case normalization in the hash function.
Registered debug identities are deliberately narrower: a dot-separated lowercase ASCII authority
and a lowercase ASCII name, with each non-empty component using letters, digits, `-`, or `_`.
Protocol owners must publish a stable authority/name pair and must not
reuse it for a different contract. Registry and handshake processing reject a stable ID associated
with a different debug identity or `SchemaRef`.

`SchemaFingerprint` is the full SHA-256 digest of the canonical schema bytes selected by the
protocol owner. `SchemaRevision(0)` is invalid. A breaking schema change needs a new compatible
contract policy or protocol major version; matching a readable name never overrides a fingerprint
mismatch.

## Typed envelope v1

Every typed frame starts with this fixed 39-byte header:

| Field | Bytes | Encoding |
|---|---:|---|
| magic | 4 | ASCII `MLCT` |
| wire version | 2 | unsigned big-endian, currently `1` |
| opcode | 2 | stable `LinkControlOpcode` value |
| flags | 2 | bounded bitset |
| request ID | 8 | unsigned big-endian |
| session-present | 1 | `0` or `1` |
| session ID | 16 | zero when absent |
| payload length | 4 | unsigned big-endian |

The payload schema is selected only by opcode. `encode_control_envelope` rejects an envelope whose
opcode does not match its typed payload. `decode_control_envelope` rejects unknown opcodes, unknown
flags, unsupported versions, invalid enum discriminants, truncation, trailing bytes, invalid UTF-8,
and non-canonical absent session IDs. The payload is capped at 64 KiB, offers/selections at 32,
capability words at 8, debug components at 128 bytes, and session mappings at 128.

Published opcodes are append-only and must never be reassigned. Error behavior is driven by
`ErrorDomain`, `ErrorCode`, optional operation opcode, and `Retryability`; the diagnostic message is
not transmitted as an authorization or retry decision input.

## Capability and migration rules

Link capabilities are a bounded `u64`; upper protocol capabilities use an independently scoped,
bounded word vector carrying the associated `ProtocolStableId`. Negotiation intersects both sets.
An initiator rejects any responder selection containing Link capability bits it did not offer.

`LinkCapabilities::TYPED_CONTROL` explicitly selects `ControlIdentityMode::TypedV1` after
intersection. Its absence selects the compatibility-only `LegacyStringV1` mode for pre-typed peers.
`ControlModeGuard` is created from the authenticated `NegotiatedSession`; typed and legacy frames
cannot be mixed in that session. New integrations must advertise typed control. Legacy mode exists
only for an owner-provided old codec and cannot call the typed encoder/decoder; readable
`ProtocolId` values remain configuration/debug input rather than authoritative dispatch keys.

## Channel authorization and compact-envelope handoff

After protocol selection, `OpenChannel` identifies the protocol and protocol-local channel by stable
numeric IDs. The active descriptor, not the remote request, supplies mode and limits. An accepted
mapping is installed into the authenticated `SessionChannelMap`. Both directions are indexed, and a
repeated protocol or session channel binding is rejected rather than overwritten. This mapping is
the direct input for the compact data envelope implemented by issue #18.

The golden vector and bounded mutation/truncation tests live with the codec in
`mutsuki-link-core/src/control.rs`; registry conformance coverage is in the phase 5 acceptance suite.
