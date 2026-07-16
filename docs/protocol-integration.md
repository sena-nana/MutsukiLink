# Upper protocol integration

MutsukiLink provides discovery, pairing, authenticated sessions, transport, channel isolation,
reconnect, and quality summaries. Product repositories own their message schemas, codecs,
idempotency, synchronization, and business recovery.

The workspace's `ntp-mutsuki-link` crate is the concrete example of this boundary: it depends on
both generic Link core and the NanaTracking Protocol crate, while neither dependency knows about the
other. It exposes only normalized NTP descriptors/results and generic Link connection contracts;
ARKit, MediaPipe, Maxine, raw camera frames, and producer backend identity are not part of its
standard channel. Its wire/session details are documented in
[NTP remote producer binding](ntp-remote-producer.md).

## Registration and session boundary

Each owner registers a `ProtocolDescriptor` before freezing the registry. A descriptor contains:

- a stable 128-bit protocol id, optional debug identity, and independent version range;
- a structured schema reference/fingerprint and protocol-scoped capability words;
- stable numeric channel ids plus optional debug names and request/response, event, or stream mode;
- priority plus maximum frame, stream, and in-flight limits;
- an explicit discardable marker allowed only for lossy events.

The frozen registry produces typed handshake offers. Negotiation happens per stable id, so one
incompatible protocol disappears from the resulting selection without closing another compatible
protocol. `ActiveProtocolSet` and the restricted multiplexer reject channels that were not selected.
Payloads are opaque; no task, file, debug-command, resource-manifest, or workspace field is parsed by
Link.

New owner adapters advertise `LinkCapabilities::TYPED_CONTROL`, encode built-in operations with the
typed control codec, and install accepted numeric channels into the authenticated session mapping.
See [Typed control wire contract](typed-control.md). Strings remain useful in configuration and
diagnostics but are not wire authority.

## LiliaCode owner contract

The LiliaCode repository should own an independent protocol crate and a namespace such as
`lilia.code`. Candidate channels are `command`, `debug`, `file`, and `event`; the owner defines their
wire schemas and request replay rules. Link supplies only the authenticated session, stream framing,
resume cursor container, reconnect state, and quality events.

Side-effecting operations such as chat send, interaction response, and process spawn default to
`RequestReplay::Never` or `ApplicationDecides`; Link must not repeat them merely because a connection
resumed.

Migration remains an owner-side deployment choice. A recommended progression is `LegacyOnly`,
`Shadow`, `LinkPreferred`, then `LinkOnly`, negotiated per peer/version. Link has no compatibility
flag that interprets legacy Lilia messages. Mobile background behavior, Wi-Fi handoff, desktop sleep
recovery, and large-file resume must be exercised in LiliaCode integration tests around the generic
Link contracts.

### Current-source audit

The audit used LiliaCode commit `72cf66f71bca4726b4e78c464d9341f50ef9d39b` on 2026-07-14. Its current mobile-to-desktop beta is a
Compose Android client talking to a desktop plaintext HTTP bridge; it is not a secure Rust connection
library. The repository's checked-in CodeGraph directory had no usable index in the shallow audit
checkout, so source inspection fell back to targeted file/symbol reads after the CodeGraph attempt.

| Capability | Current LiliaCode behavior | Migration decision |
|---|---|---|
| Discovery | QR or pasted `lilia-remote://pair` link; no mDNS or network scan | Wrap the existing UI around Link manual candidates first; add optional discovery later |
| Pairing | Ten-minute ticket/challenge; scanning creates one-sided trust | Keep only behind `legacy_pairing_v1`; render Link presentation and require explicit confirmation for v2 |
| Identity/authentication | Copyable endpoint UUID stored in SQLite; no long-term key proof, signed transcript, TLS, or resume token | Replace with platform-keystore identity, real `PairingCrypto`, TrustStore, and transport-security evidence; never import legacy trust as verified Link trust |
| Commands/messages | One TCP/HTTP JSON request at a time, dispatched by the desktop business router | Reuse business payload/dispatch in the owner crate; adapt transport to the `command` request/response channel |
| Events | Timeline subscription is approximately 1.5-second polling | Use the `event` channel; retain polling only for legacy peers and authoritative resync after gaps/new sessions |
| Files | Attachments carry desktop path metadata; no file transfer | Add an owner file protocol over `file` stream with chunks/ranges, hashes, quota/path authorization, cancellation, temporary output, atomic commit, and resume |
| Reconnect/state | Foreground resume fetches an authoritative snapshot; no address rediscovery or Link session resume | Keep snapshot reconciliation, driven by Link reconnect/continuity and refreshed endpoint candidates |
| Mobile background/network | Foreground service is a notification, not a live connection owner; persisted bridge address breaks on Wi-Fi change | Add lifecycle driver, Android network callbacks, Doze policy, QUIC rebind/reconnect, and background budgets |
| Desktop sleep | Windows uses a recent-activity keep-awake window; the non-Windows implementation is a no-op | Drive sleep/wake reconnect explicitly; retain keep-awake only as an owner policy |
| Large transfer | Whole HTTP request body is buffered without a useful transfer protocol or resume | Do not route large files through the legacy bridge; validate 1 GiB+ interrupted/resumed streams and hashes |

Reusable owner code includes the product request/response/event contracts in
`packages/contracts/src/remote-control.ts` and the desktop business dispatcher in
`apps/desktop/src-tauri/src/remote_control.rs::dispatch_request`. Android screens, active-PC
selection, task snapshot replacement, timeline merge, and unauthorized-state clearing also remain
product behavior. The old device records and transport authorization model do not meet Link's trust
baseline.

The migration's security gate is fail-closed: the legacy HTTP listener is opt-in during transition,
must never be an automatic fallback for a peer with Link trust, and cannot be treated as production
authenticated transport. The audited beta exposes pairing/status metadata too broadly and authorizes
business requests using only the device identifier, so `require_secure_link` must prevent downgrade.

Recommended owner switches are `link_transport`, `link_pairing_v2`, `link_events`, and
`link_file_stream`, plus per-peer `legacy | link | auto` and a non-bypassable `require_secure_link`.
Roll out new-pairing canaries, then command/event, then file streaming, and finally make Link the
default before removing v1. The owner still needs Android Rust/JNI or UniFFI packaging, Android
Keystore, desktop Keychain/Credential Manager, executor/timer/lifecycle drivers, and real-device
tests for Doze, Wi-Fi/cellular/AP changes, Windows/macOS sleep, revocation/rotation, and interrupted
large files.

## MutsukiDistributedHost owner contract

`MutsukiDistributedHost` is currently a separate owner repository. Its Link adapter should consume
only `AuthenticatedSession`, selected channels, `ConnectionQuality`, continuity, and disconnect
events. The owner protocol crate may use a namespace such as `mutsuki.distributed.cluster`, with
small `control` traffic separated from `resource` and `result` streams. Cluster membership, task
envelopes, resource manifests, placement, role/term, leases, and recovery remain in that owner crate.

Local IPC can connect the sidecar to a local Host control adapter. Remote QUIC (or explicitly secured
TCP) connects nodes. Large data goes directly between endpoint and worker data channels; Link never
routes it through a control node. Disabling the DistributedHost repository therefore leaves Link and
LiliaCode usable with no product dependency, while disabling LiliaCode introduces no dependency into
the distributed adapter.

## Product-neutral examples

- `peer_echo` registers a minimal request/response namespace without MutsukiCore.
- `manual_server` binds an explicit local server address and starts no discovery or pairing UI.
- `headless_pairing` emits a pairing offer for a mobile/desktop owner adapter; rendering and real
  long-term-key signing stay above Link.

Disconnect becomes a bounded `SessionEvent`; it never cancels a Core task or mutates a Lilia
workspace. Request idempotency and business-state recovery are always declared by the owner protocol.
