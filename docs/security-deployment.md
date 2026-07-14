# Security deployment

## Production remote links

Production TCP or QUIC deployments must provide authenticated encryption, mutual peer identity
verification, forward-secure session keys, and transcript/endpoint/version binding. The QUIC crate
accepts owner-supplied TLS client/server configuration; it does not invent a certificate authority
or trust policy. TCP is plaintext at the transport layer and is production-safe only inside an
owner-supplied authenticated encrypted session or equivalent protected network boundary.

Never enable automatic plaintext fallback after an authentication, certificate, version, or trust
failure. Development plaintext is an explicit `SecurityPolicy` choice, must be visibly marked by the
product, and must not share production credentials or listen on an untrusted interface.

## Local IPC

Local IPC uses Unix-domain sockets on Unix and named pipes on Windows. The accepting owner must
validate the peer credentials exposed by `LocalConnection`; filesystem/pipe permissions remain part
of the host deployment. Use a product-specific, unpredictable endpoint name, restrict it to the
current account/service identity, and remove stale endpoints during controlled startup.

## Keys and trust

- Generate long-term identity keys with an OS cryptographic provider. Do not store private keys in
  Link configuration, logs, QR codes, discovery metadata, or trust records.
- Prefer the opt-in system keyring store. If the file trust store is used, protect its directory with
  account-only permissions and encrypted storage. Link bounds file size, record count, and fields.
- Pairing requires bilateral transcript confirmation. Discovery candidates are untrusted and never
  become `PeerId` values by discovery alone.
- Rotation raises the accepted key epoch and rejects the old key. Revocation immediately blocks
  trusted reconnect and session resume. Re-pairing an already trusted peer is rejected.
- Back up only according to the product's identity-recovery policy. Link deliberately supplies no
  default export of private key material.

## Ports, firewall, and discovery

Bind remote listeners to the narrowest required address. Open only the configured TCP/UDP port and
restrict source networks where possible. mDNS is opt-in, advertises only protocol version and
transport class, and must not publish user, project, task, role, or credential metadata. Disable
discovery after selection in environments that do not require continuous presence.

Rate-limit connection, discovery, and pairing sources before expensive cryptography. Keep Link's
connection, stream, queue, frame, bandwidth, and trust-record budgets finite. Monitor structured
rate-limit, authentication, version, revocation, and resource-exhaustion errors without logging
proofs, tickets, keys, or full peer records.

## Incident and revocation flow

1. Revoke the affected peer/key in the owner trust authority and persistent Link trust store.
2. Terminate established sessions and reject resume tokens for that identity/epoch.
3. Rotate the local identity if compromise is possible, then distribute the new fingerprint through
   a separately authenticated channel.
4. Review listener exposure, discovery advertisements, and rate-limit telemetry.
5. Require explicit re-pairing; never silently downgrade to a previous key or plaintext transport.
