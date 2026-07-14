# Discovery, pairing, and trust

Discovery and trust are deliberately separate. A `DiscoveredPeer` has an ephemeral `DiscoveryId`,
endpoint candidates, service type, and expiry. It never contains or becomes a trusted `PeerId` without
an explicit pairing ceremony.

## Providers and privacy

`ManualDiscovery` is the baseline and needs no background task. QR, invitation, deep-link, or BLE
integrations implement the same `DiscoveryProvider` trait in optional owner crates. The `mdns` feature
adds `MdnsDiscovery`; enabling the feature alone is inert. Only explicit construction starts its
daemon, and only `start` begins browsing.

The mDNS advertisement API accepts service type, opaque instance/host tokens, port, Link protocol
major version, and transport class. It has no free-form TXT map and no fields for user, device detail,
project, task, Worker role, or cluster. Manual and mDNS requests are bounded by `RateLimit` and return
structured `RateLimited` errors.

## Headless ceremony

`PairingSession` is a command/state machine with bounded events. A UI, CLI, LiliaCode client, or
DistributedHost management tool may render `PairingPresentation` and submit confirm/reject/cancel/tick
commands; the library opens no window, reads no product configuration, and never auto-confirms.

The transcript binds both long-term `PeerId` values and public keys, negotiated Link protocol version,
pairing method, and caller-supplied random challenge. The six-digit short code is derived from that
transcript. `PairingCrypto` requires the identity owner to sign and verify the transcript; the pairing
crate does not ship a fallback signature scheme. `ReplayGuard` rejects a reused challenge, deadlines
produce `TimedOut`, and `PairingAttemptLimiter` independently bounds attempts and failures.

The first-pairing Link handshake exposes only a minimal public pairing namespace. Sensitive application
protocol catalogs and business channels remain unavailable until a trust record authorizes a later
trusted reconnect.

## Trust persistence

`TrustRecord` stores peer identity/public key, user-visible alias, first-pairing timestamp, Link-level
permission summary, key state, last challenge hash, and previous key fingerprints. It has no cluster
membership, Worker role, scheduling, task, or resource authority.

`FileTrustStore` is an explicit development backend using a bounded JSON file (mode 0600 on Unix) and
temp-file replacement. The `system-keyring` feature adds `SystemKeyringTrustStore` backed by macOS
Keychain, Windows Credential Manager, or Linux keyutils. Plain `pairing` does not pull those platform
backends.

Deleting a peer removes authorization. Revocation keeps an auditable terminal key state. Rotation marks
the old identity as `Rotated`, inserts the new active identity, and carries forward alias, Link
permissions, first-pairing time, and previous fingerprints. `authorize_trusted_reconnect` accepts only
an active record whose public key exactly matches; deleted, revoked, rotated, or mismatched identities
fail structurally and cannot silently reconnect.
