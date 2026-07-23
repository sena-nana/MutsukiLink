# Architecture and ownership boundary

MutsukiLink owns only reusable connection mechanics:

```text
application protocol (LiliaCode, DistributedHost, another application)
        |
        v
authenticated Link session + namespaced channels
        |
        v
optional discovery / pairing / transport implementations
```

Dependency direction:

```text
mutsuki-link-core <- optional link transport/discovery crates <- application adapters

MutsukiCore --------X--------> MutsukiLink
business plugins ---X--------> MutsukiLink transport
MutsukiLink --------X--------> MutsukiCore / ServiceHost / DistributedHost
```

`MutsukiLink` is the formal repository and crate family name. “connection runtime” or “reusable
connection library” describes its role; `LinkSDK` is not a repository or published crate name.

## Link responsibilities

- peer discovery candidates and explicit endpoint selection;
- first-use pairing and long-term peer identity;
- authenticated connection/session lifecycle;
- reconnect, quality summary, bounded multiplexed channels;
- generic transport and upper-protocol negotiation;
- optional multi-peer session orchestration (`mutsuki-link-runtime` / `PeerSessionPool`), without
  interpreting application payloads.

Multi-peer connection indexing is an opt-in runtime concern. `mutsuki-link-core` remains
single-session and runtime-neutral; hosts that need one local endpoint to many remote peers enable
the `runtime` feature and authenticate before `admit_inbound`. Details:
[runtime pool](./runtime-pool.md).

## Upper-layer responsibilities

LiliaCode owns its command, debug, file, event, and stream messages. MutsukiDistributedHost owns
cluster control, execution assignment, scheduling, task recovery, resource movement, and trust
policy. ServiceHost owns its local process and Core lifecycle.

Link therefore does not understand tasks, Workers, leadership, consensus thresholds, resource
replication, scheduling, or failover. It never passes a connection object into a business plugin and
never changes ordinary Runner/Host authoring when enabled or disabled.

## Zero-activity default

`mutsuki-link-core` has no features and no dependencies. The aggregate `mutsuki-link` default
feature set only re-exports core. Concrete transport and discovery crates are opt-in and must not
initialize listeners, scanners, runtime drivers, or background work until an application explicitly
constructs and starts them.
