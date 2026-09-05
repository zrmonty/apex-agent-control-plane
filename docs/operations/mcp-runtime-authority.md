# MCP runtime current-operation callback

`apex.v1.RuntimeAuthorityService.CheckRuntimeAuthority` is a read-only control-plane
callback. It checks an agent's request against current deployment metadata and a
published PostgreSQL operation. It does **not** authorize an engine action, renew a
lease, establish container ownership, or change a proxy to `Serving`.

This covers the Task 7B3B server and 7B3C client slices of the
[working gateway plan](../superpowers/plans/2026-09-04-working-mcp-gateway.md).
The runtime-agent client is implemented and exercised through real authenticated
controller ingress in a test-only probe. A production agent listener and its
provisioning owner remain separate work. Do not enable provisioning on the strength
of this snapshot alone.

## Deployment opt-in

Build `apex-control-plane-api` with `postgres`. Configure the existing control
listener's required client-certificate TLS material and its explicit
`APEX_CONTROL_POSTGRES_URL`. The callback uses that listener, not a new port or a
browser/operator-token route. Add both settings:

```text
APEX_CONTROL_RUNTIME_PEER_POLICY_FILE=runtime/peer-policy.json
APEX_CONTROL_RUNTIME_ENROLLMENT_FILE=runtime/enrollment.json
```

Relative paths resolve beneath the absolute `APEX_CONTROL_TRUSTED_SECRET_BASE`;
absolute paths must remain confined to it. Both variables absent means no callback
route. Partial, empty, invalid-Unicode or non-PostgreSQL configuration fails startup.
There are no fixture defaults or inferred registrations.

The deployment owner must protect each file and all ancestor directories from
untrusted writes. The inherited confinement helper uses check-then-open validation;
it is not a defense against an attacker who can concurrently replace that filesystem.
Files are bounded regular metadata documents, not sources selected by an RPC.
Each is at most 65,536 bytes. Private TLS keys retain the existing stricter secret
permission checks. Remote database connections retain verified TLS; the existing
explicit loopback plaintext exception is only for disposable lab fixtures.

Initial policy/enrollment loading and a dedicated PostgreSQL connection must succeed
before route registration. The root retains both workers through partial startup,
listener-bind failure and shutdown. A failed owner is never restarted in place.

## Trust and request sequence

1. Validate the generated v1 request and its deadline before admission.
2. Select one fresh, immutable peer-policy/enrollment generation.
3. Authenticate the **actual Agent TLS leaf** and resolve the Controller leaf pin
   attested by that agent under the same peer policy.
4. Intersect the pair with explicit installation enrollment and map the controller
   identity to its exact durable-journal worker ID.
5. Enqueue bounded claims for the dedicated PostgreSQL worker. Read the exact current
   operation, lease, desired state, revision publication and configuration hash.
6. Recheck elapsed time, current metadata and the original TLS request at handoff;
   return only the bounded snapshot.

Only the agent is authenticated by the callback connection. The controller identity
is the agent's restricted observation, not independent controller TLS proof on that
connection or an end-to-end signed delegation. A request cannot supply its own worker
mapping, role, database, file path or alternative backend.

The request requires schema version 1, the sole `CHECK_CURRENT_OPERATION` action,
the unchanged six-field `RuntimeTarget`, canonical lowercase UUIDv7 operation,
command and installation IDs, and an exact 32-byte observed-controller SHA-256 pin.
Generation and fencing values are positive and fit a signed SQL bigint. Binary
request and response envelopes are limited to 4,096 bytes; decoding uses the shared
redacted codec. The command ID is correlation data, not journal command authority.

## Deployment documents

The peer policy uses the strict shared `RuntimePeerPolicy` schema: schema version,
immutable version, validity interval, and registered leaf pins with stable identity,
role, revocation and exact installation/workspace/namespace grants. See
[`runtime_peer.rs`](../../crates/apex-auth/src/runtime_peer.rs) and its decoder for
the canonical implementation.

The enrollment document has exactly these seven root fields:

| Field | Required content |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `version` | Immutable deployment version, bounded identifier |
| `peerPolicyVersion` | Exact version of the paired peer document |
| `validFromUnixUs` | Positive canonical decimal string |
| `expiresAtUnixUs` | Canonical decimal string, later than the start |
| `controllers` | Nonempty rows containing only `identityId` and `workerId` |
| `installations` | Nonempty rows described below |

Each installation row contains exactly `installationId`, `agentIdentityId`,
`revoked` (boolean), `hostPolicyVersion`, and `scopes`. Every scope row contains
exactly `workspaceId` and `namespaceId`; tuples are never expanded into a Cartesian
product. Installation IDs are lowercase UUIDv7. Stable identity/version IDs are at
most 128 bytes; scope IDs are at most 256 bytes. Worker IDs use the existing journal
grammar—ASCII alphanumeric plus `_ . : -`, at most 128 bytes—with no normalization.
Controllers and workers form a one-to-one mapping.

Limits are 128 controllers, 128 installations, 64 scopes per installation and 1,024
scopes total. Empty/duplicate collections, duplicate decoded JSON keys, unknown or
missing fields, nulls, wrong types, positional objects, excessive depth (over 32),
invalid UTF-8 and noncanonical numeric strings refuse. Do not hand-author values by
copying test identities or timestamps into a deployment.

Changes replace the entire paired generation; they never merge grants. A changed
document must use a new version. Reusing the most recently accepted version with
different content fails closed, including after a read failure. This local check is
not a global version registry or rollback-protection service. Distribution, rollback
authorization, clock correctness and revocation delivery remain operator-owned.

## Ownership, deadlines and failure behavior

- One fixed-file reader refreshes every second. Maximum local metadata age is two
  seconds, measured from **before** both reads. Missing, malformed, mismatched or
  expired metadata disables admission; fresh valid metadata can recover it.
- One named standard thread constructs, uses and drops the PostgreSQL store. No
  PostgreSQL owner moves through Tokio, and no per-request blocking task is spawned.
- The queue holds at most eight pending jobs, plus one in progress. Queue saturation
  refuses immediately. Admission, dispatch, every query/commit checkpoint and reply
  check cancellation/currentness independently.
- One request budget covers queueing, database work and reply, capped at five seconds
  or the caller's shorter valid gRPC timeout. Expired queued work is skipped. Dropping
  the caller sets cancellation before another query can start at a checkpoint.
- A currently blocked database call remains subject to its transport bounds. The
  next job cannot start until the previous call and transaction cleanup return.
- Startup and shutdown each use one 15-second observation budget. A timed-out
  observation is not a claim that OS I/O was preempted or a thread joined. Handles
  remain on the owner for later observation; dropping an owner only signals stop.
- Incomplete shutdown emits `RUNTIME_AUTHORITY_CLEANUP_INCOMPLETE`, even if a primary
  startup/serving error must also be returned. Diagnostics contain no underlying
  parser, filesystem, SQL or credential details.

Peer denial is `PermissionDenied`; malformed claims are `InvalidArgument`; stale
operation or replaced policy is `FailedPrecondition`; dependency refusal is
`Unavailable`; full queue is `ResourceExhausted`; elapsed requests are
`DeadlineExceeded`. Transport cancellation may reach the caller as `Cancelled`.

## Snapshot and microsecond semantics

The sixteen fields are schema version, target, operation ID, command ID, action,
installation ID, agent identity, observed-controller identity, peer-policy version,
enrollment version, host-policy version, desired state, observed state, configuration
hash, database check time and exact stored lease expiry. No revision specification,
worker ID, raw pin, secret reference or executable permission is returned.

`checkedAtUnixUs` and `leaseExpiresAtUnixUs` preserve uint64 integer microseconds and
serialize as ProtoJSON strings. Their interval is compared conservatively with the
whole local monotonic elapsed request time; remote wall clocks are not subtracted.
This cannot guarantee a lease remains current after the reply. Integer timestamp
precision is not calibrated cross-host clock accuracy or completed end-to-end tracing.

## Runtime-agent client boundary

`apex_proxy_runtime_agent::authority::RuntimeAuthorityClient` owns a bounded mTLS
channel. `connect(AuthorityClientConfig)` accepts only deployment-owned settings:
HTTPS origin, explicit TLS server name and CA, client certificate/key, installation
ID, agent identity, enrollment version and host-policy version. It does not infer
system roots, use proxy environment variables or accept an unchecked caller channel.
PEM inputs are nonempty and at most 65,536 bytes each; the origin is at most 2,048
bytes. Connection setup has a five-second total observation budget.

For each `check`, the production caller must supply the **original tonic request**,
its current `RuntimePeerPolicy`, exact `AuthorityOperation` and remaining budget.
The client authenticates the request's actual Controller TLS leaf for the exact
installation and scope. It derives the pin from TLS, not the request body or headers.
The fresh outbound request carries only bounded operation claims and that pin.
Inbound metadata and credentials are not forwarded.

The client admits at most eight checks per instance and refuses a ninth immediately;
it does not wait for a semaphore slot. Each call has one monotonic budget capped at
five seconds, covering readiness, RPC, decoding, validation and handoff. Cancellation
drops the RPC future and releases the slot; it does not physically preempt a remote
database call. All sixteen snapshot fields are checked against independently expected
values or strict enum/time bounds. The original caller policy is rechecked at handoff.
The policy owner remains responsible for loading and replacing current policy; the
client does not refresh a file or combine metadata generations itself.

Errors expose static `RUNTIME_AUTHORITY_CLIENT_*` codes, without transport sources or
remote messages. A successful `connect` alone is not server acceptance of the client
identity: TLS 1.3 may deliver a server's client-certificate rejection on the first RPC.
No successful check is cached, renewed or converted into a reusable execution permit.

`examples/runtime_authority_probe` is only a cross-process test harness, gated by
`APEX_RUNTIME_AUTHORITY_PROBE=1`. It is not the production runtime agent. The control
test requires `APEX_RUNTIME_AUTHORITY_CLIENT_PROBE` to name the freshly built example
executable. CI obtains that exact path from Cargo's artifact output before running
control-plane tests; missing prerequisites fail, rather than skip, the test.

The next boundary is [restricted provisioning](mcp-runtime-provisioning.md).

## Verification

Required integration fixtures are a disposable PostgreSQL database and the existing
trusted test PKI; absence fails the tests. The CI `test-support,postgres,valkey`
configuration includes read-only bounded scheduling counters to verify zero queue
admission for denied peers and skipped expired queued jobs against the real store.
Those counters and their accessor are absent from normal production builds.

The test suites cover real mTLS/PG requests, unchanged application tables, current
claim failures, revocation on an established channel, missing/malformed-file recovery,
blocked-query revocation, cancellation/rollback, root partial startup, occupied
listeners and cleanup observed while the root subprocess remains alive. Consult the
[runtime evidence ledger](mcp-gateway-runtime-evidence.md) for executed results and
remaining acceptance limits.
