# Durable managed runtime execution (Task 3B)

The control plane accepts management changes durably and reconciles them through
the separately deployed runtime agent. This slice deliberately cannot start a
container, publish a route, admit traffic, or report a runtime Ready. A successfully
created dormant container remains NotServing until the Task4 execution boundary.

## Management contract

DeployProxy, ResumeProxy, PauseProxy, RetireProxy, RotateProxyCredentials and
RollbackProxy each retain their existing response fields and add `operation` at
field2. The response means atomic durable acceptance, not physical completion.
The existing lifecycle wire has no Pausing: pending pause uses Provisioning;
retirement uses Retiring. Only an authenticated, exact-claim Paused or Retired
execution response moves the projection to that terminal state.

GetProxyOperation requires the authenticated exact workspace/namespace/proxy
scope and operation UUID. Missing or foreign-scope operations return a static
NotFound; absent managed PostgreSQL authority returns FailedPrecondition.
Generated JSON represents generation, fencing tokens and all other uint64 values
as strings. Browser method allowlists are unchanged.

Retry the identical management request with the original request UUID. Actor,
action, reason, source/expected/rollback revision and rotation-reference set are
part of durable semantics. An exact retry returns the frozen original acceptance
even after later generations; changed semantics conflict. Storage unavailability
returns Unavailable, not malformed-input InvalidArgument. Revision/idempotency
conflicts return Aborted. No network or engine effect occurs inside acceptance.

Authenticated subjects retain the existing bounded string contract (up to256
bytes); managed evidence hashes the actor identifier while lifecycle history
retains the exact authenticated subject. Reason codes deliberately retain the
existing durable lowercase code grammar:1..128 bytes, first character lowercase,
remaining lowercase ASCII letters, digits, `_`, `.`, `-` (not arbitrary text
and not the worker identifier grammar).

The flat rotation API cannot express a multi-domain old-to-new mapping. This
implementation requires exactly one distinct existing outbound credential domain
and one replacement reference, then rewrites only matching existing occurrences
in upstream credential/ref lists, CLI refs and outbound auth bindings. It does
not populate empty lists or change subjects, scopes or unrelated fields. Multiple
old domains or replacement refs fail atomically; no lexical-order mapping exists.
Prior published revisions remain immutable. Rollback selects an eligible published
historical revision as a new desired generation, never historical readiness.
Pause/Retire cleanup of owned history does not require that the old revision pass
today's new-publication capability gate; exact history/hash/fence checks remain.

After a managed generation exists, draft publish/validate must not move current
desired authority. Validation is read-only; legacy lifecycle/retire mutations
refuse managed resources. `active_revision_id` is the current DESIRED revision,
not proof of the installed or serving revision. Evidence keeps exact current
claims separate from the immutable installed target and original launch fence.

## Deployment-owned configuration

Build control-plane-api with `postgres`. Set
`APEX_CONTROL_RUNTIME_EXECUTION_CONFIG_FILE` to a protected JSON file under
`APEX_CONTROL_TRUSTED_SECRET_BASE`. PostgreSQL, runtime peer policy, enrollment
and deployment bindings must already be configured. Example shape (deployment
must supply its actual paths, identity, endpoint and certificates):

```json
{
  "schema_version": 1,
  "installation_id": "0191b7f1-7f2c-7c13-9a61-2f29f2be1001",
  "worker_id": "controller-a",
  "endpoint": "https://runtime.example:8443",
  "server_name": "runtime.example",
  "ca_file": "runtime-ca.pem",
  "client_cert_file": "controller.pem",
  "client_key_file": "controller.key",
  "scopes": [{"workspace_id": "workspace", "namespace_id": "namespace"}]
}
```

The parser rejects unknown or duplicate fields, unsupported versions, empty or
duplicate scope sets, more than64 scopes, noncanonical installation UUIDv7,
worker IDs over128 bytes, endpoints over512 bytes, non-HTTPS origins, userinfo,
query/fragment or non-root paths. Worker IDs allow ASCII alphanumeric `_ . : -`.
TLS server names are bounded at253 bytes and are verified by TLS, with the exact
configured CA and client certificate/key; there is no insecure or ambient
credential fallback. All material files are bounded at65536 bytes and confined
to the absolute trusted base. Config/key private permissions are checked through
the existing platform loader. Symlinks and unsafe Unix ancestors/owners refuse.

The enrolled worker must belong to this installation and every selected scope.
The agent authenticates the controller role over real mTLS; its callbacks use
the distinct agent role and current-operation authority. Operator tokens do not
grant either role. No endpoint, filesystem path or transport override is accepted
from management callers. See [agent ingress configuration](runtime-reconciliation-ingress.md)
for the independently protected agent configuration and role policy.

Configuration and TLS material are fingerprinted and rechecked before dispatch,
inventory and observation. Replacement or invalid permissions stop dispatch and
latch the owner unhealthy; restart is required to adopt a new transport generation.
An absent execution file keeps execution unavailable/NotServing. An invalid
configured file fails startup. The obsolete
`APEX_CONTROL_MCP_PROXY_RUNTIME_NETWORK` variable always refuses, even when empty;
production cannot select the legacy direct-Docker provider.

## Ownership, budgets and recovery

The root retains eight physical worker threads plus one bounded keyset scanner,
their channels and PostgreSQL resources through real shutdown and partial startup
failure. Dispatch activates only after the callback listener is bound and its
server task can serve. PostgreSQL runs on physical owners, not Tokio workers.

| Boundary | Fixed limit |
| --- | --- |
| Global admitted jobs / exact-proxy jobs per process |8 /1, including queued jobs |
| Inventory page / selected scopes |8 /64 |
| Whole job from original admission |150s |
| Database lease |180s; local monotonic anchor before acquisition |
| Connect / individual execution RPC |5s /120s, shortened by original remaining budget |
| RPC phase end |at most admission+125s, reserving observation time |
| SQL statement / lock wait |5s /2s |
| Request / response |4096 /16384 bytes |
| Authenticated authority-refusal retry |max3 total calls,250ms spacing, same command/budget |
| Finished authenticated nonterminal cooldown |30s, counter retained |

A reporting timeout does not free physical capacity while SQL or cleanup remains
owned. Unknown transport completion records uncertainty only under a current live
fence; it does not retry automatically within that job. Only the authenticated
explicit `RUNTIME_AUTHORITY_REFUSED` Unavailable outcome permits the bounded
same-command retry. Uncertainty keeps the180s lease. Completed authenticated work
can shorten its lease without decrementing the fencing counter. Other replicas
still use the authoritative database lease and the agent's exact-proxy owner.

Each proxy's persisted UUIDv7 allocator strictly increases above its last command
even after restart, replica clock skew or a higher-fence takeover. Same-attempt
retries preserve the exact command/request bytes. UUID timestamps are not lease
authority. Final database expiry is sampled again after observation mutations and
on exact-event retries, immediately before commit. Terminal current-operation
callbacks end; Task4 needs a separate deployment-renewal boundary, not artificially
nonterminal cleanup operations.

Execution health at `apex.v1.McpProxyService.RuntimeExecution` requires live
inventory and a recent authenticated response, and latches NotServing on owner
stop. It does not imply container readiness. The legacy proxy serving health
remains NotServing in this slice.

## Additive schema and limits

`deploy/postgres/mcp_proxy_managed.sql` is applied under the existing schema
advisory lock. Schema marker version1 accompanies immutable acceptance snapshots
(each at most524288 bytes) and one current attempt/floor row per exact proxy.
Attempt rows hold bounded request/response bytes, original outcome/uncertainty
event IDs and real event time. Database triggers prevent acceptance mutation,
allocator reset/deletion or decreasing command/fence on handoff. Existing empty,
newer, partial or unversioned managed schemas refuse instead of silently migrating.
Apply only to an existing supported proxy/operation schema or a fresh database;
do not drop/reset floors to repair deployment failures. Existing operation/evidence
history is intentionally durable; this slice adds no history-retention deletion.

## Acceptance scope

The Task3B joint fixture uses separate production CP/agent binaries, actual
PostgreSQL and mTLS callbacks, public Cosign signature verification, protected
staging and Docker Created/network-none containers in two scopes. It tests exact
acceptance retry, operation queries, wrong role/hash/stale refusal, restart and
higher-fence adoption, pause and isolated retirement. The public signed Cosign
image is only a provisioning fixture, not an Apex gateway release. The fixture
does not configure NATS; committed evidence intents are not proof of trace fanout.
Task4 Start/readiness/network/route/admission and end-to-end browser serving remain
separate gates. Component timeout/overload/shutdown tests do not substitute for
the actual joint test.
