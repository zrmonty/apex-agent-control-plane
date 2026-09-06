# Managed runtime authority and authenticated registration

This describes the implemented control-plane boundary, not a production Serving
acceptance claim. Container network enforcement, the managed gateway factory,
route activation and end-to-end tracing are separate runtime roadmap gates.

## Three independent identities

The host agent is an enrolled `Agent`, observed over actual mutual TLS. Its
callback names the Controller certificate it observed on the original inbound
operation. The control plane verifies that pair against current protected peer
and installation enrollment, then looks up the exact current leased operation
in PostgreSQL. A caller-provided identity string or synthetic TLS extension
cannot replace the acceptor's TLS evidence.

The gateway is a managed workload, never an Agent or Controller. Its protected
profile selects exact installation/workspace/namespace/proxy/revision and one
fixed evidence actor. Renewal and business RPCs require all three:

- the actual TLS leaf certificate SHA256;
- one Bearer token whose SHA256 matches the enrolled credential pair;
- one 32-byte `apex-instance-proof-bin` value whose SHA256 matches the immutable
  registered process instance.

The end user's MCP subject is separate again. Agent enrollment or a workload
certificate does not establish an MCP user identity or authorize a business call.

## Explicit startup and ownership

`APEX_CONTROL_MANAGED_AUTHORITY_FILE` explicitly enables the managed owner.
It requires PostgreSQL and a private file confined beneath
`APEX_CONTROL_TRUSTED_SECRET_BASE`. Without this setting, managed routes are not
registered. Empty, invalid, missing or unsupported protected configuration fails
startup; there is no token-only fallback.

The registration route additionally requires the existing runtime peer-policy,
runtime enrollment and deployment-bindings settings. Both root-owned services
must be configured; merely enabling workload RPCs does not expose registration.

The synchronous root creates and retains one managed metadata reader and one
bounded physical database worker. Eight active/queued jobs share the database
capacity; cancellation does not release a slot before its physical cleanup.
Profile refresh occurs on its owned reader. Invalid refresh invalidates borrowed
selections, rather than preserving a last-known-good authorization. Metadata age
is measured from read start and must remain below five seconds.

Startup failures and shutdown retain ownership until workers are joined outside
Tokio. No synchronous PostgreSQL owner is moved to an async handler or discarded
because a response deadline elapsed.

## Protected profile document

The strict, duplicate-rejecting JSON document has `schema_version: 1`, a bounded
`version`, canonical positive decimal-string `valid_from_unix_us` and
`expires_at_unix_us`, and at most 64 `profiles`. An empty profile array explicitly
enrolls nobody. Each profile contains:

| Field | Meaning |
| --- | --- |
| `installation_id`, `workspace_id`, `namespace_id`, `proxy_id`, `revision_id` | Exact selector; no wildcard |
| `authority_profile_ref`, `authority_profile_version` | Exact staged transport-profile identity |
| `evidence_agent_id` | Fixed canonical evidence actor for this logical proxy |
| `credentials` | One or two certificate/token SHA256 pairs for bounded rotation |
| optional `launch` | Required to register a new deployment; absence/null does not enroll |

Distinct logical proxies cannot share an evidence actor or the same credential
pair. Rotation within one proxy may temporarily retain two pairs. Digests are
lowercase SHA256 hex; raw credentials and instance proofs do not belong here.

The protected `launch` enrollment contains only `config_hash`,
`host_policy_version`, `deployment_bindings_version`, `image_ref`, `image_id`, and
exactly thirteen ordered `materials` entries. Every material has a canonical
`RuntimeMaterialRole` name, secret reference and immutable version; all roles and
references are unique. Order is significant and must match the original agent
catalog, including when that order is not numeric.

The image reference's manifest digest is not the OCI image ID. Both have distinct
checks: the reference must match the published runtime image and freshly compiled
configuration; the actual attested image ID must match the independently supplied
protected image ID. Neither an image name nor a caller's hash is publication proof.

## Agent-only registration

`RuntimeDeploymentRegistry.RegisterDeployment` accepts a bounded
`CheckRuntimeAuthorityRequest` plus `RuntimeLaunchAttestation`. It does not accept
a caller-provided runtime configuration or raw proof. The canonical request bound
is 24,576 bytes, attestation 16,384 bytes, and receipt 16,384 bytes.

The handler preserves the original tonic transport metadata and extensions when
selecting the nested authority request. Online observation authenticates the
actual agent/controller pair, verifies enrollment and the current lease, and
compiles the runtime configuration from the scoped published revision and the
protected deployment catalog. The leased operation passed into registration is
taken from that actual stored observation, not reconstructed from body claims.

The managed profile then checks installation, scope, revision, original target,
process UUIDv7, profile identifiers, host/catalog versions, image, ordered
materials and fixed health port 8081. It recomputes three distinct hashes:

1. the control spec hash with the publication canonicalizer;
2. the compiled runtime manifest hash;
3. the original launch hash, sorting object keys but preserving array order.

The stage-manifest digest is authenticated agent attestation. The control plane
does not possess or independently read the agent's secret files. Secret-reference
overlap with business materials is refused; proof and manifest digest shapes are
validated without receiving their raw secrets.

One original local request budget, at most five seconds, covers observation,
compilation, queue wait, database work and final handoff. Current authority and
profile selections are rechecked throughout SQL and commit checkpoints. Lease
intervals are compared with local monotonic elapsed time, not cross-host wall
clock subtraction. A late response cannot extend the budget.

## Durable provenance and retry

The registration transaction joins the current fenced operation and scoped
published spec again under the proxy lock. It atomically records the immutable
deployment and `mcp_proxy_deployment_attestations` row. The latter contains the
exact typed attestation bytes, first authenticated authority snapshot, and a DB
registration timestamp. Database triggers reject provenance updates/deletes.

Exact retries preserve original attestation and first provenance. A receipt
contains the immutable binding, SHA256 of the typed protobuf attestation, and a
fresh current authority snapshot for the agent's final version/lease checks. The
fresh response is not a rewrite of the first stored snapshot. Changed attestation
bytes refuse. Existing identities with no provenance cannot be retroactively
blessed through this production callback.

A known registered process may be adopted under a newer controller fence while
retaining its original launch, fence, instance and proof. First registration of an
unknown older launch is refused: the mutable latest-attempt row is insufficient
original launch history. Recovery must not invent history, regenerate a proof
under the same identity, or rewrite the original fence to bypass this restriction.

A successful registration is neither a grant nor readiness nor route permission.
Post-commit cancellation can leave a committed record with an unavailable reply;
the recovery action is exact retry, not replacement. Revocation observed at a
pre-commit checkpoint rolls back both the candidate and its provenance. File
policy and PostgreSQL COMMIT are not one atomic operation: a racing revocation
can leave committed provenance while the final freshness check refuses a reply.

### Explicit agent preparation mode

Authority catalog schema 1 remains dormant and byte-compatible. To request the
authenticated registration callback, use authority catalog schema 2 with exactly
`"mode": "managed_preparation"` on every profile. Missing, null, unknown or mixed
schema/mode values are refused. Update the matching protected launch profile's
authority version as well; an existing immutable instance is not migrated by
rewriting its stage.

In this mode the agent registers only after signature verification, durable
creation, independent stopped-container inspection and a complete sealed-stage
reread. It passes the original Controller request and installed attestation,
then rechecks current policy, operation and its original job deadline. Exact
adoption repeats registration without replacing original proof or provenance.
Registration failure retains the exact dormant resource and recovery record.

This mode does not start a container, assign ingress purposes to workload TLS
materials, claim Ready, select SERVE or publish a route. A separate explicit
ingress profile and the enforced network/factory/lifecycle owners are still
required. The real control-plane/agent acceptance fixture proves sealed-stage
registration and workload PREPARE; its signed external fixture image is not a
signed Apex serving release.

## Workload authority and business calls

`ManagedRuntimeAuthority` exposes `RenewDeployment`, `GetManagedPolicy` and
`CompleteManagedCall`. `ManagedProxyGovernance.AuthorizeManagedCall` performs the
actual scoped Apex policy evaluation and durable call reservation. The managed
root bounds each of these request/reply envelopes to 16,384 bytes.

PREPARE permits non-business preflight without admitting calls. SERVE is a
separate selected-instance state with applied-decision evidence. CLOSED cannot
be reopened by replaying an old grant. Nonces, strictly increasing renewal
sequences and local request-start validity prevent refresh-by-replay.

Policy preflight does not consume business quota. Authorization binds caller,
scope, immutable launch, current policy, declared read-only tool and argument
hash. A denied call gets no reservation. Allowed calls reserve real rate, daily
budget and physical concurrency under the proxy lock; matching cleanup, not
elapsed grant time, releases physical capacity. See
[managed-call-admissions.md](managed-call-admissions.md) and
[managed-serving-registry.md](managed-serving-registry.md).

All these services remain outside the browser RPC allowlist. Workload credentials
do not grant operator commands. Unsupported CLI and approval modes remain refused
until their actual enforcement exists. Do not bypass image verification or enable
container execution merely because these authority component tests pass.
