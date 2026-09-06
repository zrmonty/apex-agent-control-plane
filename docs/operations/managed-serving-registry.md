# Private managed deployment registry

This PostgreSQL data seam does **not** enable serving. It has no RPC, listener,
credential enrollment, service owner, container effect, or route publisher.
All inputs are claims and metadata. Constructing its Rust types establishes no
authenticated principal. Only main's later bounded physical worker may call
the synchronous methods; never execute them directly on a Tokio task.

## Storage and bounds

`deploy/postgres/mcp_proxy_serving.sql` is additive schema version 1, applied
under the existing proxy schema advisory lock. Empty, newer, partial-table or
unversioned existing registries refuse startup. The desired pointer remains
`mcp_proxies.active_revision_id`. A separate per-proxy selection row holds the
installation, selected instance and positive signed-BIGINT epoch. Its identity
cannot change or be deleted, and its epoch cannot decrease or change selection
without increasing. A partial unique index permits at most one SERVE instance.

Deployment identity, configuration bytes, original operation, profile ref/version
and 32-byte proof SHA256 are immutable. No raw proof is stored. CLOSED identities
are permanent tombstones; termination cannot be undone. Maximum stored protobuf
sizes: binding 4096 bytes, configuration 262144, readiness 16384, renewal request
8192. There are at most 16 non-CLOSED registrations per proxy and at most 64
issued decisions per instance. Historical deployment tombstones are retained;
this is not a global database-size or history-retention policy.

## Private APIs

Methods and data types live in `proxy/store/postgres/serving.rs`. Main must add
crate-private reexports through the currently private `store`/`postgres` module
boundary when it integrates the service; this sidecar's write scope excludes
those parent modules.

- `register_deployment_checked(lease, registration, check)` validates the exact
  current stored operation and controller lease while holding the scoped proxy
  row lock. It joins the published revision, verifies the canonical spec hash,
  exact configuration scope/proxy/revision/generation/spec and manifest hash,
  and preserves the existing publication capability refusal. It creates PREPARE.
  Exact retry preserves all original bytes; changed proof/config/profile/binding
  refuses. Configuration integrity is not protected deployment compilation.
- `read_deployment_checked(binding, check)` returns exact stored registration,
  selection/epoch, sequence and applied-decision metadata for main's verifier
  and projection. It deliberately returns no `routable` or `authorized` verdict.
- `record_candidate_readiness_checked(lease, binding, observation, check)` requires
  a live current PREPARE candidate, an unexpired applied PREPARE decision, all
  nine distinct PASS/OK checks, exact original target/config/manifest/launch/
  process identity, live/ready, not admitting and zero physical calls. At most
  32 stages may accompany the bounded report. The returned observation UUID
  expires at the earlier of five seconds of DB time and the applied PREPARE's
  expiry, and is bound to the current controller fence. Main still authenticates
  the actual probe and rechecks its original local monotonic freshness.
- `withdraw_deployment_checked(lease, binding, reason, check)` takes the typed
  reason Replacement/Pause/Retire. Replacement closes the exact selected old
  identity while preserving prepared candidates. Pause/Retire require that
  current desired state and close every preparation/selection. Withdrawal
  advances the epoch when it changes grants and never restores an old grant.
- `select_candidate_checked(lease, binding, observation_id, check)` requires
  exact fresh readiness under the current operation/fence, no current selection,
  and no unresolved old SERVE, admission, or physical work. Every previously
  issued SERVE must be followed by an exact applied CLOSED decision with zero
  calls, or independently verified termination of that exact instance. Expiry
  is never drain proof. Selection advances the epoch and consumes readiness.
  A committed selection does not itself publish a route; main must observe a
  later applied, current, still-valid SERVE acknowledgment before routing.
- `record_deployment_termination_checked(lease, binding, check)` records main's
  independently verified exact termination, closes that instance and clears its
  physical count. It performs no inspection or kill and releases no business
  reservation from a different accounting system.
- `renew_deployment_checked(request, check)` is independent of terminal lifecycle
  operations/controller leases. Old selected SERVE can coexist with a different
  desired candidate while desired state remains Serving and the old publication
  independently remains eligible. Candidate PREPARE must still match the desired
  target. Observing a persisted Pause/Retire closes all grants in a successful
  renewal transaction even before explicit lifecycle withdrawal is called.

## Renewal replay and acknowledgment

Use the canonical `ManagedDeploymentRenewal` and `ManagedDeploymentGrant`.
`renewal_sequence` must be positive and fit signed SQL BIGINT. The instance's
durable highest sequence never decreases. New sequences may skip numbers after
local failure; resetting the sequence under an existing process identity refuses.
A new process requires a new immutable instance; adoption must not restart it.

An exact retained sequence, 32-byte nonce and acknowledgment request returns the
same decision identity, epoch and mode with **remaining DB validity**, never a
new ten-second interval. Expired/pruned sequences at or below the high-water mark
refuse. Changed request semantics conflict. A stricter conservative rule, agreed
with main: even a retained exact retry refuses if its original epoch/mode no
longer matches current deployment state. The client closes admission on refusal
and can send a higher sequence to obtain CLOSED. This never renews withdrawn
SERVE. No probabilistic nonce filter, nonce exhaustion, or lifetime request cap
is used; sequence exhaustion at signed-BIGINT maximum refuses further issuance.

Every decision is UUIDv7 and has a DB interval of at most 10,000,000 microseconds.
The echoed sequence/nonce/binding remain exact. The client must measure validity
from its **original local request start**, not receipt or remote wall-clock
subtraction. Server checks validity again after SQL and immediately before
commit. All methods retain the caller's original cancellation/deadline/policy
callback before and after physical SQL and commit. An error after commit is an
uncertain reply, not proof of rollback; recover with exact retry or a fresh
sequenced request and inspection of persisted state.

Acknowledgments must name an issued decision of this exact instance and epoch.
Unknown, future, foreign and malformed acknowledgments refuse. Only SERVE may
acknowledge admitting=true. Older known decisions cannot rewind applied progress
or physical counts. The last acknowledged decision stays pinned, with the 63
newest other decisions; without an acknowledgment at most 63 are retained. Thus
lost replies do not evict the client's last accepted-and-acknowledged decision.
An expired retained decision may still acknowledge actual application/cleanup.
Never infer closure from a CLOSED decision preceding any newer SERVE issuance.
Physical counts survive grant expiry, withdrawal, connection loss and restart.

## Remaining integration

Main owns real agent authentication and digest-only launch attestation; protected
deployment compilation and image/material/profile matching; exact workload
mTLS/token/instance-proof verification; fresh policy and credential checks before
and after this seam; bounded physical admission/SQL workers; and shutdown.
The metadata read contains credential-binding material and must not be exposed
through browser/operator RPCs or logs. The store does not validate arbitrary
caller configuration as an authenticated deployment profile.

First enrollment currently requires original launch fence == current live fence.
Higher-fence adoption of an already registered exact instance preserves the
original launch and operation. First enrollment after handoff remains unavailable
without durable original attestation. `runtime_attempts` stores only the latest
request and overwrites it/clears response on handoff; the accepted operation
proves generation/revision but does not contain a historical launch fence.
An unknown older or legacy no-proof runtime never auto-enrolls.

Business-call policy/rate/budget/concurrency reservations and physical completion
accounting, network confinement, actual readiness probing, route withdrawal and
publication after applied SERVE, runtime startup, service/root wiring, and joint
serving acceptance remain separate work. Windows component tests and real PG
semantics here do not prove those boundaries or Linux container serving.
