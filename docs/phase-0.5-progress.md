# Phase 0.5 progress

**Status: every item below shipped and gated in CI -- but the gateway does not yet do what it exists to do.** A 2026-08-08 investigation found that no code path anywhere in this repository lets an agent receive a command an operator submits: [`control.proto`](../contracts/proto/apex/v1/control.proto) defines only `SubmitCommand`, one direction, operator to gateway, and nothing on the SDK side polls, subscribes, or otherwise consumes one. `stop`/`pause`/`resume`/`inject`/`set_budget` are durably accepted, authenticated, and recorded into the queryable trace; none of them currently change what a running agent does. Full evidence and analysis: [OOB Control Gateway — Command Delivery Gap](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/05%20Research/OOB%20Control%20Gateway%20%E2%80%94%20Command%20Delivery%20Gap.md). **Everything else in this document describes the gateway's accept/durability/auth/transport path accurately and remains true; read "operationally complete" anywhere below as scoped to that path, not to an operator's ability to actually control a running agent.**

Phase 0.5 delivered the out-of-band (OOB) control command gateway per [ADR-0006](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/06%20Decisions/ADR-0006%20OOB%20Control%20Gateway%20Moved%20to%20Phase%200.5.md) and [ADR-0005](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/06%20Decisions/ADR-0005%20Cooperative%20V1%20Controls.md). The control/durability/auth logic shipped and was pen-tested first; a second pass then made the gateway an actually-deployed service with its own transport boundary, which is what makes ADR-0006's independence claim operational rather than structural; a third pass closed the two gaps that deployment surfaced -- accepted commands were never delivered onward, and `--features postgres` did not actually select the Postgres outbox. A fourth pass closed the last two open items: production operator credentials are now verified against Keycloak, and the per-operator admission ceiling holds across replicas instead of multiplying by the replica count.

Every requirement below is exercised by a live gate in `.github/workflows/live-mtls-e2e.yml` against real containers -- not only in-process. See "Honest final assessment" at the end for the two things that remain true and are *not* claimed, and see the status line above for the one that supersedes everything else in this document.

## What shipped

A new crate, `apps/control-plane-api` (`apex-control-plane-api`), exposes the five cooperative v1 controls -- `stop`, `pause`, `resume`, `inject`, `set_budget` -- behind a single tonic gRPC RPC, `ControlGateway.SubmitCommand` (`contracts/proto/apex/v1/control.proto`), served over mTLS from its own container.

| Requirement (ADR-0006) | How it is met |
|---|---|
| Durable command outbox | Reuses `apex-event-ingest`'s `EventOutbox` trait and implementations (`InMemoryOutbox`, `FileOutbox`, `PostgresOutbox` under `postgres`) via `apps/control-plane-api/src/outbox.rs`. No forked durability story. |
| Independent authentication from the ingest/data path | `apps/control-plane-api/src/auth.rs`: a distinct `OperatorCaller`/`OperatorCredentialResolver`/`OperatorTokenAuthenticator` stack with its own credential type, its own token table, and its own auth-failure rate-limit buckets -- structurally separate from `event-ingest`'s `Caller`/`BearerTokenVerifier`. An ingest workload token is not accepted here and vice versa. |
| `control` event emission | `apps/control-plane-api/src/envelope.rs` builds a validated `EventType::CONTROL` envelope and hands it to `apex_event_ingest::IngestRequest::from_validated_transport` -- the same admission gate (identifiers, RFC 3339 timestamp, RFC 8785/JCS integrity hash, `control` action schema in `validation/control.rs`) the ingest data path enforces. It is never bypassed. |
| Cooperative-only semantics (ADR-0005) | The gateway only ever durably records a command for the instrumented runtime to observe; it has no code path that terminates, suspends, or otherwise reaches into a process. |
| Reachable when the primary data path is degraded | `submit_command` (`outbox.rs`) never calls a publisher on the accept path -- a command is durable, and the RPC returns success, the moment the outbox commits the row. Fanout to JetStream/ClickHouse is a separate, best-effort, retrying background loop (`replay.rs::spawn_fanout_worker`) that drains pending rows once the primary path is reachable again. `ControlCommandResponse.delivered` reports whether fanout has completed yet without ever blocking acceptance on it. Proven live under a real broker outage -- see "Command delivery" below. |
| Commands are actually delivered, not just recorded | `startup/fanout.rs` builds an `EventPublisher` and hands it to `spawn_fanout_worker` in the running binary, so an accepted command becomes a `control` event in the queryable trace. See "Command delivery" below. |
| Multi-writer durable outbox | `startup::service::open_outbox` selects `apex_event_ingest::PostgresOutbox` under `--features postgres` and `APEX_CONTROL_POSTGRES_URL`, and the file outbox otherwise. See "Outbox backend selection" below. |
| Deployed as its own service | `apps/control-plane-api/Dockerfile` plus `control-plane-api` service blocks in `deploy/compose/compose.yaml` and `deploy/compose/compose.gateway-ref.yaml`. Its own image, its own runtime uid (10002, not the ingest gateway's 10001), its own port, its own TLS material, its own operator credential table, and its own outbox volume. See "Containerization" below. |
| Its own transport boundary | Native mTLS via `tonic::transport::ServerTlsConfig` in `src/startup/service.rs`, client certificate mandatory. See "Transport security" below. |
| Production operator identity | `src/keycloak.rs`: `KeycloakOperatorCredentialResolver` verifies short-lived, scope-bound credentials Keycloak issued via RFC 8693 token exchange, per [[Authentication and Identity]]. Selected by `APEX_CONTROL_KEYCLOAK_ISSUER`; `StaticOperatorTokenResolver` is unchanged and remains the local/lab and CI seam. See "Keycloak operator credentials" below. |
| Admission control that means the same at N replicas as at one | `src/service.rs` takes an optional `apex_event_ingest::EphemeralStore` (reused, not forked) behind `APEX_CONTROL_VALKEY_*`, with the process-local ceiling retained as the hard floor. See "Cross-replica admission" below. |

## Containerization

`apps/control-plane-api/Dockerfile` mirrors `apps/event-ingest/Dockerfile`, including the two failures that Dockerfile's comments record, both of which would have reappeared here verbatim:

- `ARG BUILD_IMAGE` / `ARG RUNTIME_IMAGE` are declared in **global** scope, before the first `FROM`. A stage-scoped `ARG` is invisible to a later `FROM`, which then expands to the empty string and fails with "base name should not be blank".
- The build context is the **repository root**. `build.rs` compiles `contracts/proto/apex/v1/control.proto` from outside the crate directory, and this crate additionally has a path dependency on `apps/event-ingest`. `deploy/postgres` is copied for the same `include_str!` reason it is copied for `event-ingest`: `--features postgres` forwards to `apex-event-ingest/postgres`, which compiles those `.sql` files into the binary.

Two decisions specific to this service:

- **Runtime uid 10002, not 10001.** ADR-0006 requires this service to be independently authenticated from the ingest data path. Sharing the ingest gateway's uid would leave that boundary visible only in application code -- at the OS layer, one container's compromise would already hold the other's file-level identity on any shared mount or volume. `deploy/compose/preflight.sh`/`.ps1` now check secret ownership against the *correct* uid per secret; a file chowned to the other service's uid is exactly as unreadable as one left owned by root.
- **`/var/lib/apex-control` and `/var/lib/apex-control-secrets` are created in the image**, owned by 10002. Docker initialises a fresh named volume from the image content at the mount point; when the path does not exist in the image it creates the volume root `root:root 0755` instead, and a non-root container cannot write to it. That is the exact `EACCES`/`INVALID_OUTBOX_CONFIGURATION` failure that hit `event-ingest` on every fresh deployment before its Dockerfile grew the same `install -d` step.

The Compose service matches `ingest-gateway`'s posture exactly -- `no-new-privileges:true`, `cap_drop: [ALL]`, `read_only: true`, `tmpfs: [/tmp]`, and `${VAR:?...}` fail-closed interpolation on the image and every secret -- and is slightly stricter in the `gateway-ref` profile, where the ingest gateway's block leaves the root filesystem writable and this one does not.

Deliberate differences from `ingest-gateway`:

- **No `depends_on`.** A command is durable the moment its outbox row commits, so this gateway must start and accept commands while JetStream/ClickHouse/the archive are down. A dependency edge would reintroduce exactly the coupling ADR-0006 exists to remove.
- **A separate outbox volume** (`control-outbox`, not `ingest-outbox`), per the code's own constraint: the two services must not share a durability boundary any more than they share auth.
- **The operator credential table is a file secret, never an `environment:` value.** Compose environment is readable through `docker inspect` and `/proc/<pid>/environ`, and these tokens authorize `stop`/`pause`/`inject` against live agents. `APEX_CONTROL_OPERATOR_TOKENS_FILE` was added for this; the inline `APEX_CONTROL_OPERATOR_TOKENS` remains for local/lab and CI. Setting both is a hard startup error rather than a precedence rule, since two configured credential sources means one is being silently ignored.

## Transport security

`src/startup/service.rs` terminates mTLS natively:

```rust
ServerTlsConfig::new()
    .identity(Identity::from_pem(server_cert, server_key))
    .client_ca_root(Certificate::from_pem(client_ca))
    .client_auth_optional(false)
```

**TLS is mandatory, with no plaintext or optional-client-auth mode.** This mirrors `event-ingest`, which has no such fallback either -- all three of its TLS paths are `required()` and its `client_auth_optional(false)` is likewise explicit, so that a tonic upgrade cannot make client certificates optional by changing a default. There is no "lab mode": local and CI use is served by the real PKI under `deploy/compose/live-mtls/`, so adding a plaintext bypass here would have invented a weaker mode that exists nowhere else in this repository. A deployment that still wants a terminating proxy in front of this process gets one; it simply speaks mTLS to the process behind it rather than plaintext.

Cert/key/CA material is read the same disciplined way `event-ingest` reads its own: bounded reads, paths canonicalized and confined under `APEX_CONTROL_TRUSTED_SECRET_BASE`, symlinks refused, and the shared `apex_event_ingest::permissions` private-key permission check applied to the server key and the operator token table.

**The loopback-only bind default and its `APEX_CONTROL_ALLOW_NONLOCAL_BIND` escape hatch were kept, deliberately.** Their original justification (the process served plaintext) is gone, but the replacement is stronger: this is the one surface that can `stop`, `pause`, or `inject` into a running agent, and widening its listener beyond loopback should be something an operator typed rather than a default that survives a copied `.env`. TLS protects bytes on the wire; it does not make "who can reach this socket at all" a non-decision. It also mirrors the acknowledgement the ingest profile has always required (`APEX_ALLOW_NONLOCAL_INGEST_BIND`) for a gateway that was never plaintext, so this is the established pattern here rather than an artefact of the plaintext era. What did change is the remediation text: the old message told operators to put a TLS-terminating proxy in front of the process, which is now actively wrong advice. `APEX_CONTROL_BIND` additionally gets its own preflight acknowledgement (`APEX_ALLOW_NONLOCAL_CONTROL_BIND`) rather than reusing the ingest one -- agreeing that ingest may be reached off-host is not the same decision as agreeing to it for the control channel.

## Command delivery

`replay.rs::spawn_fanout_worker` shipped implemented, unit-tested and exported -- and unreferenced by the binary. The deployed container durably enqueued every accepted `stop`/`pause`/`inject`/`set_budget` and then left it in the outbox forever: `delivered` was permanently `false`, and no `control` event ever reached ClickHouse. The command was recorded but not observable, which is most of the point of recording it. `startup/fanout.rs` closes that.

The publisher stack is `event-ingest`'s, unmodified and unforked: `AsyncNatsJetStreamClient` -> `NatsJetStreamTransport` -> `RetryingJetStreamTransport` -> `JetStreamPublisher`, the same four layers `apps/event-ingest/src/startup/service.rs` composes. Three decisions are specific to this service:

- **The connection is lazy, and that is the load-bearing difference.** `event-ingest` connects to NATS during startup and refuses to come up if it cannot; for the ingest data path, a gateway that cannot publish should not be accepting. Doing the same here would make JetStream a startup dependency of the control channel -- exactly the coupling ADR-0006 removes, and the reason both Compose profiles deliberately give this service no `depends_on: jetstream`. So *configuration* is validated eagerly at startup (`NatsTlsConfig::validate`: path confinement under `APEX_CONTROL_TRUSTED_SECRET_BASE`, symlink refusal, private-key permissions -- all local filesystem work, no socket), while the *connection* is established on the worker's first tick and rebuilt by the client itself thereafter. A misconfigured broker client fails startup loudly; an unreachable one defers delivery and nothing else.
- **Its own NATS client leaf and its own broker account** (`control-nats-client`, user `control-publisher`), never the ingest gateway's. ADR-0006's credential separation has to hold at the broker too, or "independently authenticated" stops at the gRPC edge and either service's compromise hands over the other's publish rights. `live-mtls/render_configs.py` grants the control account strictly less than the ingest publisher: `publish: ["apex.events.>"]` and `subscribe: ["_INBOX.>"]`, with no `$JS.API.>`, since this service never creates or manages a stream. Verified live with exactly those grants.
- **Tick interval: 5s** (`APEX_CONTROL_FANOUT_INTERVAL_SECS`, 1..=3600), matching `event-ingest`'s own outbox replay worker. Not faster because `ControlOutboxBackend` serialises every outbox operation behind a single `Mutex` that `submit_command` also takes, so sub-second polling would buy milliseconds of delivery latency at the cost of contending with the one path ADR-0006 requires to stay available -- and would turn a broker outage into a connect-attempt storm. Not slower because `delivered` and the queryable `control` event are how an operator confirms a `stop` reached the trace.

Two runtime hazards were found by running the real container, not by any in-process test:

- `AsyncNatsJetStreamClient::connect` bottoms out in `Runtime::block_on`, which **panics** on a thread that already has a tokio runtime entered -- and the worker is a tokio task. The connect therefore runs on a plain scoped thread, wrapped in `block_in_place` on a multi-thread runtime so a broker outage cannot stall the accept path. `startup/tests.rs::lazy_jetstream_publisher_connects_without_panicking_inside_the_worker_runtime` drives that path on a real multi-thread runtime against a dead broker, so a regression fails as a panic rather than only in the container.
- The same hazard, found later and only on the first Postgres-backed container start: `PostgresOutbox` drives the `postgres` crate's internal runtime and `block_on`s it on *every* query, so the worker's own `pending()`/`mark_complete()` calls aborted the worker task on its first tick. The process stayed up and kept accepting commands, so the container looked healthy while nothing was ever delivered again -- the same silent failure mode as never having wired the worker in at all. `ControlOutboxBackend::with_lock_from_async` is the fix (the accept path already went through `spawn_blocking`); `replay.rs::fanout_worker_survives_an_outbox_that_blocks_on_its_own_runtime` reproduces it with an outbox that blocks on its own runtime exactly the way `postgres::Client` does.

`startup::service::run` and `main` are consequently **synchronous**, no longer `#[tokio::main]`, matching `event-ingest`'s own `run()` and its stated reason: clients constructed during startup own internal runtimes and block on them, so construction must not happen on a runtime thread. The serving runtime is built at the end, once construction is complete.

## Outbox backend selection

`open_outbox()` unconditionally built a `FileOutbox`. `--features postgres` therefore changed nothing about the running binary -- it only forwarded the feature to `apex-event-ingest` -- so a deployment that believed it had a multi-writer backend had a single-writer file. It now branches the same way `event-ingest`'s `open_durability_stores` does: a URL selects Postgres, its absence selects the file backend, and a URL on a binary built without the feature is a hard startup error rather than a silent downgrade.

**`APEX_CONTROL_POSTGRES_URL` is this crate's own variable, and it must resolve to a database or schema of the control gateway's own.** `apex_event_ingest::PostgresOutbox` hardcodes the table name `apex_event_outbox` (`deploy/postgres/outbox.sql`), so two services pointed at one database share one outbox table -- and that is not a cosmetic overlap. `event-ingest`'s replay worker claims pending rows with `FOR UPDATE SKIP LOCKED` and fans them out through *its* sinks, so it would claim and republish control commands; this crate's fanout worker would likewise claim ingest events and republish them. Setting `event-ingest`'s `APEX_POSTGRES_URL` on this process is refused outright rather than honoured. This is the Postgres equivalent of the separate `control-outbox` volume the file backend already gets. *Flagged for the owner: giving `PostgresOutbox` a configurable table name would be the alternative, but that means editing `event-ingest`, so the conservative separate-database rule was chosen instead.*

`deploy/compose/compose.control-pg.yaml` is the overlay that proves it: a TLS Postgres (`apex_control` database) plus **two** replicas of the `--features postgres` image sharing it. Two, not one, because a single replica proves only that a connection string was read; the claim that matters for cross-replica rate limiting is that two processes can share one authoritative outbox. TLS is not optional decoration -- the shared `postgres_transport` permits `sslmode=disable` only to a literal loopback IP, so a Postgres reached by Compose service name can only be spoken to over verified TLS.

## Keycloak operator credentials

`StaticOperatorTokenResolver` was the only `OperatorCredentialResolver`, and it was always documented as the local/lab and CI seam. `src/keycloak.rs` adds the production one. It is kept alongside, not instead of: the static table is untouched, and `build_operator_resolver` now chooses between three sources by explicit configuration.

**This gateway is a resource server, not an OAuth client.** Keycloak performs the RFC 8693 exchange that turns a human's OIDC session into a short-lived, scope-bound operator credential; this process holds no client secret, initiates no flow, and does nothing but verify what Keycloak issued. That split is what the vault's [[Authentication and Identity]] note describes, and it is why nothing here needs Keycloak's admin API.

**Selection is explicit, never inferred.** `APEX_CONTROL_KEYCLOAK_ISSUER` chooses this path. Setting it alongside `APEX_CONTROL_OPERATOR_TOKENS_FILE` or `APEX_CONTROL_OPERATOR_TOKENS` is a hard startup error, the same rule and the same reason the two static sources already refused each other. Inferring "Keycloak" from the *absence* of a token table would mean "the operator table was not mounted" and "this deployment authenticates through Keycloak" are the same configuration, which is how a lab posture reaches production.

### Verification rules, and why each is stated rather than defaulted

JWT verification is one of the highest-value places in a system to get wrong, and the failure modes are all well known. Each is closed explicitly:

- **Algorithm confusion.** The permitted algorithm is derived from the **JWK**, never from the token's own header, and the header must then equal it. A symmetric (`oct`/HS*) JWKS entry is refused outright -- "present the RSA public key as an HMAC secret" is the attack in its most direct form, and a JWKS is public. `alg: none` cannot even parse, because `jsonwebtoken::Algorithm` has no such variant; that is asserted by a test rather than assumed, so a dependency bump cannot silently change it. The algorithm allow-list is an exhaustive `match` with HS\*/RSA1_5/RSA-OAEP enumerated as refusals, so a new upstream variant is a compile error rather than a silent widening.
- **`use: enc` keys.** Keycloak publishes an `RSA-OAEP` / `use: enc` key alongside the signing key **in every realm, by default, with no misconfiguration required** -- confirmed live, and asserted by a live test so the guard does not quietly stop being exercised. A verifier that selected a key by `kid` alone would be one realm-config change away from verifying signatures with encryption material.
- **Missing issuer/audience checks.** `jsonwebtoken`'s default is to validate `iss`/`aud` only when *present*. Both are added to `required_spec_claims`, along with `sub` and `exp`, so omitting a claim is not a way past its check.
- **Token-type confusion.** Keycloak signs ID, access and refresh tokens with the same realm keys, and an ID token's `aud` is the client id -- which is exactly what this gateway's expected audience is. The payload `typ` claim must equal `Bearer`. The waiver (`APEX_CONTROL_KEYCLOAK_ALLOW_ANY_TOKEN_TYP=true`) is exact-match and refuses to coexist with `_EXPECTED_TYP`.
- **Long-lived tokens.** "Short-lived" is enforced, not described: `exp - iat` is bounded by `APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS` (default 3600; Keycloak's own default access-token lifespan is 300). `iat` is required and refused if it is in the future beyond the skew leeway.
- **Clock skew.** 30 seconds, not `jsonwebtoken`'s 60. Against a credential meant to live for minutes, 60s is a meaningful fraction of its life; zero would refuse a freshly minted token whenever the gateway's clock is a hair behind Keycloak's.
- **Key rotation and staleness.** The JWKS is fetched at startup and refreshed on an interval, and the refresh **replaces** the whole set rather than merging -- so a key Keycloak has rotated away stops verifying one interval later (default 300s) rather than when the process restarts. If refreshes stop succeeding, the cache goes stale at `APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS` (default 900) and the resolver **fails closed** with a distinct `CREDENTIAL_VERIFIER_UNAVAILABLE` rather than trusting keys of unknown age.
- **Trust anchors.** The JWKS client uses `tls_certs_only`, which *replaces* the trust store with the configured CA rather than adding to it, and `https_only`. Redirects are refused: a redirect is the endpoint choosing where this process gets its trust anchors. The response is read through a bounded reader with a key-count ceiling.
- **Uniform rejection.** Every verification failure returns the same `UNAUTHENTICATED`, so a prober cannot tell a bad signature from a wrong audience from a refused scope claim. The specific reason is logged as a static code (never a token, subject, or claim value) and throttled to at most one line per second, so a credential flood cannot turn this into a log amplifier.

### Claim-to-scope mapping, and why it is shaped this way

[[Authentication and Identity]] states the rule for the rest of the system: *"Identity-provider claims are untrusted input until mapped through explicit allow-listed claim/group rules... External claims can never automatically confer Owner."* The equivalent at this boundary is that **no claim can automatically confer the `*` global operator scope**:

- The scope claim (`APEX_CONTROL_KEYCLOAK_SCOPE_CLAIM`, default `apex_control_scopes`) maps only to narrow `workspace/namespace` grants, each validated by `OperatorCaller::scoped`'s existing grammar and ceiling.
- **A `*` anywhere in that claim rejects the whole credential.** Not widened, and not silently dropped either. Dropping it would hand back a narrower grant than the token asked for and leave nobody aware the mapper is wrong; widening is the bug. A wildcard there means a misconfigured mapper or an attempt, and both deserve a refusal.
- `*` requires **all three** of: `APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE` configured, the token's `sub` present in `APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS`, and that role present in the allow-listed role claim. All unset by default, so `*` is unreachable out of the box. Half-configuring it (one of the two variables) is a startup error rather than a silent "disabled", because a half-configured break-glass reads like break-glass is set up and the operator finds out during the incident.

The local subject allow-list is the part that is **not** identity-provider controlled, and that is the whole point: an over-broad group-to-role mapping in Keycloak -- the realistic failure -- cannot by itself hand anyone rights over every workspace. *It is deliberately not a defence against a fully compromised Keycloak*, which can mint any `sub` it likes. Nothing an OIDC resource server does defends against that, and claiming otherwise would be dishonest. **Flagged for the owner:** the exact break-glass rule is a policy choice. This pass took the conservative one -- default-unreachable, two independent conditions, one of them local. A deployment that finds it too strict can relax it by configuration; a deployment that never sets it has no break-glass path through Keycloak at all and must use the static table for that case.

`sub` becomes `operator:keycloak:<sub>`, distinguishable at a glance from `operator:static:<n>` in the audit trail, and validated against the same ingest actor-identifier grammar so a malformed `sub` is refused at the credential rather than turning every command into an opaque `INVALID_COMMAND`.

### Startup posture

The initial JWKS fetch is **best-effort**. Configuration errors abort startup loudly; an unreachable Keycloak does not. Refusing to start would make the identity provider a hard startup dependency of the one channel ADR-0006 requires to stay reachable when the rest of the platform is degraded -- the same argument that made the JetStream publisher connect lazily -- and would turn a 30-second IdP blip into an outage needing a human to notice and restart a container. The resolver comes up refusing every credential with an honest `CREDENTIAL_VERIFIER_UNAVAILABLE` and begins working the moment a refresh succeeds. It never fails open.

The resolver is constructed **before** the serving runtime, because the JWKS client is `reqwest::blocking` and owns an internal runtime -- the same hazard that already made `run()` synchronous for `PostgresOutbox`.

### Dependency choice

`jsonwebtoken` is pinned to the 9.x line deliberately. It verifies through `ring`, which this dependency tree already carries for rustls, so no second crypto stack enters the build. Version 11 dropped `ring` in favour of either `aws-lc-rs` (a C library whose license set `deny.toml` does not allow, and which would need cmake/nasm in the container build) or `rust_crypto`, which pulls `rsa` 0.9 -- RUSTSEC-2023-0071, which `cargo audit` fails this repository on. `cargo deny check` and `cargo audit` are both clean with 9.3.1.

## Cross-replica admission

The per-operator admission ceiling added in the first pass (`MAX_COMMANDS_PER_WINDOW`) was a process-local `HashMap`. With N replicas the effective ceiling was N x the configured one -- academic while a file outbox made multiple replicas unsafe to run, and no longer academic the moment the Postgres outbox landed and CI started running two of them. An admission control that quietly scales with the replica count is not the control that was configured.

`ControlGatewayService` now takes an optional `apex_event_ingest::EphemeralStore`. **Reused, not forked**, the same rule the outbox and the JetStream publisher already follow: `EphemeralStore`, `InMemoryEphemeralStore`, `FallbackEphemeralStore` and `ValkeyEphemeralStore` are `event-ingest`'s, unmodified, and the call shape mirrors that crate's own `auth/service.rs::admit_request`.

- **The local ceiling is the hard floor.** The shared store can only ever *deny* an admission the local bucket would have allowed; it can never grant one. A store that is unreachable, misbehaving, or whose lock is poisoned falls through to the local buckets rather than failing open. Unit tests assert both directions -- a permanently-`Unavailable` store and a permanently-permissive one both end up bounded by the local ceiling.
- **Its own Valkey instance, ACL user, credential and key namespace** (`APEX_CONTROL_VALKEY_*`), never the ingest workload's; `APEX_VALKEY_HOST` on this process is refused outright. Same rule as the separate NATS account and the separate Postgres database, plus a concrete reason: `event-ingest`'s `ephemeral::types::KEY_PREFIX` is the fixed literal `apex:ingest`, so a shared instance would put both services' counters in one keyspace under one credential, and either service's compromise could clear or inflate the other's admission state. Separation is therefore carried by the *namespace component* (`apex.control.admission`, a value `event-ingest` cannot produce for its own admission counters) **and** by an ACL key pattern narrowed to the hex encoding of that namespace. `live-mtls/render_configs.py` derives that pattern from the same constant the Rust side uses, so the two cannot drift -- and a drift would not fail loudly, it would make every `check_rate_limit` call error and the shared ceiling quietly stop applying. Verified live: the control ACL user reads its own namespace and gets `NOPERM` on `apex:ingest:rl:<hex(workspace)>:…`, `…:fp:…` and `…:deny:…`.
- **The operator subject is hashed into the bucket**, not interpolated. `ephemeral::types` hex-encodes each key component, so a 256-byte subject would produce a 512-character component; and an operator subject is a Keycloak user identifier, which has no business being written in clear into a non-authoritative store that outlives the process and is evicted under `allkeys-lru`.
- **`APEX_CONTROL_ADMISSION_LIMIT` / `_WINDOW_SECS`** are settings (defaults unchanged at 50 per second, both range-checked, zero refused rather than clamped) because the ceiling has to be observable to be provable -- see the live test below.
- **The shared check runs on a blocking thread.** `FallbackEphemeralStore`'s circuit breaker bounds *how often* a dead accelerator is re-dialled; `spawn_blocking` bounds *what one probe can stall*. Without the second, a probe costing a connect timeout plus DNS (~3.85s against Docker's resolver, measured during the earlier pen test) would run on the tonic worker thread holding other requests -- a variant of the 135-second stall `ephemeral/fallback.rs` exists to prevent.
- **`startup/valkey.rs::LazyValkeyStore`** defers the dial to first use and re-dials after failure, wrapped as the breaker's *primary* and never used bare. `event-ingest` refuses to start without its accelerator; this gateway cannot make that trade, and without the lazy wrapper a Valkey that was down at boot would stay unusable for the process's lifetime. Configuration errors (`EphemeralErrorCode::InvalidKey`) still abort startup; `Unavailable` does not.

## Reused vs. new

Reused directly from `apps/event-ingest` (no fork):
- `EventOutbox` / `InMemoryOutbox` / `FileOutbox` / `PostgresOutbox` / `OutboxKey` / `EnqueueResult`
- `IngestRequest::from_validated_transport` and `canonical_event_hash` (both widened from `pub(crate)` to `pub` and re-exported from `event-ingest`'s `lib.rs` -- the only visibility changes made to that crate)
- `IngestRequest::event_id/envelope/workspace_id/namespace_id` accessors (the first two were `test-support`-gated; ungated since a production consumer now needs them for outbox-key construction in the fanout worker)
- `GatewayError`/`GatewayErrorCode` (mapped into the control gateway's own `CommandError` taxonomy rather than passed through verbatim, since some ingest codes describe the ingest identity model, which does not apply to an OOB operator command)
- `EventPublisher` trait, as the abstraction `spawn_fanout_worker` drives (a deployment wires in `JetStreamPublisher` or any other `EventPublisher`)

Reused for the cross-replica admission ceiling (also no fork):
- `EphemeralStore` / `InMemoryEphemeralStore` / `FallbackEphemeralStore` / `ValkeyEphemeralStore` / `ValkeyConfig` / `RateLimitKey` / `RateLimitDecision`, including `fallback.rs`'s circuit breaker and `valkey.rs`'s connection-poisoning rebuild. `apps/event-ingest` was read as reference during this pass and **not modified**.

New in `control-plane-api`:
- `contracts/proto/apex/v1/control.proto` -- the `ControlGateway` service contract
- `src/auth.rs` -- independent operator auth boundary (see table above)
- `src/keycloak.rs` -- the production operator credential verifier (see "Keycloak operator credentials" above)
- `src/startup/valkey.rs` -- lazily-connected wrapper around `event-ingest`'s `ValkeyEphemeralStore`, so an accelerator outage is never a startup dependency
- `src/envelope.rs` -- command-to-envelope construction, including a UUIDv7-derived deterministic timestamp (see "Idempotency" below)
- `src/outbox.rs` -- accept-path orchestration decoupled from fanout
- `src/replay.rs` -- best-effort fanout worker
- `src/service.rs` -- the tonic service: auth, per-operator admission rate limiting, command construction, outbox submission
- `src/errors.rs` -- redacted `CommandError` taxonomy and gRPC status mapping
- `src/main.rs` + `src/startup/` -- the runnable binary's process wiring (bind policy, mTLS material, operator credential table, file outbox), split into `env.rs`/`secrets.rs`/`service.rs`/`tests.rs` the same way `event-ingest/src/startup/` is. Bin-only: declared from `main.rs`, not from `lib.rs`.
- `Dockerfile` and the `control-plane-api` service blocks in `deploy/compose/compose.yaml` and `compose.gateway-ref.yaml`
- `tests/live_control_mtls.rs` -- live mTLS tests against the running container
- `control-plane-server`, `control-operator-client`, and `control-operator-tokens` fixtures in `deploy/compose/live-mtls/generate_pki.py`, so the control gateway borrows neither the ingest gateway's server certificate nor the ingest workload's client identity

## Idempotency

A command's `event_id` (`command_id`) is what the outbox keys on. Naively stamping `timestamp: now()` on every submission would make two genuinely-duplicate submissions of the same `command_id` hash to two different canonical envelopes -- turning intended idempotent replay into a spurious `IDEMPOTENCY_CONFLICT`. Instead, the envelope timestamp is derived from the `command_id`'s own embedded UUIDv7 millisecond clock (`envelope.rs::uuidv7_unix_millis`), so retrying the same `command_id` with the same fields always produces a byte-identical canonical envelope and is recognized as a true duplicate. A `command_id` reused with *different* fields still correctly surfaces `IDEMPOTENCY_CONFLICT`.

Determinism alone is not sufficient, because `command_id` is entirely caller-chosen. The derived timestamp is additionally bounded against the gateway's own clock (`envelope.rs::command_millis_within_acceptance_window`: at most 5 minutes ahead, at most 24 hours behind) and the `command_id` must be in the canonical lowercase hyphenated UUIDv7 spelling the ingest boundary accepts. Without those bounds, any holder of a valid operator credential could stamp a `stop`/`inject`/`set_budget` command with an arbitrary audit timestamp.

## Security review findings and fixes

- **Timestamp-based idempotency defeat** (found during edge-case testing, fixed before merge): see "Idempotency" above.
- **Missing per-operator admission rate limit**: `OperatorTokenAuthenticator` only throttled *auth failures*. A valid-but-compromised or malfunctioning operator credential could otherwise flood the durable outbox with accepted commands. Added a separate per-operator-subject admission ceiling in `service.rs` (`MAX_COMMANDS_PER_WINDOW`), independent of the auth-failure bucket.
- **Pre-existing clippy drift in `event-ingest`** (unrelated to this feature, found while running the mandated gate): `clippy::suspicious_open_options` on two lock-file `OpenOptions` calls (`outbox/file.rs`, `idempotency/file.rs`) and `clippy::type_complexity` on `startup/service.rs`'s ephemeral-store return type. Fixed with `.truncate(false)` (documenting that lock-file content is intentionally preserved, not overwritten) and a `SharedEphemeralStore` type alias respectively. Verified these did not change behavior -- both are lint-only fixes.
Found during the containerization/TLS pass:

- **The operator credential table would have travelled as a Compose `environment:` value.** The binary only read `APEX_CONTROL_OPERATOR_TOKENS`, so wiring it into `compose.yaml` the obvious way would have put bearer credentials that authorize `stop`/`pause`/`inject` somewhere `docker inspect` and `/proc/<pid>/environ` expose -- while every other credential in that file is a file secret. Added `APEX_CONTROL_OPERATOR_TOKENS_FILE`, held to the same owner-only permission policy as a private key, and made setting both sources a hard startup error.
- **A bare `docker compose up -d` in CI would have hidden control-side failures under the gateway's name.** `.github/workflows/live-mtls-e2e.yml`'s gateway smoke-start step started every service in the profile. Once this profile also defined `control-plane-api` and its `service_completed_successfully` init container, a control-side init failure would have failed the *gateway* step, printing only the gateway's logs -- the same class of undiagnosable CI failure that step's own comments already record. The `up -d` is now scoped to `ingest-gateway`; Compose still starts everything it depends on.
- Reviewed and verified live, against the running container: the mTLS gate rejects a client presenting no certificate (server sends TLS `CertificateRequired`) and a client presenting a certificate from an untrusted CA (`UnknownCA`), while a *trusted* certificate with no operator token reaches the application and returns gRPC `Unauthenticated` -- which is what makes the first two results meaningful rather than "the server rejects everything". An ingest workload certificate plus ingest bearer token is also refused, confirming ADR-0006's credential separation against the two credentials a deployment actually issues. Container hardening was confirmed by `docker inspect`: uid 10002, `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `no-new-privileges:true`, not privileged; staged secrets 0600 owned by the runtime uid.
Found during the delivery/backend pass:

- **A JetStream publisher in this process must not become a startup dependency.** The obvious wiring -- copy `event-ingest`'s eager `AsyncNatsJetStreamClient::connect` into `run()` -- would have made the control channel refuse to start whenever the primary data path's broker was unreachable, silently inverting ADR-0006. Configuration is validated eagerly and the connection deferred instead; confirmed live by cold-starting the container with JetStream stopped, submitting a command (accepted in 0.32s), restoring the broker, and watching the backlog drain with no restart and no operator action.
- **The accept path must not be able to block behind the fanout worker.** The worker's connect attempt blocks its thread for up to the 5s NATS connect timeout, once per tick, for the duration of an outage. On a small container that could starve the tonic listener. `block_in_place` (guarded by a runtime-flavor check, the same guard `event-ingest`'s NATS client uses) lets the runtime migrate other tasks off that worker. Reviewed and confirmed: `ControlGatewayService` never holds a publisher reference at all, so the only coupling between the two paths is the outbox mutex, which the 5s tick keeps uncontended.
- **A shared Postgres database would have crossed the two services' durability boundary.** `PostgresOutbox` hardcodes `apex_event_outbox`, so an operator reusing one database for both would have had each service's replay worker claiming and republishing the other's rows through its own sinks -- ingest events emitted as control fanout and vice versa. `APEX_CONTROL_POSTGRES_URL` is a distinct variable, `APEX_POSTGRES_URL` on this process is refused outright, and the requirement is documented at the config surface and in `.env.example`.
- **Least-privilege broker account.** The control gateway's NATS user is granted `publish: ["apex.events.>"]` and `subscribe: ["_INBOX.>"]` only -- no `$JS.API.>`, unlike the ingest publisher, because this service never manages a stream. Verified live that fanout works with exactly those grants rather than assuming it needed more.
- Reviewed for: secrets in logs (the new fanout paths log only static `GatewayErrorCode`/summary strings and the tick interval -- never a token, connection string, or payload), and error-message leakage at startup (`NatsTlsConfig` validation failures are reported as their `public_code()` and never include the configured path or URL).

Found during the Keycloak/cross-replica pass:

- **A dead accelerator container looks exactly like no accelerator at all.** The first live run of the cross-replica test reported 2 x the ceiling. The cause was not in the Rust: the Valkey container was exiting on `chown: .: Operation not permitted`, because the image's `docker-entrypoint.sh` begins with `chown -R valkey .` and the service runs under `cap_drop: [ALL]`. The gateway kept serving happily on its process-local ceiling, so the only symptom of a completely absent accelerator was that the cross-replica limit silently stopped applying -- there is no error, no log line, and no health signal that distinguishes it from a deployment that never configured one. Fixed by invoking `valkey-server` directly (and stating `user: 999:1000`, since bypassing the entrypoint also bypasses its `gosu`). The reason the test caught it is that it asserts an *exact* combined count rather than "fewer than everything". **Flagged for the owner:** a deployment that configures Valkey and then loses it permanently degrades silently to N x the ceiling. `admission ceiling: shared (valkey)` at startup proves the store was *attached*; nothing periodically re-asserts it is *working*. A health/metrics surface for "accelerator sidelined" (`FallbackEphemeralStore::accelerator_sidelined` already exposes it) is the natural follow-up and is out of scope here.
- **A `use: enc` key in every realm's JWKS.** Not a defect introduced here -- the guard was written before the live test -- but worth recording as a finding, because it is the concrete reason "look the key up by `kid`" is insufficient against a real Keycloak rather than a theoretical one. Keycloak publishes an RSA-OAEP encryption key next to the signing key by default, in every realm.
- **Token-type confusion is reachable with the obvious configuration.** If the expected audience is the gateway's client id -- which is the natural choice, and what the lab realm uses -- then a Keycloak *ID token* for that client passes issuer, audience, expiry and signature. The payload `typ` check is the only thing separating them.
- Reviewed for: secrets in logs (the Keycloak paths log only static rejection codes and never a token, `sub`, claim value, issuer URL or audience; `KeycloakConfigError` carries a static string for the same reason, so a misconfiguration cannot leak an internal issuer URL into a log aggregator), log amplification (rejection logging is throttled to one line per second in aggregate, on top of the existing per-token auth-failure bucket), and unbounded reads (the JWKS response is read through a bounded reader with a key-count ceiling; the token is size-checked before it is parsed).

- Reviewed for: auth bypass (none found -- every RPC path requires `authenticate` before any outbox interaction), injection via `inject.content` (content flows untouched into the `control` event's `parameters.content` field and is never interpreted, matching ADR-0005's "content is untrusted data" requirement; `validation/control.rs` already enforces `content_classification: "untrusted"` and a 32 KiB ceiling), budget overflow/negative/NaN/infinity/zero (all rejected by the existing `validate_control_data` finite/positive/bounded check, exercised here via `submit_command_rejects_a_negative_budget_limit`), replay/duplicate attacks (idempotency semantics above), secrets in logs (the fanout worker and auth paths only ever log static `GatewayErrorCode`/summary strings, never tokens or payload content), and TOCTOU on outbox claim (`ControlOutboxBackend` serializes every outbox operation, including the fanout worker's `pending`/`mark_complete`, behind a single `Mutex` -- verified under the concurrency test below).

## Edge cases covered (tests)

`apps/control-plane-api/src/keycloak/tests.rs` offline verification tests (28), against locally minted tokens and a fixture JWKS, so the whole rejection taxonomy is covered in ordinary unit CI with no network:

- Valid token maps to exactly the scopes its claim carries and nothing else
- Expired, and not-yet-valid (`nbf`)
- Signed by a different key **under the same `kid`** -- the forgery a JWKS-backed verifier actually has to stop
- Unknown `kid`, missing `kid`
- `alg: none`, with an empty *and* a non-empty signature segment, in case emptiness was what did the rejecting
- HS256 signed with the public modulus (algorithm confusion), and a symmetric JWK published under the signing `kid`
- Header `alg` disagreeing with the JWK's `alg` in the same family (RS512 token, RS256 JWK)
- An `use: enc` JWK refusing to verify a signature
- Wrong issuer, wrong audience, and a token carrying *no* `iss`/`aud`/`sub`/`exp` claim at all
- An ID token (`typ: ID`) refused as an operator credential
- A lifetime exceeding the ceiling; a token with no `iat`
- `*` in the scope claim rejecting the whole credential, in three shapes
- A role claim alone not conferring the global scope; break-glass requiring role *and* local allow-list together
- Malformed and out-of-grammar scope claims refused rather than partially honoured; a space-separated scope claim accepted
- A `sub` that could never be an ingest actor id
- Nested role-claim paths (`resource_access.<client>.roles`), and a path that does not exist conferring nothing
- Oversized token refused before parsing; configuration validation (plaintext/credentialed issuer, staleness ceiling below the refresh interval, malformed claim paths)
- A stale key cache failing closed with `CREDENTIAL_VERIFIER_UNAVAILABLE`, and every *verification* failure being indistinguishable from the outside

`apps/control-plane-api/src/{auth,envelope,outbox,replay,service}.rs` unit/integration tests (41, run with `--features test-support`):

- Two replicas without a shared store admit twice the ceiling; with one, exactly the ceiling between them (the defect and its fix, asserted as exact counts)
- A permanently-`Unavailable` store falls back to the local ceiling rather than failing open **or** shut
- A permanently-permissive store cannot raise the local ceiling
- The admission key is namespaced away from the ingest workload, carries no operator identity, is stable per subject and distinct across subjects, and satisfies the store's own key grammar (a key the store rejects would make the shared ceiling silently never apply)


- Duplicate command idempotency (`submit_command_is_idempotent_for_a_repeated_command_id`)
- Idempotency conflict on a reused `command_id` with different fields (`submit_command_rejects_a_reused_command_id_with_different_fields`)
- Concurrent commands to the same target with the same `command_id` -- exactly one non-duplicate acceptance across 8 concurrent tasks (`submit_command_handles_concurrent_duplicate_submissions_without_a_torn_write`)
- Malformed `inject` parameters missing `content_classification` (`submit_command_rejects_inject_without_untrusted_classification`)
- Negative `set_budget` limit (`submit_command_rejects_a_negative_budget_limit`)
- Missing/duplicate/malformed authorization headers (`auth::tests::*`)
- Auth-failure rate limiting (`authenticate_rate_limits_repeated_failures_for_the_same_token`)
- Post-auth admission rate limiting (`submit_command_rate_limits_a_single_operator_after_the_per_second_ceiling`)
- Scope enforcement -- an operator cannot act outside its granted workspace/namespace, a global operator can act everywhere (`submit_command_rejects_a_scope_the_operator_does_not_hold`, `global_operator_allows_every_well_formed_scope`)
- Degraded-fanout availability: a `FlakyPublisher` that fails once still leaves the command durable and pending, then succeeds and is marked complete on the next tick (`fanout_worker_retries_after_a_transient_publish_failure`)
- Deterministic UUIDv7-derived timestamps and rejection of non-v7 UUIDs (`envelope::tests::*`)

`apps/control-plane-api/src/startup/tests.rs` startup-policy tests (9):

- Loopback default, and that a non-loopback bind is refused without acknowledgement in both address families
- That the acknowledgement is exact -- `"TRUE"`, `"True"`, `"1"`, `"yes"`, `"on"`, `" true"` must all fail closed rather than be read as consent to expose the control channel
- Bind values that are not socket addresses
- Two configured operator credential sources refused
- Bounded reads (empty, oversized, exactly-at-limit, missing)
- Trusted-base confinement, symlink refusal, and agreement with the platform private-key permission primitive

These cover startup policy rather than `env::var` plumbing because that plumbing is structurally untestable here: the crate has `unsafe_code = "forbid"` and Rust 2024 requires `unsafe` to call `env::set_var`. Each rule is therefore split into a pure `*_value` function taking `Option<&str>`, the same pattern `event-ingest`'s `attempts`/`attempts_value` uses.

`apps/control-plane-api/tests/live_control_mtls.rs` live-container tests (5, opt-in via `APEX_CONTROL_LIVE_MTLS=1`):

- Valid operator certificate + valid token accepted, and the command lands durably in the container's outbox volume
- Valid certificate, **no** token -- reaches the application, returns `Unauthenticated`
- **No** client certificate -- refused at the handshake
- Client certificate from an untrusted CA -- refused at the handshake
- Ingest workload certificate + ingest bearer token -- refused (ADR-0006 credential separation)

`apps/control-plane-api/tests/live_control_postgres.rs` live two-replica tests (3, opt-in via `APEX_CONTROL_LIVE_POSTGRES=1`, against `compose.control-pg.yaml`):

- 16 concurrent submissions of one `command_id` split across both replicas: exactly one first acceptance, 15 duplicates, zero errors (`two_replicas_accept_one_command_id_exactly_once`). Without `ON CONFLICT DO NOTHING`, every loser of the insert race would get a unique violation surfaced as INTERNAL_FAILURE -- an operator's `stop` failing with a server error because someone else sent the same one.
- A command accepted by replica A is a duplicate at replica B (`a_command_accepted_by_one_replica_is_a_duplicate_at_the_other`). This is the assertion that distinguishes one shared authoritative outbox from two independent ones: on a per-replica file outbox both would report a first acceptance, so it fails if `--features postgres` ever silently falls back again.
- A reused `command_id` with different fields still conflicts across replicas rather than overwriting an operator's recorded intent (`a_reused_command_id_with_different_fields_conflicts_across_replicas`).

`apps/control-plane-api/tests/live_control_keycloak.rs` live tests against a **real Keycloak** (14, opt-in via `APEX_CONTROL_LIVE_KEYCLOAK=1`, against `compose.control-keycloak.yaml`). These exist because a hand-rolled JWT mock and a hand-rolled verifier can agree with each other while both disagree with the identity provider. Two halves -- the resolver driven directly against the live JWKS, and the **deployed container**:

- A genuine token accepted, mapped to `acme/prod` and nothing else, with the subject derived from the real `sub`
- The realm really does publish an `RSA-OAEP` / `use: enc` key alongside the signing key (asserted, so the guard stays exercised)
- A one-second-lifespan token, aged past `exp` plus the skew leeway: refused (`SIGNATURE_OR_REGISTERED_CLAIMS`)
- A twelve-hour-lifespan token, correctly signed and in date: refused (`TOKEN_LIFETIME_EXCEEDS_CEILING`) -- **and accepted once the ceiling is raised**, which is what proves the refusal was the ceiling and not something else about the token
- A token from a **second realm on the same Keycloak** with the same `clientId` and the same audience mapper: refused (`UNKNOWN_KID`)
- A real token with one signature bit flipped: refused
- `alg: none` and HS256 over the **real payload and the realm's own `kid`**: refused (`MALFORMED_HEADER`, `HEADER_ALG_DOES_NOT_MATCH_JWK`)
- A token whose audience is another service: refused
- A real token whose scope claim is `["*"]`: whole credential refused (`WILDCARD_IN_SCOPE_CLAIM`)
- The break-glass realm role **without** the local subject allow-list: narrow scopes only. **With** it: global. Role withdrawn in Keycloak: narrow again -- the revocation path
- The deployed `control-plane-api-oidc` container (configured with the issuer and **no** static table, since both is a startup error) accepts a real Keycloak credential, enforces the scope that credential carries, and refuses the static lab operator token outright

`apps/control-plane-api/tests/live_control_valkey.rs` live cross-replica tests (2, opt-in via `APEX_CONTROL_LIVE_VALKEY=1`, against `compose.control-pg.yaml -f compose.control-valkey.yaml`). Two containers, each with its own mTLS Valkey connection under its own ACL user -- not one store object shared between two services in one process, which is what the in-process test does and is a different claim. One test, in three sequential states of one stack, with the overlay pinning limit 8 over a 60-second window so the counts are exact rather than a race against a window boundary:

1. **Valkey up:** 8 of 64 admitted across both replicas -- the configured ceiling, not twice it.
2. **Valkey stopped mid-run:** 16 of 64 -- each replica's own local ceiling. Neither fails open (64) nor shut (0), and 64 requests complete in ~23s against the dead accelerator, well inside the 120s bound the test asserts. The measured pre-breaker failure that `ephemeral/fallback.rs` exists to prevent was 135 seconds for a *single* request.
3. **Valkey restarted:** 8 of 64 again, with **no restart of either replica** -- which is what `LazyValkeyStore` plus the breaker's cool-down buy, and would not happen if the accelerator were only dialled at startup.

Plus an ACL isolation test: the control gateway's Valkey user reads its own admission namespace and gets `NOPERM` on the ingest workload's rate-limit, fingerprint and deny-hint key shapes. That is the half the ceiling assertions cannot show -- a pattern accidentally widened to `~*` would pass every other assertion in the file.

`deploy/compose/gateway-ref/verify_control_fanout.py` (CI gate, no cargo involvement): fetches the last message on the command's own `apex.events.<ws>.<ns>` subject via `$JS.API.STREAM.MSG.GET` and requires the expected markers in the stored envelope. It deliberately does **not** read `ControlCommandResponse.delivered` -- that is the service reporting on itself, and this project has already shipped one bug in exactly that shape (a reused `event_id` reported as a duplicate when it had been freshly accepted). A worker that was never spawned, connected as the wrong principal, or published to the wrong subject leaves nothing to find.

The middle case is the load-bearing one: it proves a correctly-certified client *does* reach the application layer, so the two handshake refusals demonstrate that the certificate is what stopped them rather than the server being broken in some way that rejects everything. Nothing else in CI can catch a regressed TLS gate -- every other test drives the service in-process as a library, where `ServerTlsConfig` is never constructed at all.

## Verification gates

```powershell
cd apps/control-plane-api
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check
cargo audit
```

All pass clean (75 + 18 + 14 + 5 + 3 + 2 tests; `deny` reports advisories/bans/licenses/sources ok; `audit` finds nothing across 292 dependencies), as do `event-ingest`'s own gates (`cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`). `apps/event-ingest` was read as reference during every pass and has not been modified since the first.

`.github/workflows/live-mtls-e2e.yml` additionally builds the real images, starts the real containers, and drives real traffic at them. This exists for the same reason the equivalent gateway step does: `docker compose config` parses YAML, and never catches a Dockerfile that cannot build, a binary that panics before binding, or a container that cannot write its data volume. All three of those reached `master` for `event-ingest` before it had such a gate. The control-side steps, in order:

| Step | What only it can catch |
|---|---|
| Build and smoke-start the control gateway image | Dockerfile/build/bind/volume failures |
| Live control-gateway mTLS tests | A TLS gate that silently made client certificates optional |
| Verify control commands reach JetStream | A fanout worker that was never spawned, connected as the wrong principal, or published to the wrong subject |
| Postgres-backed control gateway (two replicas) + live tests + "landed in Postgres, not a file" | `--features postgres` selecting nothing, and double-claimed outbox rows |
| **Cross-replica admission ceiling (two replicas + Valkey) + live tests** | An accelerator that is configured but not working -- which looks exactly like no accelerator at all, and which this gate caught on its first run |
| **Keycloak-backed operator credentials + live tests** | `build_operator_resolver` not selecting the Keycloak path in a real container, and every verification rule against real Keycloak-issued material |

Both new gates assert a startup log line (`admission ceiling: shared (valkey)`, `operator credentials: keycloak`) *before* sending any traffic, so a container that fell back to a different code path fails with that as the diagnosis rather than with a downstream assertion that could have failed for a dozen reasons.

## Open items for a future pass

Closed by the containerization/TLS pass: the container image and Compose wiring, and native mTLS termination. Closed by the delivery/backend pass: the unwired fanout worker and the inert `postgres` feature. Closed by this pass: Keycloak-backed operator credentials and cross-replica admission rate limiting (see the two sections above). Nothing *ADR-0006* itself called for is outstanding -- every requirement that ADR actually states (durable outbox, independent auth, `control` event emission, cooperative-only semantics, reachable-when-degraded) is met and gated.

That is a narrower claim than it reads at first, and narrower than this document originally made it sound. **0. An agent cannot receive a command.** `control.proto` defines only `SubmitCommand`, operator to gateway, one direction -- no `WatchCommands`, no subscription, nothing. `packages/sdk-python/src/apex_sdk/control.py` validates a command's shape; it does not fetch one. `examples/reference-agent`'s reason-act loop has no control-checking logic. Every accepted command's actual lifecycle ends at "durably recorded and queryable" -- ADR-0005's premise that "the instrumented runtime observes and acts on" a command was never built on the runtime side. This was not in the original six work items or in any prior pass's own open-items list; it is a scoping gap between ADR-0006 (the gateway) and ADR-0005 (the runtime), not a broken promise on tracked work. See [OOB Control Gateway — Command Delivery Gap](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/05%20Research/OOB%20Control%20Gateway%20%E2%80%94%20Command%20Delivery%20Gap.md) for the full evidence and open questions on how to close it.

What follows are the other, genuinely lower-stakes follow-ups surfaced by this work rather than required by it:

1. **`PostgresOutbox` has a fixed table name.** Not a defect -- the separate-database rule is a sound answer and is enforced at startup -- but it does mean the two services cannot share one database even where an operator would prefer that. Making the table name a constructor argument would remove the constraint; not done because it means editing `apps/event-ingest`, which these passes deliberately only read.
2. **`event-ingest`'s Valkey key prefix is likewise a fixed literal** (`apex:ingest`). The control gateway's counters are separated by an unreachable namespace component *and* a narrowed ACL key pattern *and* its own instance, which is enough, but the prefix reading `apex:ingest` for a control-gateway key is misleading to anyone reading a `KEYS` dump. Making it a constructor argument has the same "means editing `event-ingest`" cost as the table name, and the same conservative answer was taken.
3. **No health or metrics surface for "the accelerator is sidelined."** A Valkey that is configured and then permanently lost degrades silently to N x the ceiling; the startup line proves the store was attached, nothing re-asserts that it works. `FallbackEphemeralStore::accelerator_sidelined()` already exposes the state, so this is a plumbing task, not a design one. See the finding in the security section.
4. **The lab harness has one CA.** In `compose.gateway-ref.yaml` the control gateway's client CA is the shared lab `ca`, so an ingest workload certificate survives the *handshake* there and is stopped by the operator credential check instead (`rejects_an_ingest_workload_credential` asserts exactly that). `compose.yaml` separates them -- `CONTROL_CLIENT_CA_FILE` is distinct from `GATEWAY_CLIENT_CA_FILE` -- so in a real deployment that attempt does not survive the handshake either. Giving the lab harness a second CA would let CI exercise the production topology; `live-mtls/` assumes a single `ca.pem` throughout.
5. **`compose.yaml` still ships the static operator table as its configured default**, with the Keycloak switch documented in a comment beside it and in `.env.example` rather than wired as the default. Both cannot be set (it is a startup error), so one of them has to be the file's default, and switching the production reference to a path that requires an operator to stand up a realm first would make the reference profile unstartable out of the box. **Flagged for the owner** as a deliberate choice rather than an oversight.

## Honest final assessment

Against the Phase 0.5 Plan's definition of done, every requirement now holds *operationally* -- deployed, in containers, against real infrastructure, gated in CI -- rather than structurally. The five cooperative controls, the durable outbox, the independent auth boundary, the separate transport, actual delivery into the queryable trace, a multi-writer outbox across replicas, production operator identity, and an admission ceiling that means the same thing at two replicas as at one.

Two things are deliberately **not** claimed:

- **The break-glass policy is a choice this pass made, not one the product specified.** The conservative shape (default-unreachable, two independent conditions, one of them local configuration the identity provider does not control) is defensible and documented in code, but the owner should confirm it is the rule they want before it is depended on in an incident.
- **The Keycloak resolver defends against a mis-mapped identity provider, not a compromised one.** A Keycloak that can mint arbitrary tokens can mint an arbitrary `sub`, so the local break-glass allow-list stops an over-broad group-to-role mapping and nothing more. That is the ceiling of what any OIDC resource server can do, and it is worth stating plainly rather than letting "explicit allow-listed claim rules" imply more than it delivers.
