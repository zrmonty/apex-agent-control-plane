# Rust browser edge: configuration and boundaries

Status: Task 3's browser foundation and corrected browser test are reviewed.
Real Keycloak, HTTP, PostgreSQL and mTLS tests and scoped independent reviews
pass. The test now checks the actual bounded Set-Cookie instruction and freezes
the pre-credential browser expiry; it no longer assumes a shared Node/Chromium
creation clock. Three consecutive no-screenshot journeys and all 79 startup
tests pass. This is test-observation repair, not a production cookie change.
Durable login admission and redacted BFF stage timing are implemented.
Durable MCP trace persistence/query is unproven.
Do not expose this development checkpoint publicly. The
[release evidence ledger](mcp-gateway-release-evidence.md) records exact limits.

## Process and transport

The control-plane binary owns a separate, optional browser HTTP listener.
Static console assets and public TLS belong to the deployment HTTPS edge.
Browser routes must share its configured origin; no cross-origin credentialed
API or additional Node frontend server is introduced.

Enablement requires both `APEX_CONTROL_BROWSER_BIND_ADDR` and
`APEX_CONTROL_BROWSER_CONFIG_FILE`. An absent pair disables this listener;
partial, empty or malformed settings fail startup. A configured listener must
be a numeric loopback socket with a nonzero port, such as `127.0.0.1:8088`.
The control listener's nonlocal-bind acknowledgement cannot widen this browser
hop. The HTTPS edge must share its network namespace or another explicitly
confined local topology; do not publish plaintext through a Docker bridge.

The ordinary control listener remains mandatory mTLS. The browser edge connects
to that same process with a dedicated client certificate, a configured server
name and its explicit CA. Wildcard control binds map to the same address
family's loopback for this connection; non-loopback-specific control binds and
port zero are currently rejected when enabling the browser. The browser cannot
supply an internal target, service name, credential or TLS policy.

Enabled browser startup requires a PostgreSQL-enabled binary and
`APEX_CONTROL_POSTGRES_URL` for the control plane's own database/schema. It also
requires the existing exclusive Keycloak operator source: no static credential
table or anonymous fallback. `APEX_CONTROL_KEYCLOAK_EXPECTED_TYP` must resolve to
`Bearer`; the allow-any-type waiver is refused. The API audience must differ
from the browser client ID, and the configured maximum access-token lifetime
must not exceed 3,600 seconds.

## Configuration and private material

Start with the [metadata-only example](../../deploy/compose/working-browser/browser-config.example.json).
The configuration file must be confined under
`APEX_CONTROL_TRUSTED_SECRET_BASE`. Material references are relative to that
trusted directory, or absolute paths still confined inside it. Keep this
directory deployment-owned and not writable by application callers. The
existing canonical-path checks are not an atomic defense against concurrent
replacement by someone allowed to modify the secret directory.

The JSON parser rejects unknown/duplicate fields and files larger than 32 KiB.
No inline token, key or arbitrary provider endpoint is accepted. Provider
authorization/token/revocation URLs are derived from the configured Keycloak
issuer; JWKS uses the existing configured Keycloak URL. Discovery must match
those fixed values. The sole callback is `<public_origin>/auth/callback`.

Private files use the shared platform permission policy, regular-file and size
checks, and refuse final symlinks or canonical escapes. Private reads allocate
zeroizing buffers before reading, including failure paths. This does not prove
every temporary allocation inside TLS/OIDC dependencies is wiped.

- `client_secret_file`: 16–4,096 ASCII graphic bytes, with at most one optional
  trailing LF or CRLF. No whitespace trimming beyond that single line ending.
- Session-key files: exactly 32 raw bytes. Not hex, Base64 or newline-terminated
  text. Keys are provisioned and persisted by the deployment, never generated
  implicitly at service startup.
- `session_keys`: exactly one `active` key and at most three `retired` keys,
  each with a unique ID. Retired entries additionally require a positive
  `decrypt_until_unix_seconds`; they decrypt only before that exclusive deadline.
  New encryption always uses the active key. Removing a still-needed old key
  makes its sessions unreadable rather than falling back to another key.
- Management/provider CA and certificate PEM files: at most 1 MiB. The dedicated
  management private key is also at most 1 MiB and must satisfy private-file policy.

Session absolute age is 300–86,400 seconds; idle age is 60–3,600 seconds and no
greater than absolute age. HTTP concurrency is 1–256, with immediate busy
rejection; the whole request budget is 15–60 seconds. The internal management
connection uses a 5-second timeout and each management RPC has a 10-second bound.
These deadlines bound cooperative application work, not physical OS scheduling.

`global_scope_catalog` lists exact `workspace/namespace` choices for an explicitly
configured break-glass operator. It grants no authority and has at most 256
entries. Ordinary operators see only verified access-token grants. Wildcards
in this catalog are rejected; an empty catalog does not invent tenant choices.

## Session and RPC behavior

| Route | Boundary |
| --- | --- |
| `GET /auth/login` | Durable shared admission precedes provider I/O and attempt storage; independent one-use state, browser binding, nonce and S256 PKCE; fixed provider redirect. |
| `GET /auth/callback` | Atomically consumes the matching browser-bound attempt before provider I/O; issuer/nonce/ID identity and separate API access authority must verify. |
| `GET /api/session` | Returns verified subject, exact scope choices, CSRF token and honest capability flags; no provider credentials. |
| `POST /api/apex/v1/<Service>/<Method>` | Exact Origin and session-bound CSRF, bounded generated JSON allowlist, verified stored access credential, dedicated mTLS and existing Rust scope authorization. |
| `POST /auth/logout` | Origin/CSRF-bound local revocation and encrypted-token erasure first; provider revocation is bounded and best effort. |

The browser's session credential is an opaque `__Host-apex_session` cookie: Secure,
HttpOnly, SameSite=Lax, Path=/, no Domain. Storage uses its digest and an AEAD
bundle bound to issuer/client/subject/absolute expiry. Login cookie/state and
CSRF values are independently generated. The separate `__Host-apex_login` binding
may remain for its original, unextended ten-minute lifetime so independent tabs
can finish their own one-use attempts. It grants no session authority: callback
consumes its matched state row, and logout revokes/clears the session credential.
Both application cookie kinds use the same Secure/HttpOnly/Lax/host/path rules.
Access/refresh/ID tokens never enter
browser JSON or storage, and hostile browser Authorization headers are ignored.
Do not log callback query strings, cookies, request bodies or provider replies
at the deployment edge.

Near access expiry, one committed generation claim precedes one provider refresh.
Contenders get a closed busy/unavailable result; they do not retry the old token.
A verified replacement must win the conditional commit and a fresh state check.
Logout/expiry wins against a late result. A failed or abandoned claim remains
non-serving until its bounded lease expires; it is never reclaimed with the old
refresh token. A successful refresh preserves CSRF, original nonce and absolute
session expiry. A concurrent logout cannot retract an RPC already authorized and
dispatched; subsequent requests and refresh commits are fenced.

An RPC timeout may have an uncertain mutation outcome. Do not generate a new
request ID and blindly repeat it. Reconciliation retains the original request
identity. The console integration and complete recovery UX remain later tasks.

## Shutdown and verification status

Login admission uses one PostgreSQL GCRA row per browser-session schema: burst
60, refill one admission per database-clock second. Contenders serialize before
sampling that clock. Accepted admission is committed before provider work and
is not refunded on failure. This is not a strict 60-per-rolling-minute quota.
Client headers, cookies, restart and attempt pruning cannot reset the row.
Backward/negative clock samples, overflow and malformed state fail closed.
Session storage metadata is now version 2; an existing version-1/partial schema
is refused, not automatically repaired or migrated. The encrypted bundle format
remains version 1. Migration and deployment require an explicit reviewed path.

Root startup retains final PostgreSQL and lazy publisher owners outside the
serving runtime. Listener binding/TLS construction precede background workers;
gRPC acceptance and browser mTLS connection run concurrently. The supervisor
owns both servers, treats unexpected exit as failure, requests shared shutdown,
drains or aborts/joins servers, joins workers and closes the session worker.
The runtime is destroyed before final blocking resource owners. Seven root-process
tests exercise actual Keycloak login and scoped persistent management, a disabled
browser, immediate shutdown, occupied listener ports, and invalid bridge TLS trust/name. They observe
zero root-owned PostgreSQL connections after startup returns while the child is
still alive. They do not prove cleanup with a connected NATS/Valkey publisher or
external browser/TLS topology; passing helper tests alone is insufficient.

Windows material component tests explicitly require the existing `test-support`
permission waiver. They do not establish production Windows ACL enforcement.
Unix CI must exercise actual private modes and symlink rejection. The supported
deployment remains Linux OCI, including on Docker Desktop.

BFF observations use the shared integer clock for actual login, callback,
session, refresh, management and logout stages. Generated timing fields retain
integer microseconds and optional nanoseconds, separate trace/span/process IDs,
clock source, resolution and optional uncertainty. Fixed stage/action/status
names exclude subjects, URLs, queries, cookies, credentials and error text.
Handler-response-ready means application handling completed, not socket delivery.
Cancellation is partial, not success; unknown clock uncertainty stays unknown.

Each record is bounded to 32 stages and 64 KiB, including its newline. A dedicated
worker has a 128-record queue (at most 8 MiB queued payload plus one in-flight
record). Requests never wait for queue capacity or write output themselves.
An uncertain write/flush failure closes that exporter so later records cannot
be appended to a corrupt JSON prefix. These observations are lossy diagnostics,
not durable evidence or an MCP trace query implementation.

Configure the existing loopback-only `APEX_CONTROL_METRICS_ADDR` to scrape
`apex_browser_observation_{exported_records,dropped_records,dropped_stages,
clock_errors,id_errors,exporter_errors,incomplete_shutdowns}_total` independently
of the observation queue. The same integer counters are in the runtime status
line. After server/runtime drain, exporter shutdown waits at most one second;
incomplete output or recorded loss returns a sanitized degraded process result
with the final counter snapshot. It does not alter any request authorization or
response. No synchronous fallback output is added by this shutdown helper.
Blocked OS writes cannot be cancelled: queued loss accounting may be delayed
until a detached writer returns. This does not solve globally blocked process
stdio or prove every OS teardown deadline.

Complete MCP trace persistence/query/UI remain later tasks. Printed precision
does not establish end-to-end tracing or one-microsecond cross-host accuracy.

## Local UI development

The Vite server remains loopback-only. Set `APEX_UI_BROWSER_EDGE` explicitly to
`http://127.0.0.1:<Rust-browser-port>` before starting it to forward only `/api`
and `/auth` routes to that local Rust edge. Other destinations, URL credentials,
paths, queries and ambiguous port spellings are refused. There is no proxy when
the variable is absent and no preview-data fallback when the edge is unavailable.

Origin, provider redirects and Secure cookies are preserved. Login still needs
the configured HTTPS public origin and its HTTPS frontend; the Vite HTTP hop
does not waive the Rust origin/CSRF checks or make Secure cookies work over HTTP.
This option is development wiring, not the production deployment frontend.
