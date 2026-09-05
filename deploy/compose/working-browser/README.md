# Real Keycloak browser-login fixture (LAB only)

This disposable local/CI fixture supports Task 3's real Rust browser login.
It imports the [shared lab realm](../gateway-ref/keycloak/apex-realm.json), runs
only Keycloak, and preserves a ready instance until explicitly stopped. It is
not part of production startup. All committed credentials are lab fixtures.

The pinned image matches `../compose.control-keycloak.yaml`:

```text
quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007
```

The image must already be cached. The helper never builds or pulls it. It uses
Compose V2, Node 24 built-ins, and a `dev-mem` database with no persistent
volumes. Every start creates a new random `apex-browser-lab-<owned-id>` project
with ownership labels on both the container and network.

The only published port is `127.0.0.1:<port>:8443`, default `18451`. HTTP is
explicitly disabled, including inside the container. `KC_HOSTNAME` is the
complete `https://127.0.0.1:<port>` URL; dynamic backchannel URLs are disabled.
Host Rust uses that same issuer, discovery, token and JWKS origin with the
existing CA. An optional `--issuer-port` separates the canonical HTTPS port
from the published backend port for the E2 response gate described below.
Both ports are independently validated decimal integers in 1024..65535, and
both hosts are fixed to `127.0.0.1`. Omitting it retains the default behavior.
No DNS override or TLS verification bypass is needed for Keycloak.

The fixture runs as container root with only `DAC_OVERRIDE` so the existing
host-private lab key can be read across Linux host/container UID differences.
Only the exact leaf certificate, leaf key and realm JSON are mounted, all
read-only. No Docker socket, host network, PKI directory mount, host permission
change, generated PKI or secret copy is involved. This is a lab compatibility
choice, not a production deployment prescription.

## Existing PKI and environment

The main integration owner must already have generated disposable PKI with
`../live-mtls/generate_pki.py` and exported `APEX_BROWSER_TEST_PKI_DIR` to its
absolute root. Reuse that generation. The helper reads these exact files:

```text
APEX_BROWSER_TEST_PKI_DIR/
  trusted-host/
    ca.pem
    control-plane-server.pem
    control-plane-server.key
```

The leaf must match its key, verify against this CA, be currently valid, and
include IP SAN `127.0.0.1`. The helper never overwrites or removes these files.
The existing `untrusted-host` and other component-test identities remain the
main test's inputs. Docker Desktop must have access to the existing PKI path.

Run the following from the worktree root. This prints resolved configuration
without contacting Docker or reading private keys:

```powershell
node scripts/prepare-browser-keycloak.mjs config --port 18451
```

Only the main integration owner should run the following Docker lifecycle
commands. This preparation sidecar did not start or stop any containers.

```powershell
# APEX_BROWSER_TEST_PKI_DIR is already set to the existing disposable PKI root.
$browserFixture = node scripts/prepare-browser-keycloak.mjs start --port 18451 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Keycloak fixture startup failed' }
try {
    $env:APEX_BROWSER_KEYCLOAK_ISSUER = $browserFixture.env.APEX_BROWSER_KEYCLOAK_ISSUER
    # Keep APEX_BROWSER_TEST_PKI_DIR unchanged. Run the main Rust acceptance here.
    # Startup JSON is safe to retain: paths/issuer/ownership only, no credentials.
} finally {
    node scripts/prepare-browser-keycloak.mjs stop --owned-id $browserFixture.ownedId
    if ($LASTEXITCODE -ne 0) { throw 'Owned Keycloak fixture cleanup failed' }
}
```

`start` is also the default command. `--pki-dir ABSOLUTE_LOCAL_PATH` can replace
the input environment variable; the returned `env.APEX_BROWSER_TEST_PKI_DIR`
then carries that canonical root. For a successful start, stdout contains JSON
with `ownedId`, `project`, exact resource IDs, `paths`, `env`, resolved Compose
configuration, client ID, username, and the fixed callback/logout URLs.

The returned `env` contains exactly the main Rust test's agreed inputs:

```text
APEX_BROWSER_KEYCLOAK_ISSUER=https://127.0.0.1:18451/realms/apex
APEX_BROWSER_TEST_PKI_DIR=<existing absolute PKI root>
```

Read `paths.realm` for `clients[clientId == "apex-browser"].secret` and
`users[username == "apex-browser-lab"].credentials[type == "password"].value`.
The helper does not export passwords, client secrets or provider tokens. No
bootstrap admin account is configured. This client cannot mint a login via
password/direct grants or service credentials: the test must follow actual
Keycloak HTML and submit the human credential, retaining state, nonce and PKCE.

The registered browser public origin is `https://console.example`, with exact
callback `https://console.example/auth/callback`. The HTTP test owns routing
that browser callback to its edge. Do not follow it onto the public internet,
change the Keycloak client redirect to an arbitrary local URL, or confuse this
browser-origin routing with the provider's directly reachable loopback issuer.

## Cleanup and readiness

The helper checks the random project is empty before creating anything. It
prints its ownership ID to stderr before creation for recovery. Creation,
readiness errors and SIGINT/SIGTERM during startup enter owned cleanup in
`finally`; success retains the fixture. A hard process kill or host failure
cannot run `finally`: retain the emitted ID and run the explicit stop command.

```powershell
node scripts/prepare-browser-keycloak.mjs stop --owned-id <exact-emitted-32-hex-id>
```

Stop needs neither PKI nor the original port. It checks the whole project
inventory, ownership labels, expected names/image/loopback binding, and network
attachments before removing anything. Unexpected resources fail closed. It
rechecks resources and removes only exact validated container/network IDs,
then verifies the project is empty. It never uses `compose down`, prune, a glob,
or filesystem deletion. A repeated stop of an already empty owned ID succeeds.

Readiness has a 300-second limit and uses verified HTTPS discovery plus JWKS;
redirects are not followed, responses are bounded, and issuer/endpoints must
exactly match the configured loopback URL. Provider support for code flow,
S256, refresh, and confidential client authentication is required. This proves
provider availability, not the Task 3 login/refresh/RPC acceptance gate. The
main Rust test owns that real flow and must assert token audiences, refresh
reuse rejection, browser token absence, and denied scope `acme/other`.

## E2: complete real refresh response versus logout or lost reply

`browser_refresh_races` uses a **second, separately owned Keycloak instance**.
Keep the normal `18451` fixture intact. The main integration owner starts the
second backend on `18462`, advertising canonical HTTPS port `18461`:

```powershell
$refreshFixture = node scripts/prepare-browser-keycloak.mjs start --port 18462 --issuer-port 18461 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'E2 Keycloak fixture startup failed' }
$previousRefreshIssuer = $env:APEX_BROWSER_REFRESH_TEST_ISSUER
try {
    $env:APEX_BROWSER_REFRESH_TEST_ISSUER = $refreshFixture.env.APEX_BROWSER_KEYCLOAK_ISSUER
    # Existing APEX_BROWSER_TEST_PKI_DIR and APEX_BROWSER_SESSION_TEST_DATABASE_URL stay set.
    cargo test -p apex-control-plane-api --features postgres,test-support --test browser_refresh_races
    if ($LASTEXITCODE -ne 0) { throw 'E2 real Keycloak refresh acceptance failed' }
} finally {
    $env:APEX_BROWSER_REFRESH_TEST_ISSUER = $previousRefreshIssuer
    node scripts/prepare-browser-keycloak.mjs stop --owned-id $refreshFixture.ownedId
    if ($LASTEXITCODE -ne 0) { throw 'E2 owned Keycloak cleanup failed' }
}
```

Expected E2 environment:

```text
APEX_BROWSER_REFRESH_TEST_ISSUER=https://127.0.0.1:18461/realms/apex
APEX_BROWSER_TEST_PKI_DIR=<existing disposable PKI root>
APEX_BROWSER_SESSION_TEST_DATABASE_URL=<existing disposable loopback PostgreSQL URL>
```

The helper continues returning `env.APEX_BROWSER_KEYCLOAK_ISSUER`; map that
value into `APEX_BROWSER_REFRESH_TEST_ISSUER` for E2. Keep the normal fixture's
`APEX_BROWSER_KEYCLOAK_ISSUER` on `18451` so normal Keycloak tests and E2 can
run in the same Cargo batch. E2 requires the exact `18461` issuer above and
does not fall back to the normal fixture's variable.

The helper's readiness connects to `https://127.0.0.1:18462` with the trusted
CA; the gate need not exist yet. Genuine discovery must advertise issuer,
authorization, token, JWKS, logout and revocation URLs on `18461`. Only after
validation does readiness fetch the fixed backend path
`/realms/apex/protocol/openid-connect/certs`. The returned `readiness` object
contains these two exact physical URLs. No discovery URL is followed or
rewritten into a general proxy target. HTTPS readiness uses a direct agent,
with certificate verification, bounds, and no redirect following.

Each Rust case starts its own TLS gate on `127.0.0.1:18461`, with the existing
trusted leaf/key, forwarding only allowed Keycloak paths to the fixed HTTPS
backend `127.0.0.1:18462`. It pins the CA, rejects redirects and environment
proxies, disables retries/compression, and bounds total requests to 16 KiB,
total responses to 64 KiB, concurrent connection tasks to eight, and accepted
connections to 128. Exactly one complete refresh response can be held. The
real-provider and PostgreSQL fault cases serialize ownership of the fixed port
within their test process; do not run another copy of this target concurrently.

The gate runs on its own OS thread with an active Tokio runtime before the
production Keycloak resolver performs its blocking initial JWKS fetch. Its
API arms one refresh, notifies the test only after reading the complete real
Keycloak 200, and accepts a release-or-close decision. Two-second handshakes
and a two-second release/drop deadline keep ordering independent of sleeps
and precede the BFF transport/provider/claim deadlines. Other connections
continue serving metadata and revocation while the refresh response is held.

The positive control performs real login/PKCE, validates the held access token
with the production resolver and the held ID token with public
`IdTokenVerifier`, authentic discovery/JWKS, saved subject and nonce, then
releases the reply. It requires generation 1, persisted rotated tokens and
authenticated session/management access. The logout case instead waits for
valid cookie/Origin/CSRF logout and an independent PostgreSQL observation of
revoked state and null token columns before release. It requires late 401,
no replacement session/cookie, no management call and exactly one upstream
refresh. A separate case closes downstream after the real 200 and requires
503, unchanged claimed generation/deadline, no later refresh retry, and
successful durable logout. Neither case spends the old or rotated refresh
token as a probe.

Only the copied access expiry is shortened in each case's owned UUID schema;
the signed credentials and grants stay unchanged. Async helpers cancel owned
tasks, and the gate closes/joins its owned thread. Schema cleanup targets only
the case's owned UUID schema.

Independent PostgreSQL observations and copied-expiry injection use
`connect_postgres_for_worker` on a blocking thread. Its transport arms a
five-second deadline before startup and each SQL operation; expiry closes
and joins the socket driver so the blocking call can return. The helper also
checks the caller's deadline before connecting, between operations and before
returning, preventing late results from starting another SQL operation. The
two-second async watchdog alone cannot stop blocking work: runtime destruction
may wait for the active transport deadline. No query is retried.

The two `pg_faults::` regressions exercise the actual observation helper with
owned loopback peers that withhold startup or the snapshot query response.
Each runs in an owned child protected by an independent ten-second watchdog.
They require failure plus runtime/gate destruction within seven seconds, peer
EOF before rescue cleanup, front-port rebinding and child reaping. The peer
acknowledges the setup SET statements before withholding the snapshot query;
it supplies no database result or identity-provider acceptance evidence. These
cases cover the observation worker and gate teardown, not every inherited
schema-creation/removal failure path.

The main owner retains responsibility for the second Keycloak container.
These are component integration cases; they do not establish external browser
cookie-jar, deployed HTTPS edge, startup or full-runtime acceptance. Existing
refresh fencing may make the cases immediately GREEN; do not claim a new
production fix or manufacture a RED result for that additional coverage.

## Checks and sources

```powershell
node --test scripts/prepare-browser-keycloak.test.mjs
node --check scripts/prepare-browser-keycloak.mjs
```

Tests exercise the real realm/config, argument validation, discovery checking,
owned-inventory validation and lifecycle orchestration without executing Docker.
The six existing service-client scenarios retain their original claims and
lifetimes.

Main-owner verification reported on 2026-09-04: the pure helper tests passed
14/14. The two PostgreSQL fault regressions first produced semantic RED
(0 passed, 2 failed, 20.01 seconds): each confirmed its selected protocol stall
before the independent watchdog killed and reaped its owned child. After the
bounded observation transport change, the combined E2 target passed 5/5 in
11.65 seconds, including both fault regressions and the three authentic
Keycloak cases, with `postgres,test-support`. This RED concerns test-helper
teardown, not a new production authentication defect. Delta review remains
with the main owner's reviewer.

Options were checked against existing repository Compose/configuration and the
official Keycloak [hostname guide](https://www.keycloak.org/server/hostname),
[TLS guide](https://www.keycloak.org/server/enabletls),
[configuration reference](https://www.keycloak.org/server/all-config), and
[server administration guide](https://www.keycloak.org/docs/latest/server_admin/).
See the [shared realm README](../gateway-ref/keycloak/README.md) for browser
client details, lab credential locations, refresh settings and source references.
