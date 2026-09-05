# Production-root browser journey (owned lab only)

Parent entrypoint: `node apps/operator-ui/scripts/browser-journey.mjs`.
Use installed **Playwright 1.62.0** and its default Chromium headless shell.
Do not run this child independently against shared state: the Rust root UI
case owns a fresh empty PostgreSQL schema and the root restart.

Current cookie policy is the **original-wire + frozen browser-expiry contract**
at the end of this document. Earlier cookie/diagnostic sections record historical
snapshots, including the superseded cross-clock assertion; their passing runs
are not verification of the current delta.

Required environment:

- `APEX_ROOT_BROWSER_HTTP_ADDR=127.0.0.1:<port>`: parent-owned real BFF.
- `APEX_BROWSER_TEST_PKI_DIR`: existing absolute local lab PKI directory.
- Real lab Keycloak already running at `https://127.0.0.1:18451/realms/apex`.
- Actual UI build already present in `apps/operator-ui/dist`.

Optional `APEX_UI_ARTIFACT_DIR` must name an existing test-owned directory
strictly beneath the OS temporary directory. The child creates one unique
`ui-journey-*` subdirectory with four PNGs: inventory/draft, desktop/mobile.
Only these safe pre-save views are captured, never login, credential inputs,
network traces, HARs, PDFs, storage snapshots or automatic failure images.
The parent retains/removes its artifacts after inspection; the runner never
deletes shared paths, PKI, PostgreSQL, or Keycloak resources.

## Exact protocol

The child writes LF-only lines, with no other stdout:

1. `UI_READY_FOR_RESTART` after real UI create + fresh detail/list verification.
   Parent fully stops the root, proves owner cleanup, then sends `D\n`.
2. `UI_OFFLINE_OBSERVED` after a reload sees the honest unavailable session
   gate, not an empty/success inventory or a cached proxy card. Parent restarts
   the same database, session key and ports, proves readiness, sends `R\n`.
3. `UI_JOURNEY_PASSED` after a fresh list returns the identical UUIDv7/name,
   actual UI logout returns 204, session reload returns 401, and owned Chromium
   and HTTPS frontend have closed. The child then exits 0.

Every failure is a fixed `UI_JOURNEY_FAILED_<category>` stderr line and exit 1.
No caught error contents, credentials, URLs, response bodies, cookies or
control-plane messages are printed. Ambient debug logging is suppressed in
this dedicated process before Playwright import. Browser environment strips
APEX/proxy/debug settings; the runner never edits host files or system trust.

## Bounds and trust

The frontend binds `127.0.0.1:0`, serves only actual bounded built assets and
known SPA paths, and forwards exact `/api/` and `/auth/` prefixes to the one
validated literal-loopback target. There is no API or provider fulfillment.
Proxy requests are capped at 256 KiB before dispatch; replies at 1 MiB before
relay; 32 concurrent requests/connections and 5-second absolute request/reply
deadlines. A down upstream yields an empty 502, not a fixture response.
Assets are capped at 8 MiB each, 32 MiB total, 256 entries; no symlink files,
source maps or arbitrary sibling files. Hop-by-hop/proxy/forwarding headers
are removed; OAuth Location/Set-Cookie and authority/CSRF inputs are preserved.

The browser uses canonical `https://console.example` with
`MAP console.example:443 127.0.0.1:<ephemeral-port>`. The SPKI exception is
exactly SHA-256 of the existing control-plane leaf's DER public key. There is
no global certificate bypass or `ignoreHTTPSErrors`. Default launch supplies
the isolated temporary browser profile. The exception is deliberately a
lab-key exception, not evidence of public-CA browser trust.

Request-stage CDP Fetch interception checks the console and fixed Keycloak
origins, including redirect hops, before continuing unmodified requests.
Unknown origins fail the journey; external DNS is also disabled by a final
resolver rule. WebSockets, downloads, service workers and unexpected pages
are refused. This harness exercises the known UI/realm, not adversarial HTML
in arbitrary worker or out-of-process iframe targets.

Page/action/navigation and parent acknowledgement waits are 20 seconds;
proxy waits are shorter. The total child watchdog is 120 seconds, plus a
4-second emergency cleanup bound, beneath the parent's 150-second watchdog.
Normal runtime is expected below 60 seconds; main reported a 2.39-second
successful root case after the cookie correction (before the review fixes
below). SIGTERM, parent stdin EOF, errors and timeout
initiate browser/frontend cleanup. Default Playwright launch's SIGTERM
process-tree owner is notified every 250 ms during cleanup: its pinned 1.62
implementation first closes gracefully, then force-kills/reaps on repeated
notification. This covers EOF while launch is still pending without private
Playwright API calls or process enumeration. A 4-second emergency exit uses
Playwright's owned-tree exit guard; parent has its own exact-child kill/reap.
A launched browser's close rejection is a cleanup failure, never PASS. The
250 ms notifications and 4-second emergency remain active on that failure.
A rejected launch is handled separately so cleanup cannot replace the original
launch failure. Success waits for both browser and frontend closure.

Every actual upstream reply must carry exactly `Cache-Control: no-store`
before relay. A missing or different value fails the journey's violation gate
and yields only an empty local 502; it is not accepted as offline evidence.
Validated upstream cache headers are preserved. Local assets and local errors
still receive no-store, without manufacturing proof about the BFF.

## Verification boundaries

`node --test apps/operator-ui/scripts/browser-journey/*.test.mjs` exercises
real loopback HTTP transport, strict input parsing, bounded file loading,
and real child-process failure/redaction. The helper upstream is deliberately
synthetic transport-only data, **not** evidence of BFF or Keycloak correctness.
The actual journey only becomes G0 evidence when the parent's production-root
integration test runs it successfully. No live root/Chromium run was performed
by the sidecar before handoff. Runtime EOF/forced-browser cleanup still needs
the parent/independent review's actual-browser coverage.

Primary references checked for the implementation:

- [Chromium's port-mapping command tests](https://chromium.googlesource.com/chromium/src/+/refs/tags/142.0.7444.265/tools/captured_sites/captured_sites_commands_test.py).
- [Chromium's SPKI-only certificate exception definition](https://chromium.googlesource.com/chromium/src/+/8402d3c5bc13e018fa75eba650ed881755e0223b%5E%21/).
- [CDP Fetch requestPaused redirect behavior](https://chromedevtools.github.io/devtools-protocol/tot/Fetch/#event-requestPaused).
- Installed `playwright-core@1.62.0/lib/coreBundle.js`, processLauncher around
  lines 8846-9024: graceful-close, repeated-notification kill, exit guard,
  process-group/Windows exact-tree termination and cleanup wait.

## Historical cookie-expectation integration correction (superseded below)

Production `browser/edge/login.rs` deliberately reuses the unextended ten-minute
`__Host-apex_login` browser binding for independent tabs. Callback consumes the
matched one-use PG row, not this cookie; logout clears only the session cookie.
The harness's original unconditional binding-cookie rejection was incorrect.

The first correction purely validated the observed jar: initially no application
cookies; exactly one session while authenticated and none after logout; at most
one surviving binding afterward. Both cookie kinds require canonical 32-byte
opaque values, actual boolean Secure/HttpOnly, Lax, exact host/path and finite
future expiry. Binding expiry is capped at 600 seconds from observation of the
actual `/auth/login` 302 response, never a sliding later-inspection deadline.
Later observations reject replacement or expiry extension; a browser-removed
expired binding is allowed, but an expired binding still present is rejected.
No cookie is injected, cleared, renewed, or otherwise changed by the harness.

Focused command: `node --test apps/operator-ui/scripts/browser-journey/cookies.test.mjs`.
Observed meaningful RED: 38 pass / 8 fail against the extracted prior policy;
GREEN: 46/46, 0.058 seconds. An initial literal session-token test fixture was
corrected to canonical encoding before the reported RED. Syntax checks passed
for the changed journey and cookie helper. No full rerun, API/Cargo call, or
real-browser run was performed for this correction; main owns actual-root
verification. Only cookie observation/validation changed in the journey; its
launch profile, transport, protocol, storage checks and UI actions are unchanged.

Main subsequently reported actual production-root **1/1 GREEN in 2.39 seconds**
with real Keycloak/PostgreSQL create, reload, outage, restart and logout. This
is the prior cookie-corrected baseline, not verification of the following delta.

## Bounded independent-review corrections (verification pending at root)

Schrodinger's two P2 findings were addressed only in cleanup and cache-policy
handling. Targeted semantic RED was 14 pass / 6 fail; final focused GREEN is
24/24 in 0.281 seconds across cleanup, gateway and runner tests, with five
changed JavaScript files passing syntax checks. Close rejection, both closure
orders, failed launch and hanging close are covered through the real cleanup
owner with a controlled external Browser.close boundary. Gateway tests use
real loopback transport, including missing/cacheable headers, actual no-store
positive controls, no retry/fallback and unavailable-response discrimination.

The cookie helper/tests and all browser journey actions remain unchanged.
No live browser/root, Cargo or full UI run was performed for this delta. Main's
full-root rerun and independent review of these fixes remain pending; these
component tests do not prove actual Chromium forced-tree cleanup. See ignored
`.superpowers/sdd/2026-09-04-working-mcp-gateway/task-3-ui-journey-fix-report.md`
for exact evidence and source hashes.

## Historical failure-only diagnostic delta

Main subsequently reported a no-artifact full-bin failure categorized `journey`
and an isolated no-artifact real-root failure categorized `cookie` (1.32s).
The following instrumentation diagnoses those failures; it does not fix or
establish their root cause. Main owns the actual-root rerun.

Only one new exact stderr category is introduced: `cookie_lifetime`. It means
the existing finite/future binding and valid issuance checks passed, but
`binding.expires <= issuedAt + 600` failed. All other cookie violations remain
`cookie`, including session count, attributes, expiry, missing issuance,
replacement and extension. The same values are accepted/rejected as before;
no tolerance, clock adjustment or renewed observation anchor was added.

Unknown dependency exceptions now use an in-memory static component label
instead of generic `journey`: browser setup, login, scope selection, response
body/JSON, inventory, privacy observation, optional artifact work, identity
creation/detail, parent protocol, offline verification or logout. Labels reuse
existing exact categories. Explicit known failures keep their original category.
These notifications produce no output or additional await; only the existing
failure line is emitted. No exception text/stack, URL, cookie, expiry, credential
or response data is serialized. The three stdout protocol markers are unchanged.
The component labels deliberately do not distinguish every repeated operation.

Focused RED: `node --test scripts/browser-journey/diagnostics.test.mjs scripts/browser-journey/cookies.test.mjs`
from `apps/operator-ui`: 42 pass / 8 fail, 0.056s. Failures were four unchanged
cookie rejections reporting the old category, plus four classifier tests
against the generic-journey scaffold. GREEN with `scripts/browser-journey/runner.test.mjs`
also included: **53/53, 0.216s**, no skipped/cancelled tests. Syntax checks
passed on all six changed JavaScript files. Tests cover static phase fallback,
explicit-category preservation, rejection of forged/multiline diagnostic
strings, and all 46 original cookie acceptance cases with diagnostic-only
expectation changes. There was no real browser/root, screenshot, Cargo or
Docker run by the sidecar. No tool sessions remain. Changes are unstaged;
the previously staged snapshot was not modified in the index.

Frozen diagnostic JavaScript SHA-256 (paths relative to `apps/operator-ui/scripts`):

| Path | SHA-256 |
| --- | --- |
| `browser-journey.mjs` | `B493987E5053A14FF47C16309887F344928CD4625861305910147289A50F141A` |
| `browser-journey/journey.mjs` | `7C76EE20E1C9333420FDDB43E7BBCFC6CED9A58CF95F7E19C52776C6AE82BA19` |
| `browser-journey/cookies.mjs` | `962B2B66700B10B747B9723DD7B252F67FB188383B335B7B197DF7A4DF3EBC20` |
| `browser-journey/cookies.test.mjs` | `C282A56D99D2C8902952C04CF869F4594BAE0CA3503EF8E8CC1FE6DEE0278D40` |
| `browser-journey/diagnostics.mjs` | `7EBF702DCA1B108B45DA16E7D3CD04AAE10A0E5E97880970BCBF8E62BA033A81` |
| `browser-journey/diagnostics.test.mjs` | `D38579E300893F81924F8BB65173BD50BD9522712F26DD266320DD70A195940D` |

## Current contract: original wire instruction + frozen browser expiry

Main reproduced the no-screenshot actual-root failure as `cookie_lifetime`
after the preceding count, security and expiry-validity checks passed. The
approved correction changes the test's proof, not production cookie behavior.
[Chromium's ParseExpiration and Create implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/cookies/canonical_cookie.cc)
derives Max-Age expiry from Chromium's creation time, not Node's response-event
Date.now. Installed Playwright 1.62.0 forwards Storage.getCookies expiry without
millisecond normalization (`lib/coreBundle.js:38344`). Its synchronous headers()
uses provisional headers; headerValues('set-cookie') awaits actual headers
(`lib/coreBundle.js:59614`). That installed file's SHA-256 is
`3258D1CF334C6AFC95F22AA9C292436CB976B391E0437F1359C83B84F0CB9D66`.
The Chromium reference explains the contract; it is not claimed as the exact
installed browser revision or a measured cross-process clock calibration.

`cookie-headers.mjs` validates actual original login GET/302 Set-Cookie data:
one canonical opaque __Host-apex_login, Secure, HttpOnly, SameSite=Lax, exact
Path=/, no Domain/Expires/unknown or duplicate attributes, and one canonical
integer Max-Age in 1..600. Production may shorten the remaining admission
lifetime (`apps/control-plane-api/src/browser/edge/login.rs:92`), so exactly
600 is not required. Header attribute names are case-insensitive. Parsing is
bounded before splitting: at most 8 Set-Cookie values, 4096 ASCII bytes each,
8192 bytes aggregate. Other cookie names are not confused with the binding.

`cookie-observer.mjs` reads only console-origin response cookies, never the
provider's cookie headers. It tracks every asynchronous read: at most 32 active
and 512 total responses, with no overflow queue. Each actual-header/jar read and
drain has a 5-second absolute bound, checked before dispatch and on settlement;
cancellation/timeout fails the entire journey, so abandoned reads cannot refill
the pool. Underlying browser RPC cleanup remains owned by browser shutdown.
There is no default Playwright timeout assumed for headerValues/context.cookies.
The frontend's existing 32 KiB upstream header bound still precedes this parser;
the parser cannot prevent Playwright's own allocation of an already received
header array. Monitoring every console response is intentional and bounded;
there is no new HTTP request, provider read, request fulfillment or cookie write.

After the real redirect reaches the Keycloak form, capture awaits the original
headers and a console-only jar **before filling/submitting credentials**. It
requires no session and exactly one matching secure binding, freezes that
binding's finite future absolute expiry, and cannot be called again. Later
checks retain exactly one authenticated session/none after logout, all original
privacy/storage/attribute/opaque checks, unchanged binding value and expiry no
greater than either the original or the preceding observed expiry. A removed
expired binding remains acceptable; an expired binding present is rejected.
Any later response issuing the binding is rejected, even the same value/age.

**Explicit proof boundary:** this verifies the BFF's actual bounded lifetime
instruction plus Chromium's retained absolute expiry. It does not independently
calibrate Chromium's cookie-creation clock against Node. There is no seconds
grace, precision guess, later-inspection + Max-Age deadline or browser fixture
injection. The removed cross-clock upper bound is deliberately replaced, not
silently described as unchanged acceptance. `cookie_lifetime` now means invalid
wire Max-Age; other observer failures remain static `cookie`. No new stderr
category, raw header, value, expiry, stack, URL or token output was introduced.

The journey drains observation before returning. Entrypoint awaits its final
drain **after successful browser/frontend cleanup and before PASS**; finalization
requires the page already closed. This keeps observation attached while any
later reply could arrive and makes late asynchronous validation failure
non-success. The existing cleanup owner, 4-second emergency, 120-second journey
watchdog, three stdout markers, UI actions, screenshots and provider/PG fixtures
are unchanged. Screenshot collection was not run for this correction.

### TDD evidence and frozen handback

From `apps/operator-ui`, initial command:
`node --test scripts/browser-journey/cookie-headers.test.mjs scripts/browser-journey/cookie-binding.test.mjs scripts/browser-journey/cookie-observer.test.mjs`
observed **60 tests: 26 pass / 34 fail, 0.075s**, against parser/capture/observer
scaffolds. Valid wire/snapshot cases failed, while missing observation, later
issuance, bounds and premature-finalization tests exposed missing rejection or
awaiting. The previous cross-clock jar validator remained during this RED.
No import/compile/fixture error. A subsequent focused late-poll regression was
also observed RED (one dispatched read versus zero), then fixed before handback.

Final focused command:
`node --test scripts/browser-journey/cookie-headers.test.mjs scripts/browser-journey/cookie-binding.test.mjs scripts/browser-journey/cookie-observer.test.mjs scripts/browser-journey/cookies.test.mjs scripts/browser-journey/diagnostics.test.mjs scripts/browser-journey/runner.test.mjs scripts/browser-journey/cleanup.test.mjs`
was **119/119 GREEN in 0.303s**, no skipped/cancelled tests. All nine changed/new
JavaScript files passed `node --check`; all are under 600 lines. The 46 existing
cookie cases remain, with superseded clock-specific cases now checking the
frozen original expiry/required original snapshot. New wire cases validate
the actual Max-Age ceiling independently. Observer tests use controlled external
Playwright-response/jar boundaries, not a real browser or a fabricated BFF proof.

Only the owned Node subtree changed. No Cargo/Docker, actual root/browser,
screenshots, commits, index writes or nested agents. No active tool sessions.
Main's repeated real-root runs and Schrodinger's independent review remain
required; component GREEN is not evidence that the intermittent root failure
is resolved. Source frozen; main owns continuation.

Current correction SHA-256 (paths relative to `apps/operator-ui/scripts`):

| Path | SHA-256 |
| --- | --- |
| `browser-journey.mjs` | `3F3E97751AF7223E82D4746AAA30AB3CC207322FC2825FFB850FEF302A720048` |
| `browser-journey/journey.mjs` | `D7587A0E7FA9177179A657F81CDF6B36910C6F97292FB8A9C814EF49E62D891F` |
| `browser-journey/cookies.mjs` | `6972E5B80641EA80D8693DE60EB2DD444ECD15B168F745C74949C26EFA5CF25E` |
| `browser-journey/cookies.test.mjs` | `C3A378D35A67CA7BE485EAFB808B1FDBB37DE3BA2817EEC398867A6DE7516526` |
| `browser-journey/cookie-headers.mjs` | `059B027AC592AB5D02D07A33A480321BD0D958666E8F30B61FDF13D5A8140064` |
| `browser-journey/cookie-headers.test.mjs` | `E5090C83C34F372FDE8516D40CD0E1174FA385DAFE6C268A5D54440476EFE8DC` |
| `browser-journey/cookie-binding.test.mjs` | `23618753BDAF05A1F5CD91E22F9DC96D30F8E2101E9B483D3DBF2331AB481C4B` |
| `browser-journey/cookie-observer.mjs` | `13222F55E10A57C57866DE15C4B769659AC984F429A6D1A1A7F5776FDCA178E9` |
| `browser-journey/cookie-observer.test.mjs` | `222B955A7C5036DAB5F301E790D72EF52260620D8C8C3FD26A54DFBB24F62337` |
