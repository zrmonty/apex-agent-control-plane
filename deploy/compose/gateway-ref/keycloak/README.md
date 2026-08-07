# Lab Keycloak realms for the control gateway's operator-credential verifier

**Local/CI only.** Imported by `deploy/compose/compose.control-keycloak.yaml`
into a `start-dev` Keycloak with an in-memory database, re-imported from source
on every start. The client secrets in these files are fixtures; they authorize
nothing outside this profile and are not credentials in any deployment sense.
A real deployment issues clients through Keycloak's own admin flow and never
commits their secrets.

Keycloak's realm importer rejects unknown keys (`_comment` included), so the
explanation of what each client is for lives here rather than inline.

## Why a real Keycloak at all

`apps/control-plane-api/src/keycloak/tests.rs` already covers every rejection
offline, against locally minted tokens and a fixture JWKS. What it cannot cover
is the shape Keycloak actually emits: where the `typ` claim lives, that a realm
publishes an `enc` key alongside the `sig` one, that an access token and an ID
token are distinguishable at all, and what a `kid` looks like. A hand-rolled
mock and a hand-rolled verifier can agree with each other while both disagree
with the identity provider.

## `apex-realm.json`

Realm `apex`. Issuer `https://keycloak:8443/realms/apex` (fixed by
`KC_HOSTNAME`, so a token minted through the published host port still carries
the in-network issuer the gateway is configured with).

One realm role, `apex-control-break-glass`. On its own it confers nothing: the
gateway additionally requires the token's `sub` to appear in its
locally-configured `APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS` allow-list, which is
the part the identity provider does not control.

Every client below is service-accounts-only (`client_credentials`), so the live
test can mint real tokens without driving a browser flow. Each carries an
audience mapper for `apex-control-gateway` and a hardcoded `apex_control_scopes`
claim, because a scope claim is what a deployment's own protocol mapper would
produce from group membership.

| Client | What it is for |
|---|---|
| `apex-control-gateway` | The positive case. Scope claim `["acme/prod"]`, 300s tokens. |
| `apex-control-break-glass` | Same, plus a hardcoded `apex-control-break-glass` realm role, so the live test can prove the role alone does **not** confer the `*` scope and that role + local allow-list together does. |
| `apex-control-overbroad` | Scope claim `["*"]`. The misconfigured-mapper case: the gateway must refuse the whole credential rather than widening to a global scope or silently dropping the entry. |
| `apex-control-shortlived` | `access.token.lifespan` of 1 second, so an expired-but-genuinely-Keycloak-signed token can be presented without waiting out the realm default. |
| `apex-control-longlived` | `access.token.lifespan` of 12 hours. A real Keycloak signature on a credential that is simply not short-lived; the gateway's `exp - iat` ceiling must refuse it. |
| `apex-control-wrong-audience` | Audience mapper for `some-other-service`. Proves the audience check bites against material Keycloak actually issued. |

## `other-realm.json`

A second realm, `other`, on the same Keycloak, with its own signing keys and
deliberately the *same* `clientId` and the *same* audience mapper. The only
things distinguishing its tokens are the issuer and the signing key, so a
verifier that checked the audience but not the issuer would accept them.
Issuer confusion is one of the acceptance tests the product vault's
*Authentication and Identity* note calls for by name.
