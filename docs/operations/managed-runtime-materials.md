# Sealed runtime material composition

`createManagedRuntimeMaterials(stageOwner, nowUnixUs)` composes the reviewed
[sealed-stage owner](managed-stage-owner.md), [purpose-aware TLS roles](managed-tls-materials.md)
and [upstream bundles](managed-upstream-material.md). It performs no file/network
I/O and grants no admission or readiness. Only a genuine local stage-owner handle
can provide bytes; a matching object or self-declared configuration cannot.

The caller still owns the stage on both success and failure. After all consumers
have copied their material, dispose the stage and await its bootstrap `closed`
promise. A successful material constructor does not prove physical file closure.
Disposing runtime materials does not dispose the caller's original stage.

## Purpose and separation

- Governance and evidence use their own client-purpose TLS triplets.
- Ingress uses the explicit schema-3 WORKLOAD triplet as a server identity,
  matching the protected ingress TLS server name.
- All three leaf identities and public keys must differ, including certificates
  reissued with the same private key.
- Each unique published upstream `credentialRef` uses its explicit versioned
  bundle. Its client key must differ from all three critical runtime keys.
- Governance, evidence, health and instance-proof credentials must have different
  underlying raw bytes. Decoded canonical health-token bytes cannot equal the
  proof or authority token bytes. Upstream bearer tokens cannot reuse any of
  those protected credentials.

The proof is exactly 32 nonzero-as-a-whole bytes. Health uses the existing
canonical 43-character base64url profile. Authority bearer values use 16–4096
allowed ASCII token characters plus at most two trailing padding characters,
with no controls or `Bearer ` prefix. This does not prove randomness, global
credential uniqueness or remote enrollment; protected provisioning still owns
those guarantees.

The earliest server/client/issuer certificate expiry is retained as exact integer
Unix microseconds. Runtime admission/readiness must enforce expiry continually;
construction-time preflight is not ongoing authorization or full PKIX validation.

## API and lifetime

The immutable opaque owner exposes only binding, expiry, selected reference list
and public TLS fingerprints. There is no secret-bearing debug/JSON surface.

| Helper | Allowed selector / result |
| --- | --- |
| `runtimeTlsMaterial` | `governance`, `evidence`, `ingress`; copied CA/cert/key |
| `runtimeTokenMaterial` | `governance`, `evidence`, `health`, `instance-proof`; copied bytes |
| `runtimeJwksMaterial` | Copied staged JWKS bytes; JWT factory must validate them |
| `runtimeUpstreamMaterial` | Exact selected published credential reference; copied bundle material |
| `disposeRuntimeMaterials` | Revoke future access and wipe owned buffers/child owners |

Each returned buffer belongs to its consumer, which must retain it until the
associated physical transport work closes and then wipe it. A caller can neither
mutate the owner's material through a copy nor retrieve bytes from a forged or
disposed handle. Failure cleans partial ownership with one static error, without
changing source-stage bytes. JavaScript strings, garbage-collected native keys,
TLS internals and external consumer copies prevent a whole-process zeroization
guarantee.

## Integration boundary

This layer interprets selected upstream credentials, not CLI secret profiles,
per-subject outbound auth bindings or other unused references. Those require
their explicit execution/compilation gates; the existence of metadata or staged
bytes does not implement those behaviors. The separate inbound verifier must
validate JWKS and user tokens before authentication. Root composition must still
establish the inspected guard route, real channels, readiness, mandatory durable
evidence, expiry-aware admission and physical shutdown.

Tests exercise content/key reuse, invalid roles and clocks, defensive copies,
forged handles, source-stage independence and explicit allocation wiping on late
failure/disposal. A native TLS test uses copied composed credentials after source
stage and material-owner disposal. Its stage-loader fixture is synthetic; it is
not protected FD-stage, real edge or production Serving acceptance.
