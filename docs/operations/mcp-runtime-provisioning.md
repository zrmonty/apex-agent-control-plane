# MCP runtime provisioning boundary

Status on 2026-09-06: authenticated production ingress and durable
**stopped-container provisioning** are implemented. The agent combines current
operation/configuration resolution, publication-bound launch/material selection,
protected catalogs, Linux Cosign verification, confined staging and bounded durable
container effects. The control plane uses authenticated `ReconcileRuntime` calls;
the production agent does not register legacy mutation RPCs.

This is not managed Serving. Protected paired gateway/guard staging and verified
paired creation/start/recovery remain unfinished. The reviewed local guard data
producer writes no stage and grants no execution permission. See the
[integration checkpoint](managed-runtime-checkpoint.md) and
[runtime continuation](../superpowers/plans/2026-09-05-runtime-execution-continuation.md)
for scoped acceptance and current publication status. Neither a callback snapshot,
signature nor staged directory can enable `Serving` by itself.

## Image catalog selection

`apex_proxy_runtime_agent::image_catalog::ImageCatalog::parse` accepts trusted bytes,
not an RPC-provided catalog or arbitrary file path. The production metadata owner
loads and refreshes the protected deployment file. The parser alone does not establish file ownership,
metadata freshness, registry reachability, image contents or signature validity.

Schema 1 supports exact-identity keyless signing constraints for the Cosign
verification boundary. Key-based and regular-expression identity policies are not
implemented. The following is a template, not an approved production image; replace
the organization, release identity and digest placeholder with reviewed values.

```json
{
  "schema_version": 1,
  "images": [{
    "id": "gateway-release",
    "image_ref": "ghcr.io/your-org/apex-mcp-gateway@sha256:<64-lowercase-hex-digest>",
    "signing": {
      "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
      "certificate_identity": "https://github.com/your-org/your-repo/.github/workflows/release.yml@refs/tags/your-release"
    }
  }]
}
```

The document is at most 65,536 bytes and contains 1–64 entries. IDs and full image
references are independently unique. IDs are 1–64 lowercase ASCII letters/digits
plus `.`, `_`, `-`, beginning with a letter/digit and excluding `..`. Image references
use the existing compiler-compatible registry/repository and lowercase SHA-256 shape,
at most 512 bytes. Tags, credential-bearing references, host paths and extra flags
refuse. Issuer and exact certificate identity are bounded to 2,048 printable ASCII
bytes. The issuer must be a canonical HTTPS URL without credentials, query or fragment.
The identity is an exact literal, never a regex or command-line fragment.

Unknown, missing, duplicate decoded fields, positional arrays in place of objects,
unsupported versions and signature-bypass switches refuse. Errors and Debug output
do not include catalog contents. `select(id, published_image_ref)` requires an exact
match and returns borrowed signing constraints. It performs no network or engine I/O.

## Remaining execution gates, in order

1. Bind the produced guard data to protected paired staging. Verify the selected
   gateway and guard images under the approved signing policy. Retain exact
   publication, launch, material, topology and durable ownership joins.
2. Connect paired create/inspect/start/recovery. Recheck current authority at each
   effect boundary. Preserve uncertain-effect quarantine and inspect actual network
   isolation. Existing stopped-container and empty-network tests are not start proof.
3. Compose the real HTTPS/session root, non-admitting readiness, route selection
   and short-lived admission renewal. Keep failure paths non-serving.
4. Prove pause/resume/retire, replacement, rotation/rollback and restart with actual
   traffic, physical drain and ownership-scoped cleanup.
5. Complete the fresh-install, two-proxy, durable activity and microsecond trace
   journey, then the integrated release gate. Use approved Apex images, not the
   public Cosign verifier fixture. Production release signing needs separate authority.

Task 8 enforced egress/routing and Task 9 admission/lifecycle remain separate gates.
Production readiness, G0–G3 acceptance and complete end-to-end microsecond tracing
remain open. Do not expose the Docker socket to a gateway, enable the legacy provider
as a shortcut, or treat an engine `running` observation as application readiness.

## Linux signature verification

`SignatureVerifier::open(executable, cache)` requires existing protected absolute
paths, rejects symlinks and writable/untrusted ancestors, and holds the executable
descriptor. The cache is private mode 0700 and must retain its inode and pathname.
Deployment administrators must preserve these paths and install a reviewed binary.
Root or the actual dedicated agent UID may own executable ancestors; the cache
must belong to the effective agent UID. Other platforms refuse without effects.

`verify` selects the ID and immutable digest from the deployment-owned catalog,
then executes the held binary with exact issuer/identity, claim checking, JSON
output, one Cosign worker and no insecure/regex overrides. This follows the
[official Cosign verification flags](https://github.com/sigstore/cosign/blob/v3.1.3/doc/cosign_verify.md).
Real verification includes signature, certificate and transparency evidence; parsing
the bounded output is an additional digest check, not signature verification itself.

One verifier instance admits one synchronous call via a non-waiting lock. It has no
queue or implicit thread pool. The production effect owner supplies bounded
blocking ownership. Child stdin is closed; inherited environment is cleared except for the
explicit protected HOME. Private-registry authentication is not implemented.
Output limits are 256 KiB stdout and 64 KiB stderr. Refusals do not expose either
stream, parser or process errors. Owned buffers are zeroized on refusal/drop.

Cancellation and a maximum requested 30-second budget kill the owned process group
and reap the direct child. The leader is observed without reaping before signalling,
so cleanup does not signal a recycled PID. Trusted tools must not escape their
process group, and the agent must not install a competing SIGCHLD auto-reaper.
Kernel spawn/reap can outlast a deadline: the blocking owner must retain its slot
until cleanup actually finishes. This is not a sandbox for arbitrary CLI programs.

## Linux secret staging

`StagingOwner::open(state_root, source_root)` opens existing separate, nonoverlapping
0700 roots through no-follow, descriptor-relative traversal. Every ancestor must be
root/effective-UID owned and not group/other writable. Supported effective UIDs are
0 and 10001; UID10001 also needs the matching group to seal files successfully.
Root-mode Linux acceptance is tested; UID10001 deployment acceptance remains open.

`stage(target, instance_id, revision_json, launch_json, materials)` validates all
material scopes before any source read. Sources are fixed basenames, private regular
single-link files of 1–65,536 bytes, checked before and after reading. Revision bytes
are bounded to 256 KiB; launch bytes to 16 KiB. This primitive treats those bytes as
opaque: it does not prove publication or validate the launch hash. Its metadata
parser also accepts bare secret identifiers; the gateway launch contract is stricter
and requires `secret://` for every material, with health matching `health.credentialRef`.
The launch owner enforces that stricter contract before calling stage.

The caller selects a canonical UUIDv7 before constructing launch bytes. Staging
creates only `apex-runtime-<instance_id>` with no-overwrite semantics. It writes
`runtime-revision.json`, `launch-context.json`, and fixed role filenames:

- `health-token` (43 canonical base64url characters encoding 32 bytes)
- `governance-{ca,cert,key,token}` and `evidence-{ca,cert,key,token}`
- `inbound-jwks` and `workload-{ca,cert,key}`

Files are fsynced and sealed 0400 UID/GID10001; the directory is sealed 0500 and its
parent fsynced. The state pathname is checked against the held inode before source
reads and before returning. The deployment owner must keep that pathname stable
through mount/use; a later trusted rename is not prevented by a returned Path.
No automatic rollback or Drop cleanup removes files: failures may leave an owned
quarantine, and success may be backing live read-only mounts. The durable effect
owner supplies mount verification and targeted recovery cleanup for the stopped
gateway path. This primitive alone supplies none of those guarantees; paired
gateway/guard staging and running-container lifecycle remain separate work.

## Acceptance split

Ordinary package tests remain non-root. The explicit `staging-integration` feature
enables the real Linux filesystem test target; CI compiles its exact executable and
runs it as root on the disposable runner. Production code is not feature-gated.
The network Cosign test is marked ignored in ordinary unit runs and is explicitly
required with `--exact --ignored` in the same CI acceptance step, not silently skipped.
That step also requires filesystem attacks/held-executable acceptance and a positive
protected-cache open as dedicated nonroot UID1001, separate from container UID10001.

The real fixture uses Cosign **v3.1.3**, release SHA-256
`4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`, to verify
`ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8`.
Its exact signer is `keyless@projectsigstore.iam.gserviceaccount.com`, issuer
`https://accounts.google.com`; a wrong identity must fail. These are public verifier
test fixtures, not an approved Apex image or proof of production readiness.
