# MCP runtime provisioning boundary

Task 7 provisioning is **not operational yet**. The agent has a current-operation
callback client and a deployment-owned image catalog parser. It does not yet have
a production listener, signature verifier, trusted secret-staging owner or container
effect owner. A callback snapshot or catalog match cannot enable `Serving`.

## Image catalog selection

`apex_proxy_runtime_agent::image_catalog::ImageCatalog::parse` accepts trusted bytes,
not an RPC-provided catalog or arbitrary file path. Its owner must eventually load
and refresh a protected deployment file. The parser does not establish file ownership,
metadata freshness, registry reachability, image contents or signature validity.

Schema 1 supports exact-identity keyless signing constraints for the planned Cosign
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

1. Compose actual Controller mTLS ingress with current deployment metadata and the
   operation context needed by the callback. The existing Ensure wire request does
   not yet supply the operation/command correlation required by this composition.
2. Resolve an approved catalog entry and verify the pinned image's signature with
   the deployment's exact issuer/identity policy, chain and transparency evidence.
   Own bounded verifier/registry work, cancellation and redacted output; no bypass flags.
3. Stage immutable per-revision configuration and scoped credential files under an
   agent-owned root. Enforce traversal/symlink protection, mode 0400, UID 10001 and
   read-only mounts. Credentials must not enter argv, Docker environment, logs or RPCs.
4. Persist installation ownership and generation/fencing state, then perform bounded,
   constrained OCI effects. Recheck operation/currentness at effect checkpoints;
   inspect exact ownership and host restrictions rather than trusting requested flags.
5. Replace the control plane's legacy direct Docker provider with authenticated agent
   calls. Keep unavailable agents fail-closed. Prove duplicate/retry/restart behavior
   and two-proxy isolation before claiming provisioning is operational.

Task 8 enforced egress/routing and Task 9 admission/lifecycle remain separate gates.
Production readiness, G0–G3 acceptance and complete end-to-end microsecond tracing
remain open. Do not expose the Docker socket to a gateway, enable the legacy provider
as a shortcut, or treat an engine `running` observation as application readiness.
