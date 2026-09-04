# Managed MCP proxy threat model

Status: implementation baseline for the Apex managed proxy platform  
Scope: control-plane lifecycle, one isolated OCI runtime per proxy, upstream
sessions, fixed CLI profiles, operator UI, and durable activity evidence.

## Trust boundaries

1. The operator browser is an untrusted client. It may request state and
   mutations, but it never holds policy authority, Docker access, or secret
   values.
2. The control plane is the authority for exact workspace/namespace scope,
   immutable revisions, approval, lifecycle, and durable proxy activity.
3. The proxy runtime is a constrained execution boundary. It may use only the
   upstreams, tools, credentials, and egress destinations in its published
   revision.
4. Upstream MCP servers and discovered catalogs are untrusted external input.
5. The secret provider is a separate authority. Control state stores references
   such as `secret://...`; values are resolved only inside the runtime path.
6. Analytics projections are downstream consumers and must not be able to
   erase or retroactively change an admitted activity record.

## Threat/control matrix

| Threat | Required control | Evidence to retain |
| --- | --- | --- |
| Token passthrough or token confusion | Verify exactly one bearer header; bind issuer, audience, expiry, subject scope, and proxy ID; never forward inbound tokens as upstream credentials | Safe auth decision and trace metadata; never the token |
| Confused deputy | Authenticate the operator/agent against the exact workspace and namespace before every read or mutation; recheck revision identity server-side | Scope, actor, proxy, and revision IDs |
| Tool poisoning | Quarantine discovery; expose only a server-validated explicit tool allowlist; treat names, descriptions, and schemas as untrusted text | Catalog hash and selected tool alias |
| SSRF | HTTPS-only destinations; exact declared host/port; reject userinfo, local names, private ranges, metadata ranges, and unsafe redirects; revalidate DNS answers | Destination policy result and upstream ID |
| DNS rebinding | Resolve and validate every connection target, including redirect targets; do not trust the first lookup forever | Validated origin and connection trace |
| CLI injection | Fixed executable path and digest, fixed argv, typed scalar fields, `shell=false`, bounded timeout/output, sanitized environment, and approved exit codes | Profile ID, exit code, sizes, and duration |
| Secret leakage | References only in control state; no secrets in query keys, DOM, logs, event payloads, argv, environment, or error text; bounded credential provider | Reference identifier only, if operationally required |
| Container escape | Rootless uid/gid, read-only rootfs, no-new-privileges, all capabilities dropped, bounded tmpfs/PIDs/CPU/memory, no host mounts, and no runtime socket | Rendered OCI/Compose security settings |
| Cross-proxy session/cache access | One session map, discovery cache, credential scope, and runtime handle per `(proxy_id, revision_id)`; no process-global upstream state | Proxy/revision/session correlation without raw state |
| Replay or duplicate mutation | UUIDv7 request IDs, exact payload hash and scope matching, immutable published revisions, and idempotent provider keys | Request ID, operation, revision, status |
| Stale revision execution | Require expected revision on mutations; load the stored revision immediately before deployment and authorization; reject mismatches | Expected/current revision IDs |
| Approval bypass | Approval is a server-side authority; missing/false approval fails closed; approved `requires_approval` calls continue only after the decision is recorded | Approval outcome and policy ID |
| Evidence loss | Admit activity before returning an allowed result; denial remains denied if telemetry is unavailable; downstream projection is not the admission commit | Receipt ID, event status, bounded sizes |
| Unbounded input/output | Bound body size, identifiers, discovery catalogs, argv, CLI output, event metadata, rate, concurrency, and runtime resources | Rejection code and safe limits |
| UI trust escalation | Client is a view of server state; no local readiness claims; refetch after mutation; render remote labels and error text as text | Server status and revision |
| Availability abuse | Per-proxy admission/rate/budget controls, bounded retries, timeouts, and explicit degraded/failed states | Policy revision and latency metadata |

## Security invariants

- An allowed call has a complete chain: authenticated caller → exact proxy
  revision → explicit tool → Apex authorization → policy snapshot → rate and
  budget admission → egress decision → upstream call → output filter → event
  admission.
- No raw upstream response, token, credential, CLI environment, or secret
  value is included in activity evidence.
- If authorization, policy, approval, filtering, egress, or evidence admission
  cannot be established, the call does not return an allowed result.
- A published revision is immutable. Changes create a new revision and require
  fresh validation, approval, and deployment.
- A provider restart converges to at most one active runtime per proxy and
  revision, and an old revision is drained before termination.

## Residual risks and next proof

The Docker adapter currently provides the provider command boundary and a
testable reconciler, but production startup still fails closed until a durable
proxy event sink and live runtime wiring are configured. The next acceptance
gate must exercise real container health, secret-provider resolution, upstream
TLS, and proxy activity through the control-plane endpoint. This document does
not claim those live prerequisites are complete.
