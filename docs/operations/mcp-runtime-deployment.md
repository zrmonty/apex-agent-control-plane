# Authoritative runtime configuration resolution

The control plane can now resolve a runtime configuration from the current
PostgreSQL-published revision and protected deployment metadata. The runtime-agent
client consumes that result over pinned mTLS. This closes the **RuntimeConfiguration
publication-binding boundary**, not production ingress or container provisioning.

`RuntimeLaunchContext` construction, material-role selection, signature/staging
composition, durable container ownership, egress and admission remain separate
execution gates. A valid manifest, resolution, signature or staged directory is
never an execution permit. No gateway is marked `Serving` by this RPC.

## Enable the control-plane endpoint

Keep the existing [authority settings](mcp-runtime-authority.md), including explicit
PostgreSQL, trusted secret base, server/client TLS trust, peer policy and enrollment.
Add `APEX_CONTROL_RUNTIME_DEPLOYMENT_BINDINGS_FILE` with the protected document path.
Relative paths resolve against `APEX_CONTROL_TRUSTED_SECRET_BASE`; absolute paths
must pass the existing trusted-base confinement checks. The deployment owner must
protect both the file and its ancestors from untrusted writes.

The new setting without the authority pair/database is a startup error. An empty
path, missing file or structurally invalid initial document fails startup. Absent
this setting, the root continues to expose only the existing check service; the
deployment service is not registered. There is no development or in-memory fallback.

This is a workload mTLS endpoint on the existing control listener, not a browser API.
The browser allowlist is unchanged. There are no raw secrets in the request or reply.

## Generated metadata contract

The canonical schema is `contracts/proto/apex/v1/proxy_runtime_deployment.proto`.
Use generated `RuntimeDeploymentBindingsDocument` ProtoJSON, not Rust struct JSON.
Unknown fields, decoded duplicate keys, conflicting aliases, unknown enums and
noncanonical uint64 encodings refuse. All uint64 values are decimal **strings**,
including nested telemetry `maxExportQueueBytes`.

| Document field | Requirement |
|---|---|
| `schemaVersion` | Integer 1 |
| `version` | Scope-identifier grammar, at most 128 bytes |
| `validFromUnixUs`, `expiresAtUnixUs` | Positive signed-SQL-range microseconds; half-open validity interval |
| `profiles` | 1–32 profiles; complete document at most 262,144 bytes |

Each profile selects **one exact** installation/workspace/namespace/proxy/revision.
Installation, proxy and revision IDs are canonical lowercase UUIDv7. Workspace and
namespace use the existing exact scope grammar. Duplicate selector tuples refuse,
even if their host-policy versions differ. There are no wildcards or priority rules.

| Profile field | Meaning |
|---|---|
| `installationId`, `workspaceId`, `namespaceId`, `proxyId`, `revisionId` | Exact enrolled and published target |
| `hostPolicyVersion` | Must equal the installation's enrollment-selected version |
| `resourceUrl` | Canonical gateway HTTPS audience matching published ingress |
| `images` | Unique `{digest, imageRef}` entries; compiler selects the published digest |
| `secretRefs` | Exact declared union of revision secret references, never secret bytes |
| `toolSchemas` | Exact exposed upstream/tool pairs and bounded schema metadata |
| `approvedOutputProfiles` | Unique approved profile identifiers, not policy bodies |
| `networkGrants` | Exact published destinations plus approved CIDR metadata |
| `auth` | Explicit issuer, audience, JWKS, scopes and workload-identity reference |
| `telemetry` | Existing bounded ProxyTelemetryPolicy; integer microsecond contract retained |
| `pidLimit` | Compiler-supported host PID bound |

Generation is deliberately absent from the file. The current verified operation
supplies it. The compiler retains the full published spec and historical control
hash, then computes the separate runtime manifest hash. Image signatures are still
verified independently against the agent's approved signing catalog. Network-grant
metadata is not proof that host egress enforcement exists.

The existing compiler rejects unsupported CLI/stdio shapes and missing security
metadata. Structural document validity does not prove that every profile compiles
against its future selected revision; resolution refuses compiler-incompatible
profiles without returning partial configuration.

## Online request and response

`apex.v1.RuntimeDeploymentService/ResolveRuntimeDeployment` takes the existing
`CheckRuntimeAuthorityRequest`. It accepts only target, operation, command,
installation and the agent's actual observed controller certificate pin. It accepts
no candidate configuration, image override, profile body, filename or secret value.

The service authenticates the actual agent TLS certificate, intersects its grant
with the observed-controller grant and enrollment, and derives the controller's
worker identity from protected metadata. The existing fixed PostgreSQL worker
verifies current operation, target, fencing token, lease, publication and row/blob
consistency. Only that returned revision reaches the compiler.

The response contains schema version 1, `RuntimeAuthoritySnapshot`, compiled
`RuntimeConfiguration` and `deploymentBindingsVersion`. Request limit is 4,096 bytes;
complete response limit is 270,336 bytes. Existing check-only request/reply limits
remain 4,096 bytes. Complete configuration ProtoJSON remains limited to 262,144 bytes.

Both services share the existing bounded database queue and monotonic request/lease
checks. Compilation and envelope sizing precede final elapsed-budget and metadata
generation checks. No request holds a policy lock over an await or performs file I/O.

## Metadata rotation and currentness

The existing single reader samples all configured files every second, including
file-read time in a two-second maximum-age bound. Invalid or missing configured
deployment metadata disables the shared authority state, including check-only calls.
Identical reads refresh age without invalidating in-flight requests. Different
accepted content gets a new internal generation and invalidates old requests.

Changing bytes while retaining the last accepted version refuses, even after a
temporary disable. Publish a new document version for changes. This check is local
to the running process and last accepted document, not a durable rollback ledger
or an atomic multi-file deployment transaction. Peer/enrollment version matching
and exact host-policy matching still apply. Deployment operators own safe rotation.

## Agent API and future effect owner

`RuntimeAuthorityClient::resolve(original_request, current_policy, operation, budget)`
uses the same pinned channel and eight-call admission ceiling as `check`. It derives
controller identity from the original TLS request, forwards no inbound headers,
caps the whole call at five seconds and validates all authority snapshot fields.
It also checks configuration/target relation, control hash, recomputed manifest,
response size and deployment-version grammar.

The privately constructed, redacted `ResolvedDeployment` exposes only read-only
`configuration()`, `authority()` and `bindings_version()` accessors. It is not a
durable capability. The future production effect owner must use this configuration,
refresh its policy and recheck online authority after expensive verification/staging
and immediately before each container effect. It must additionally bind and validate
launch context and material roles; those are not supplied by this resolution RPC.

Failures expose static `RUNTIME_AUTHORITY_*`, `PROXY_RUNTIME_OPERATION_NOT_CURRENT`
or `RUNTIME_AUTHORITY_CLIENT_*` codes. Do not log complete messages, manifests,
transport errors, deployment file contents or secret references.

## Verification scope

Tests cover strict metadata parsing and exact compilation; immutable version and
generation handling; actual mTLS/PostgreSQL resolution; existing-channel file
rotation and missing-source refusal; and a separately compiled agent client against
the actual production control root, including wrong-role and stale-lease refusal.
The probe is test-only Controller ingress, not a production agent service.
See [release evidence](mcp-gateway-release-evidence.md) for executed results.
