# Online runtime deployment binding

Approved scope: bind agent launch configuration to the PostgreSQL-published
revision before enabling container execution. A self-consistent manifest hash
does not prove publication or authorization.

## Authority boundary

`RuntimeDeploymentService.ResolveRuntimeDeployment` is a separate mTLS-only
unary RPC. Its input is the existing `CheckRuntimeAuthorityRequest`: exact target,
operation, command, installation and actually observed controller certificate
pin. There is no caller-supplied configuration or profile selector. The existing
check-only RPC and its 4,096-byte envelopes remain unchanged.

The response contains schema version 1, the existing authority snapshot, a
compiled RuntimeConfiguration, and deployment-bindings version. Request limit:
4,096 bytes. Response limit: 270,336 bytes. Configuration retains its existing
262,144-byte strict ProtoJSON/compiler limit. Resolution uses the existing fixed
PostgreSQL owner, current-operation checks, five-second monotonic budget,
enrollment intersection and original-request TLS rechecks.

## Protected deployment metadata

An optional `APEX_CONTROL_RUNTIME_DEPLOYMENT_BINDINGS_FILE` enables resolution
only alongside the configured PostgreSQL authority service. The deployment
owner protects the file and ancestors under the existing trusted base. The
existing single refresh thread reads it with peer policy and enrollment; no
per-request file I/O, new unbounded queue or fallback store is introduced.

The generated ProtoJSON RuntimeDeploymentBindingsDocument has schema version,
version, validity interval and 1..32 profiles; maximum 262,144 bytes. Each profile
selects exactly installation/workspace/namespace/proxy/revision and host-policy
version. Duplicate selector tuples are invalid. Profile fields are resource URL,
digest-to-image entries, secret references, tool schemas, approved output-profile
IDs, network grants, authentication, telemetry and PID limit. Generation is
injected from the current database operation, never accepted from metadata.
Raw secrets, arbitrary filesystem paths and container flags are not supported.

The selected document participates in the same local generation/freshness
boundary as enrollment and peer policy. Invalid/missing configured metadata
disables authority. Same-version/different-bytes replacement is refused against
the last accepted version in this process. This is not durable rollback defense.
Document expiry and metadata rotation invalidate in-flight resolutions.

## Agent consumption

The agent's pinned authority channel also hosts the generated deployment client.
Resolution shares its eight-call ceiling, five-second total budget, actual inbound
controller authentication and full authority-snapshot validation. It validates
target/configuration relation and manifest hash, returning a privately constructed,
redacted `ResolvedDeployment` with read-only accessors. No candidate manifest is
an input to resolution. A resolution is point-in-time data, not an execution permit.

Production ingress must use only this configuration and recheck current authority
after signature verification/staging and immediately before container effects.
The listener, owned effect executor and durable provisioning journal are outside
this slice and remain disabled/unimplemented until separately verified.

## Required evidence

Behavior tests cover strict metadata parsing, exact profile selection, compiler
input substitution, version immutability/rotation/expiry, agent response mismatch,
and real mTLS/PostgreSQL resolution. Preserve existing authority and runtime tests.
Do not represent successful compilation or a valid self-hash as publication proof.
