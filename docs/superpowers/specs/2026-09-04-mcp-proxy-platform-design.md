# Apex Managed MCP Proxy Platform

**Status:** Accepted design
**Date:** 2026-09-04
**Scope:** Managed MCP proxies, operator UX, isolated runtimes, authentication, CLI execution, governance, evidence, and deployment lifecycle.
**Roadmap authority:** `docs/roadmap.md`

## 1. Purpose

Apex will provide a managed MCP proxy platform. An operator can create many proxies from the existing React operator console, configure each proxy independently, and deploy each proxy into its own hardened OCI container.

The proxy is the governed data-plane boundary between an AI client and an approved MCP server, API, document source, database adapter, or CLI runner. Apex remains the enforcement and evidence layer. The proxy must not become a second policy engine, identity authority, audit store, or workflow system.

The target flow is:

```text
Operator UI
  -> typed control-plane client
  -> Rust control-plane API
  -> durable desired state and lifecycle command
  -> proxy reconciler
  -> one isolated OCI container per proxy
  -> upstream MCP server, API, or approved CLI runner
  -> Apex authorization and evidence
  -> filtered tool result and operator activity
```

This design extends the existing narrow `portfolio.read` gateway slice. It does not invalidate the completed live vertical slice or authorize unrelated roadmap work.

## 2. Repository alignment

The current repository already provides the important seams:

- `apps/operator-ui` is a React 19 + TypeScript + Vite console with TanStack Router and TanStack Query.
- The operator UI is a static browser application. It must use generated API clients and must not own policy, identity, secrets, or durable state.
- `apps/mcp-gateway` is a thin TypeScript MCP gateway. It currently exposes one read-only tool over stdio and delegates governance and evidence to Apex.
- `apps/control-plane-api` is the Rust control authority with operator authentication, mTLS, durable outbox/inbox behavior, approvals, and command delivery.
- `crates/apex-policy` is the transport-neutral governance boundary for scope, identity, authorization, approvals, and content-free tool evidence.
- Protobuf contracts under `contracts/proto/apex/v1` are the contract source of truth.
- PostgreSQL is the mutable control-state authority. NATS JetStream, ClickHouse, and immutable archive paths remain downstream evidence and analytics destinations.
- The existing operator UI navigation contains Overview, Agent groups, Event stream, Findings, Evidence vault, Retention, Deployment, and Settings. `MCP proxies` is the next focused surface.

The current gateway remains a useful implementation seed. The managed platform needs a separate lifecycle/control boundary around proxy instances so the browser never creates containers or embeds deployment logic.

## 3. Product boundary

### Apex owns

- Workspace and namespace scope.
- User, agent, operator, and service identity.
- Policy and authorization decisions.
- Approval and high-impact action controls.
- Credential issuance, binding, rotation, and revocation workflows.
- Durable command and evidence records.
- Redaction policy and retention policy.
- Operator-visible status, activity, and audit correlation.

### The proxy owns

- MCP transport termination and protocol compatibility.
- MCP upstream client connections.
- Tool discovery quarantine and explicit exposure selection.
- Input schema validation and bounded request handling.
- Adapter routing.
- CLI command-profile execution.
- Network and runtime policy enforcement delegated to its deployment profile.
- Output validation, filtering, and data minimization.
- Structured metadata for the Apex governance and evidence calls.

### The proxy must not own

- A local policy database that can override Apex.
- A second audit or evidence store.
- Browser-held credentials.
- An unrestricted shell.
- A Docker or Kubernetes control socket.
- Cross-proxy sessions, caches, credentials, or temporary files.
- Direct autonomous trading or other high-impact actions without the approved Apex flow.

## 4. Runtime topology

### 4.1 One proxy, one isolated runtime

Each deployed logical proxy receives one OCI container. The container has its own:

- `proxy_id` and immutable `revision_id`;
- service identity and certificate;
- secret-reference namespace;
- network egress policy;
- resource budget;
- MCP endpoint and tool catalog;
- upstream connection pools;
- temporary filesystem;
- health and readiness state; and
- evidence correlation namespace.

Multiple configured proxies must never share MCP sessions, access tokens, cookies, tool catalogs, response caches, environment variables, or temporary files.

The first provider is Docker/OCI because it matches the current self-hosted deployment. The provider interface must hide Docker-specific details so a later Kubernetes workload or microVM provider can implement the same lifecycle contract. The browser never receives a runtime-provider credential.

### 4.2 Container baseline

The deployment controller must request the following baseline unless a stricter profile is selected:

- Pinned and signed image digest.
- Non-root UID and GID.
- Read-only root filesystem.
- `no-new-privileges`.
- Dropped Linux capabilities.
- No privileged mode.
- No host network.
- No host PID or IPC namespace.
- No Docker or container-runtime socket.
- No broad host filesystem mounts.
- Bounded writable temporary storage.
- CPU, memory, PID, file-descriptor, and process-start limits.
- Request body, response, log, and decompression limits.
- Explicit liveness, readiness, and shutdown deadlines.

Rootless execution is preferred where the deployment provider supports it. Container security controls follow Docker's guidance on reduced privileges and capability removal: [Docker Engine security](https://docs.docker.com/engine/security/) and [Docker rootless mode](https://docs.docker.com/engine/security/rootless/).

### 4.3 Network policy

Default egress is deny-by-default. A proxy may reach only declared destinations:

- Apex governance and event endpoints.
- The configured identity and secret providers.
- Declared upstream MCP endpoints.
- Declared API endpoints.
- Declared CLI destinations.

Every URL is normalized before policy evaluation. The runtime must validate scheme, hostname, port, DNS result, IP range, redirect destination, certificate identity, response size, and decompression ratio. Loopback, link-local, multicast, private ranges, cloud metadata services, and Unix-socket escapes are denied unless a server-side policy explicitly allows a specific destination.

The proxy must revalidate the destination after DNS resolution and at connection time. Redirects must be revalidated; a safe initial URL must not authorize an unsafe final URL. These rules follow the allowlist and metadata-service protections in [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## 5. Operator UI

### 5.1 Routes and navigation

Add `MCP proxies` to the primary navigation below `Agent groups`.

```text
/mcp-proxies
/mcp-proxies/$proxyId
/mcp-proxies/$proxyId/activity
```

The collection page uses the existing Apex shell, breadcrumb, typography, spacing, colors, responsive behavior, and explicit unavailable/loading/empty/denied states.

The collection page contains:

- A page heading and short explanation of the proxy boundary.
- A prominent large `+ New proxy` button.
- Search by name, slug, proxy ID, or owner.
- Scope, environment, status, policy, and health filters.
- A card or dense-row view for each proxy.
- A visible indicator for draft, provisioning, ready, degraded, paused, failed, and retired states.
- Active revision, last deployment, upstream count, exposed-tool count, and policy state.
- A server-derived freshness indicator for live activity.

### 5.2 Creation flow

The large plus opens a wizard. A draft is created immediately with a server-generated ID and remains non-routable until published.

#### Step 1: Identity

- Display name and slug.
- Workspace and namespace.
- Environment.
- Owner and operational contact.
- Optional description and tags.

#### Step 2: Ingress

- Streamable HTTP endpoint or controlled stdio mode.
- Private or externally reachable exposure.
- Host and path assigned by the control plane.
- Allowed origins.
- MCP protocol revision.
- Inbound authentication requirement.

Streamable HTTP must validate `Origin`, authenticate every connection, and use the current supported MCP transport contract. Local stdio must not write non-MCP data to stdout. [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

#### Step 3: Upstreams

- Add one or more upstream connections.
- Select stdio or Streamable HTTP.
- Provide a declared URL or command-profile reference.
- Select an outbound credential binding.
- Run discovery and a bounded handshake.
- Display discovered tools, resources, prompts, capabilities, server identity, and schema hashes.

Discovery is quarantined. No discovered tool is exposed until the operator explicitly selects it and Apex policy accepts the binding.

#### Step 4: Tool exposure

- Select individual tools.
- Set stable aliases when upstream names collide.
- Select read, business-write, or high-impact classification.
- Set input schema limits and output classification.
- Configure response redaction and field minimization.
- Configure timeout, rate, concurrency, and result-size limits.

#### Step 5: CLI runners

- Select an approved CLI profile.
- Review executable digest and image identity.
- Review typed argument schema.
- Select permitted environment and secret references.
- Review filesystem, network, timeout, and output limits.

#### Step 6: Authentication and governance

- Bind inbound identity and scopes.
- Bind outbound credential references.
- Select Apex policy.
- Select approval mode.
- Set data classification and retention.
- Set rate and budget ceilings.

#### Step 7: Review and deploy

- Show a redacted configuration diff.
- Show all tools, upstreams, credential references, egress destinations, CLI profiles, and policy bindings.
- Run schema, policy, credential, network, and connectivity validation.
- Save as draft or publish a revision.
- Require explicit confirmation for deployment.

The UI may show a connection-test result, but a test is never proof of authorization. The final call still passes through Apex.

### 5.3 Proxy detail page

The detail page uses tabs:

- **Overview:** state, endpoint, revision, owner, scope, health, and next safe action.
- **Upstreams and tools:** upstream connection status, discovery results, tool exposure, schemas, and drift.
- **Authentication:** inbound method, outbound bindings, issuer/audience, expiry state, and rotation action. Never show secret values.
- **CLI runners:** command profiles, executable identity, policy, limits, and recent results.
- **Governance:** policy binding, approval tier, classification, budget, rate, and redaction posture.
- **Runtime:** container revision, image digest, resource limits, network destinations, readiness, and restart history.
- **Activity:** server-derived calls, decisions, approvals, failures, evidence receipts, and lifecycle changes.
- **Revisions:** immutable revision list, diffs, deployment state, rollback, and retirement.

Actions must be explicit and scope-checked: `Validate`, `Deploy`, `Pause`, `Resume`, `Rotate`, `Rollback`, `Duplicate`, and `Retire`.

The UI follows the existing operator UI decision: generated typed clients, server-side authorization, secure HTTP-only sessions, no browser token storage, and untrusted content rendered as text. See `docs/architecture/Operator UI Framework.md`.

## 6. Configuration model

The API stores secret references, not secret values. Configuration is split into mutable draft state and immutable published revisions.

```text
McpProxy
  proxy_id
  display_name
  slug
  workspace_id
  namespace_id
  environment
  owner
  desired_state
  observed_state
  active_revision_id

McpProxyRevision
  revision_id
  proxy_id
  immutable_spec
  config_hash
  policy_id
  approval_state
  validation_state
  created_by
  created_at

ProxySpec
  ingress
  upstreams[]
  exposed_tools[]
  cli_profiles[]
  auth_bindings[]
  governance_binding
  runtime_profile
  retention_profile

UpstreamBinding
  upstream_id
  display_name
  transport
  endpoint_or_command_ref
  server_identity
  discovery_policy
  credential_ref
  network_policy
  tool_catalog_hash

CliProfile
  profile_id
  executable_ref
  executable_digest
  fixed_argv_template
  input_schema
  working_directory
  environment_allowlist
  secret_refs[]
  filesystem_policy
  network_policy
  timeout_ms
  max_output_bytes
  allowed_exit_codes[]

GovernanceBinding
  policy_id
  approval_mode
  data_classification
  rate_limit
  concurrency_limit
  budget
  retention
```

A published revision is content-addressed by `config_hash` and cannot be edited. A change to identity, tool exposure, upstream, credential, policy, image, network, or runtime limits creates a new revision.

## 7. Authentication

### 7.1 Inbound HTTP

Each HTTP proxy endpoint acts as its own protected MCP resource:

- Publish OAuth protected-resource metadata.
- Advertise the authorization server.
- Return a standards-compliant `401` challenge.
- Require HTTPS.
- Use PKCE for authorization-code flows.
- Validate issuer, audience, expiry, not-before, scopes, tenant, and proxy identity.
- Bind the caller to Apex user, agent, workspace, namespace, and run context.
- Reject a token issued for another proxy.

The proxy uses the MCP `resource` parameter and audience-restricted access tokens. It supports pre-registered clients first; dynamic registration or Client ID Metadata Documents are provider capabilities that require explicit trust policy. The proxy must never accept a token simply because it was valid for a different upstream. [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)

### 7.2 Inbound stdio

Stdio credentials are supplied by the controlled launching host or runtime environment. The proxy must not attempt HTTP OAuth discovery over stdio. Credential values are read only by the runtime and are never written to stdout, tool output, telemetry, or diagnostic bundles.

### 7.3 Outbound upstreams

Each upstream has an independent credential binding. Supported binding types include OAuth client credentials, controlled delegated token exchange, mTLS, API key or bearer secret, and CLI-specific short-lived material.

The inbound token is never passed through to an upstream. The proxy obtains a separate audience-restricted credential or presents a distinct mTLS identity. OAuth security follows [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) and resource indicators follow [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707).

### 7.4 Rotation

Rotation is a controlled revision transition:

```text
stage new credential
  -> validate and health-check
  -> publish new revision
  -> deploy new container
  -> drain old revision
  -> revoke old credential
  -> record evidence
```

The UI shows reference names, issuer, audience, expiry, and rotation state. It never displays raw tokens, private keys, API keys, cookies, or CLI secret contents.

## 8. Governance and call execution

Every tool call follows this order:

```text
authenticate caller
  -> validate protocol and schema
  -> resolve proxy and revision
  -> resolve upstream and tool
  -> ask Apex to authorize
  -> request approval when required
  -> enforce rate and budget
  -> enforce egress and CLI policy
  -> execute
  -> validate and filter output
  -> admit evidence
  -> return result
```

The request sent to Apex includes proxy ID, revision, upstream, tool, scope, identity, trace, classification, and bounded input metadata. Apex returns the authorization decision, policy identity, approval requirement, and output handling requirements.

The proxy uses the existing interfaces:

```text
ApexGovernance.authorize(request)
ApexGovernance.get_policy(scope)
ApexEvents.emit(event)
ApexApproval.request(action)
```

The proxy fails closed when identity, policy, approval, egress, filtering, or required evidence admission is unavailable. A denied request emits metadata-only denial evidence. The proxy does not wait for every downstream analytics destination after the durable admission boundary.

Use the existing enforcement classes:

- **Read:** authorize, execute, filter, emit evidence, return.
- **Business write:** authorize, execute, durably record, return.
- **High impact:** authorize, obtain approval, reauthorize, execute, record complete evidence, return.

Tool descriptions, instructions, resources, prompts, arguments, and results are untrusted data. A discovered instruction cannot alter Apex policy, select an undeclared destination, or create a command profile.

## 9. CLI execution

A CLI tool is an approved profile, never a free-form shell command.

```text
CliProfile
  executable_digest
  fixed_executable_path
  argv_schema
  allowed_working_directory
  input_schema
  environment_allowlist
  secret_references
  network_egress_policy
  timeout
  max_output_bytes
  allowed_exit_codes
```

Execution requirements:

- Spawn an executable with an argument array.
- Disable shell interpretation.
- Reject pipelines, redirects, command substitution, globbing, and environment expansion.
- Validate every argument against a typed schema or explicit allowlist.
- Require an immutable executable or image digest.
- Run inside a dedicated sandbox directory.
- Mount only minimum required inputs.
- Give no write access to application code or host storage.
- Inject only explicitly allowed environment values and short-lived credentials.
- Enforce timeout and terminate the complete process tree.
- Limit stdout, stderr, result records, and duration.
- Parse output against a declared schema.
- Redact credentials and restricted data before returning output.
- Emit command profile ID, executable digest, classified argument metadata, exit status, timing, and sizes.

This follows [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), which recommends allowlisting commands and validating arguments rather than concatenating untrusted strings.

## 10. Lifecycle and reconciliation

### 10.1 State machine

```text
DRAFT
  -> VALIDATING
  -> AWAITING_APPROVAL
  -> PROVISIONING
  -> READY
  -> DEGRADED
  -> PAUSED
  -> RETIRING
  -> RETIRED
```

Explicit failure paths are:

```text
VALIDATING   -> FAILED
PROVISIONING -> FAILED
READY        -> DEGRADED
DEGRADED     -> PROVISIONING
```

Every transition records prior state, next state, actor, reason code, revision, validation result, runtime identity, and trace/event IDs.

### 10.2 Reconciliation

The control plane stores desired state. A reconciler produces observed state:

```text
desired revision
  -> validate schema, policy, secrets, and connectivity
  -> obtain required approval
  -> provision isolated container
  -> inject scoped identity and references
  -> apply resource and network policy
  -> run readiness checks
  -> publish endpoint
  -> report READY
```

The reconciler is idempotent. A controller restart, duplicate command, or lost response must not create a second active proxy for the same revision. The runtime provider uses a deterministic deployment key composed of `proxy_id` and `revision_id`.

### 10.3 Deployment and rollback

- Never route requests before readiness succeeds.
- Do not edit a running container in place.
- Keep the previous ready revision available until the new revision is healthy.
- Drain active requests before termination.
- Revoke old credentials after draining.
- Roll back by activating a prior immutable ready revision.
- Record deployment, readiness, rollback, and retirement evidence.
- Retain retired revisions according to evidence policy.

The local provider may use Docker Compose for the first proof, but dynamic provisioning must be behind a runtime-provider interface rather than embedded in the UI or MCP handler.

## 11. API and contract surface

Add a versioned contract, preferably `contracts/proto/apex/v1/mcp_proxy.proto`, for the operator-facing management surface. The existing `ControlGateway` command service remains separate; proxy management is a resource lifecycle API, not an agent control command.

Required operations:

```text
CreateProxy
GetProxy
ListProxies
UpdateProxyDraft
ValidateProxy
DiscoverUpstream
TestProxyConnection
PublishProxyRevision
DeployProxy
PauseProxy
ResumeProxy
RotateProxyCredentials
RollbackProxy
RetireProxy
ListProxyActivity
```

Mutation requirements:

- Operator authentication and scope authorization.
- UUIDv7 idempotency key.
- Optimistic revision check.
- Server-side validation.
- Durable lifecycle event.
- Reason code for pause, rollback, rotation, and retirement.

The browser client must be generated from this contract. It must not define a competing TypeScript API model that can drift from Protobuf or OpenAPI.

## 12. Evidence and observability

Each call receives a durable call ID and emits content-free evidence with:

```text
proxy_id
proxy_revision
workspace_id
namespace_id
user_id
agent_id
run_id
trace_id
upstream_id
tool_name
transport
policy_id
decision
approval_id
classification
status
latency_ms
retry_count
input_bytes
source_bytes
filtered_bytes
output_bytes
removed_field_count
cli_profile_id
executable_digest
credential_binding_id
error_code
```

Do not log raw prompts, access tokens, private keys, client records, complete CLI arguments, or full tool results by default. Sensitive diagnostics require explicit policy, redaction, and retention handling.

Tracing uses W3C trace context and OpenTelemetry-compatible names. Use `gen_ai.operation.name=execute_tool` for tool execution and add low-cardinality proxy, upstream, transport, policy, revision, and status attributes. Tool arguments and results are sensitive and must be opt-in, bounded, and redacted. [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)

Minimum metrics:

- Request rate, concurrency, and queue depth.
- p50, p95, and p99 latency.
- Authentication failures and token refresh failures.
- Governance denials and approval holds.
- Upstream errors, retries, and connection churn.
- CLI timeouts, nonzero exits, and output truncation.
- Filtering and removed-field counts.
- Container readiness, restarts, and resource pressure.
- Evidence-admission failures and downstream lag.
- Budget and rate-limit consumption.

The Activity tab reads scoped server data through the existing live-update boundary. It does not reconstruct authorization or evidence state in the browser.

## 13. Performance and reliability

The first throughput target is predictable overhead per proxy, not unrestricted fan-out. Each proxy may maintain bounded persistent upstream connections and a bounded tool catalog cache. Caches are scoped to one proxy and one revision; they never become policy or audit authorities.

Performance work must measure:

- Cold container startup.
- Readiness and first-call latency.
- Warm authorization-to-result latency.
- Upstream connection reuse.
- Tool discovery duration.
- CLI startup and teardown.
- Output filtering cost.
- Evidence admission latency.
- Memory and CPU per idle and active proxy.
- Maximum safe concurrent calls under resource budgets.

Retries are limited to idempotent transport failures and upstream operations explicitly marked retryable. A retry receives a new attempt metadata field but remains under the same call and governance boundary. Non-idempotent operations are not retried automatically.

## 14. Verification plan

### Contract tests

- Generated client matches the versioned contract.
- Draft and revision validation reject unknown or unsafe fields.
- Idempotency conflicts are rejected.
- Scope isolation prevents cross-workspace reads and mutations.

### Runtime tests

- One container is created for one proxy.
- Two proxies cannot see each other's files, sessions, secrets, caches, or network destinations.
- Root filesystem and capability restrictions are active.
- Container restart converges to desired state.
- Old revisions drain before revocation and termination.
- Rollback restores the prior ready revision.

### Protocol tests

- Stdio stdout contains only MCP messages.
- Streamable HTTP validates origin and authentication.
- Unsupported protocol versions fail safely.
- Tool discovery remains quarantined until selected.
- Schema and tool-name drift moves the proxy to `DEGRADED`.

### Security tests

- Inbound tokens cannot be replayed to an upstream.
- Audience, issuer, scope, expiry, and proxy binding are enforced.
- SSRF destinations, redirects, DNS rebinding, metadata addresses, and private ranges are rejected by default.
- CLI shell syntax, arbitrary binaries, unsafe arguments, environment expansion, and process escapes fail closed.
- Tool descriptions and results cannot change policy or create new commands.
- Secrets do not appear in logs, events, errors, browser responses, or crash artifacts.

### Evidence and failure tests

- Denials, approval holds, upstream failures, filter failures, and admission failures produce safe metadata.
- Durable evidence is committed before required success responses.
- Downstream analytics or archive outage does not lose an admitted event.
- Duplicate lifecycle commands and controller restarts remain idempotent.

### UI tests

- Keyboard-accessible large-plus flow.
- Draft, loading, empty, offline, stale, denied, failed, degraded, and retired states.
- No raw credentials in DOM, storage, or network payloads.
- Accessible labels and focus handling for every wizard step.
- Redacted revision diff and explicit deploy confirmation.
- Responsive layout at narrow and high-contrast settings.

## 15. Implementation sequence

1. Add the versioned proxy resource contract and storage model.
2. Add server-side draft validation and immutable revision publishing.
3. Add the OCI runtime-provider interface and one-container reconciliation proof.
4. Evolve the current TypeScript gateway into a revision-aware managed proxy runtime while preserving the `portfolio.read` proof.
5. Add per-proxy MCP ingress and upstream transport adapters.
6. Add per-proxy inbound and outbound authentication bindings.
7. Add Apex governance, approval, filtering, and evidence integration.
8. Add the `MCP proxies` inventory and large-plus wizard in `apps/operator-ui`.
9. Add CLI profiles only after the container, network, credential, and evidence controls are verified.
10. Add pause, resume, rotation, rollback, retirement, activity, and live status.
11. Run the full negative-path, isolation, performance, and live-container verification gate.

The first end-to-end acceptance slice remains a read-only `portfolio.read` proxy. Direct trade execution, broad workflow orchestration, and unrelated operator surfaces remain out of scope.

## 16. Decisions and non-goals

| Decision | Result |
|---|---|
| Runtime isolation | One hardened OCI container per logical proxy |
| Current provider | Docker/OCI adapter |
| Future providers | Kubernetes workload or microVM adapter behind the same interface |
| Proxy policy authority | Apex only |
| Evidence authority | Apex durable event path only |
| Browser authority | Request and display only |
| CLI model | Fixed profiles with typed argv; no arbitrary shell |
| Inbound credentials | Per-proxy, audience-bound |
| Outbound credentials | Per-upstream, separate from inbound |
| Secret storage | External provider references; no raw values in control state |
| Revision model | Immutable, content-addressed, rollback-capable |
| First business slice | Read-only `portfolio.read` |

The following are explicitly not part of this phase: a second governance system, unrestricted remote shell, direct autonomous trade execution, unrelated dashboard work, additional archive providers, broad workflow orchestration, complex cost forecasting, high-availability cache architecture, or expansion to MCP domains before the shared proxy patterns are proven.

## 17. External references

- [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture)
- [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)
- [RFC 9700: OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [OWASP MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
- [Docker Engine security](https://docs.docker.com/engine/security/)
