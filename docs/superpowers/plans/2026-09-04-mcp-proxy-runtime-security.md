# MCP Proxy Runtime and Security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run each managed proxy in an isolated runtime with safe MCP transport handling, separate credentials, governed execution, and fixed CLI profiles.

**Architecture:** Keep `apps/mcp-gateway` as the TypeScript data-plane seed, split managed responsibilities into focused modules, and make runtime configuration immutable per revision. A Docker/OCI provider creates one hardened container per proxy; the proxy calls Apex for authorization and evidence before and after execution.

**Tech Stack:** Node.js 24, TypeScript, `@modelcontextprotocol/sdk` 1.x, `zod`, `@grpc/grpc-js`, `child_process.spawn`, HTTPS/mTLS, OAuth/OIDC discovery, Docker/OCI, and existing gateway tests/live proof.

**Spec:** `docs/superpowers/specs/2026-09-04-mcp-proxy-platform-design.md`

## Global Constraints

- One hardened OCI container per logical proxy.
- No Docker or Kubernetes control socket inside a proxy container.
- Read-only root filesystem, non-root user, dropped capabilities, `no-new-privileges`, bounded tmpfs, and explicit CPU/memory/PID/network limits.
- Secret values never enter control state, browser state, events, logs, errors, or diagnostic bundles.
- Inbound MCP credentials are separate from per-upstream outbound credentials; inbound tokens are never passed through.
- CLI tools use fixed profiles with typed argv; arbitrary shell execution is prohibited.
- HTTP MCP transport validates origin and authentication; stdio emits only MCP messages on stdout.
- Every call passes Apex authorization and required evidence admission.
- Every changed source and test file must remain at or below 600 lines.

## File map

- Modify: `apps/mcp-gateway/src/index.ts` — select stdio or managed transport from validated revision config.
- Create: `apps/mcp-gateway/src/managed/config.ts` — revision configuration parsing and bounded defaults.
- Create: `apps/mcp-gateway/src/managed/upstream.ts` — isolated per-upstream client sessions and discovery quarantine.
- Create: `apps/mcp-gateway/src/managed/http.ts` — Streamable HTTP ingress, origin, host, body, and session checks.
- Create: `apps/mcp-gateway/src/managed/auth.ts` — inbound verification and outbound credential providers.
- Create: `apps/mcp-gateway/src/managed/cli.ts` — fixed command profile execution.
- Create: `apps/mcp-gateway/src/managed/network.ts` — URL, DNS, redirect, and destination policy.
- Create: `apps/mcp-gateway/src/managed/managed-executor.ts` — Apex authorization, execution, filtering, and evidence orchestration.
- Create: `apps/mcp-gateway/src/managed/*.test.ts` — focused security and behavior tests.
- Modify: `apps/mcp-gateway/package.json` and lockfile only for required runtime dependencies.
- Create: `apps/mcp-gateway/Dockerfile` — non-root, production runtime image.
- Create: `apps/mcp-gateway/runtime-profile.json` — explicit container baseline consumed by the provider.

## Interfaces

```typescript
export type ProxyRevisionConfig = Readonly<{
  proxyId: string;
  revisionId: string;
  ingress: IngressConfig;
  upstreams: readonly UpstreamConfig[];
  exposedTools: readonly ExposedTool[];
  cliProfiles: readonly CliProfile[];
  authBindings: readonly AuthBinding[];
  governance: GovernanceBinding;
  runtime: RuntimeProfile;
}>;

export type IngressConfig = Readonly<{
  transport: "stdio" | "streamable-http";
  endpoint?: string;
  allowedOrigins: readonly string[];
}>;

export type ExposedTool = Readonly<{
  upstreamId: string;
  toolName: string;
  alias: string;
  classification: "read" | "business-write" | "high-impact";
}>;

export type UpstreamConfig = Readonly<{
  upstreamId: string;
  transport: "stdio" | "streamable-http";
  endpointOrCommandRef: string;
  credentialRef?: string;
}>;

export type CliProfile = Readonly<{
  profileId: string;
  executableRef: string;
  executableDigest: string;
  argvSchema: unknown;
  timeoutMs: number;
  maxOutputBytes: number;
}>;

export type AuthBinding = Readonly<{
  bindingId: string;
  direction: "inbound" | "outbound";
  credentialRef?: string;
  audience?: string;
}>;

export type GovernanceBinding = Readonly<{
  policyId: string;
  approvalMode: "none" | "operator" | "dual-operator";
  classification: "public" | "internal" | "confidential" | "restricted";
}>;

export type RuntimeProfile = Readonly<{
  imageDigest: string;
  cpuMillis: number;
  memoryBytes: number;
  pidLimit: number;
  readOnlyRootfs: true;
}>;

export type QuarantinedToolCatalog = Readonly<{
  upstreamId: string;
  schemaHash: string;
  tools: readonly unknown[];
}>;

export type CliResult = Readonly<{
  exitCode: number;
  stdout: unknown;
  stderrBytes: number;
  durationMs: number;
}>;

export function parseProxyRevisionConfig(input: unknown): ProxyRevisionConfig;

export interface UpstreamSession {
  discover(): Promise<QuarantinedToolCatalog>;
  call(tool: ExposedTool, input: unknown): Promise<unknown>;
  close(): Promise<void>;
}

export interface CliRunner {
  run(profileId: string, input: unknown): Promise<CliResult>;
}
```

## Task 1: Add revision configuration and container image baseline

**Files:** Create `src/managed/config.ts`, `Dockerfile`, and `runtime-profile.json`; modify `src/index.ts` and package scripts.

- [ ] **Step 1: Write configuration rejection tests**

Test missing proxy/revision IDs, unknown fields, unbounded limits, missing governance binding, a secret value in place of a reference, writable rootfs, host networking, and valid read-only `portfolio.read` configuration.

- [ ] **Step 2: Run focused tests**

Run `pnpm --dir apps/mcp-gateway test -- managed/config.test.ts`. Expected: the new tests fail because the managed config parser does not exist.

- [ ] **Step 3: Implement `parseProxyRevisionConfig`**

Use strict Zod schemas, reject unknown keys, bound counts and byte limits, require a revision hash, and expose only immutable parsed values. Do not accept raw tokens, private keys, shell strings, or host paths.

- [ ] **Step 4: Build the image baseline**

Use a pinned Node 24 runtime, a non-root UID, production-only dependencies, a read-only rootfs-compatible layout, and a startup check that refuses missing identity or governance configuration. Add a profile declaring dropped capabilities, no-new-privileges, PID/memory/CPU bounds, and no runtime socket.

- [ ] **Step 5: Run typecheck, tests, and build**

Run `pnpm --dir apps/mcp-gateway typecheck`, `pnpm --dir apps/mcp-gateway test`, and `pnpm --dir apps/mcp-gateway build`. Expected: all pass.

- [ ] **Step 6: Commit**

```powershell
git add apps/mcp-gateway/src/index.ts apps/mcp-gateway/src/managed/config.ts apps/mcp-gateway/src/managed/config.test.ts apps/mcp-gateway/Dockerfile apps/mcp-gateway/runtime-profile.json apps/mcp-gateway/package.json apps/mcp-gateway/pnpm-lock.yaml
git commit -m "feat: add managed proxy runtime configuration"
```

## Task 2: Implement isolated upstream sessions and discovery quarantine

**Files:** Create `src/managed/upstream.ts`, `src/managed/upstream.test.ts`, and `src/managed/network.ts`; modify `package.json` only if the existing SDK lacks the required transport helper.

- [ ] **Step 1: Write session-isolation tests**

Create two proxy configs and assert their client instances, catalogs, credentials, caches, and temporary paths are distinct. Test that an undiscovered tool cannot be called and that schema-hash drift produces `DEGRADED` status.

- [ ] **Step 2: Write SSRF and destination tests**

Reject loopback, link-local, multicast, private, metadata-service, unsupported-scheme, unsafe-port, redirect, and DNS-rebinding destinations. Accept only a declared HTTPS destination or a declared stdio command profile.

- [ ] **Step 3: Run the focused tests**

Run `pnpm --dir apps/mcp-gateway test -- managed/upstream.test.ts managed/network.test.ts`. Expected: failures identify the unimplemented session and destination policy.

- [ ] **Step 4: Implement sessions and network checks**

Create one client/session per configured upstream, quarantine all discovery output, require explicit exposure records, normalize and revalidate URL destinations, revalidate redirects, and bound response/decompression sizes. Never share module-level auth or catalog state.

- [ ] **Step 5: Run tests and commit**

Run `pnpm --dir apps/mcp-gateway typecheck` and the focused tests; expected: pass. Commit with `git commit -m "feat: isolate MCP upstream sessions"`.

## Task 3: Implement inbound and outbound authentication

**Files:** Create `src/managed/auth.ts`, `src/managed/auth.test.ts`, and `src/managed/http.ts`.

- [ ] **Step 1: Write authentication tests**

Cover missing/duplicate authorization headers, invalid issuer, wrong audience, expired token, missing scope, wrong proxy binding, invalid origin, PKCE state mismatch, and successful per-proxy authentication. Add a test proving an inbound token is never passed to an upstream request.

- [ ] **Step 2: Run focused tests**

Run `pnpm --dir apps/mcp-gateway test -- managed/auth.test.ts`. Expected: failures identify missing verification and header handling.

- [ ] **Step 3: Implement HTTP resource protection**

Publish protected-resource metadata, produce standards-compliant challenges, validate `Origin` and `Host`, require HTTPS outside localhost, verify issuer/audience/expiry/scope/proxy binding, and bind the result to Apex caller context. Use the MCP resource parameter for outbound token acquisition.

- [ ] **Step 4: Implement credential separation**

Resolve only secret references. Select an independent outbound provider per upstream. Never copy inbound authorization headers to an upstream. Keep refresh material in memory only for the minimum lifetime and redact all error paths.

- [ ] **Step 5: Run typecheck, tests, and commit**

Run `pnpm --dir apps/mcp-gateway typecheck` and `pnpm --dir apps/mcp-gateway test`; expected: pass. Commit with `git commit -m "feat: secure managed proxy authentication"`.

## Task 4: Add fixed CLI profiles

**Files:** Create `src/managed/cli.ts`, `src/managed/cli.test.ts`, and `src/managed/cli-fixtures/`; modify `src/managed/config.ts` only for the profile schema.

- [ ] **Step 1: Write CLI safety tests**

Reject shell strings, pipelines, redirects, command substitution, globbing, environment expansion, unknown executables, unsafe working directories, unapproved environment names, missing digest, oversized input, timeout over the profile limit, and output over the profile limit.

- [ ] **Step 2: Run focused tests**

Run `pnpm --dir apps/mcp-gateway test -- managed/cli.test.ts`. Expected: failures identify the missing runner.

- [ ] **Step 3: Implement `spawn`-based execution**

Use `spawn(executable, argv, { shell: false })`, fixed executable identity, typed argument validation, sandbox working directory, environment allowlist, bounded stdio, timeout, process-tree termination, allowed exit codes, output schema validation, and safe error mapping.

- [ ] **Step 4: Add metadata-only evidence**

Return only filtered structured output. Emit profile ID, executable digest, classified argument metadata, exit status, timing, and sizes. Never record complete secret-bearing argv, environment, stdout, or stderr.

- [ ] **Step 5: Run tests, line limits, and commit**

Run `pnpm --dir apps/mcp-gateway typecheck`, `pnpm --dir apps/mcp-gateway test`, and `python scripts/test_check_source_line_limits.py`; expected: pass. Commit with `git commit -m "feat: add governed CLI profiles"`.

## Task 5: Connect Apex governance and evidence

**Files:** Create `src/managed/managed-executor.ts`, `src/managed/managed-executor.test.ts`; modify existing `src/live/governance.ts`, `src/live/events.ts`, and `src/telemetry.ts` only through focused adapters.

- [ ] **Step 1: Write the execution-order tests**

Assert the exact order: authenticate, schema validation, proxy/revision resolution, Apex authorization, approval, rate/budget, egress/CLI policy, execution, filtering, evidence admission, result. Assert denied and evidence-failure paths never call the upstream.

- [ ] **Step 2: Run focused tests**

Run `pnpm --dir apps/mcp-gateway test -- managed/managed-executor.test.ts`. Expected: failures identify missing orchestration.

- [ ] **Step 3: Implement the executor**

Use `ApexGovernance.authorize`, `getPolicy`, `ApexApproval.request`, and `ApexEvents.emit` with proxy/revision/upstream/tool/scope/identity/trace metadata. Fail closed for missing policy, approval, filtering, or required evidence admission.

- [ ] **Step 4: Add bounded OpenTelemetry metadata**

Use W3C trace context and `gen_ai.operation.name=execute_tool`; add low-cardinality proxy, revision, upstream, transport, policy, and status attributes. Keep content capture disabled by default.

- [ ] **Step 5: Run gateway verification and commit**

Run `pnpm --dir apps/mcp-gateway typecheck`, `pnpm --dir apps/mcp-gateway test`, `pnpm --dir apps/mcp-gateway build`, and the existing `node apps/mcp-gateway/scripts/live_proof.mjs` against the live stack. Expected: existing `portfolio.read` proof remains green. Commit with `git commit -m "feat: govern managed proxy execution"`.
