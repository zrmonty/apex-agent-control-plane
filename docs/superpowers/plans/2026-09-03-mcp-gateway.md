# Thin TypeScript MCP Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone TypeScript MCP stdio gateway that exposes one validated, read-only `portfolio.read` tool and delegates authorization and durable evidence admission through replaceable Apex-shaped interfaces.

**Architecture:** Keep the MCP transport in a thin composition layer and put request orchestration behind a transport-neutral executor. The executor receives authenticated context, a governance adapter, an event-admission adapter, and an immutable local portfolio adapter; it validates input, authorizes the exact scope, filters the raw record, emits metadata-only evidence, and returns only the filtered result. The local Apex adapter is a development implementation of the governance contracts, not a second gateway-owned policy or audit system.

**Tech Stack:** Node.js 24, TypeScript 5.9, pnpm, `@modelcontextprotocol/sdk` 1.30, Zod 4, and Node's built-in `node:test` runner executed through `tsx`.

**Spec:** `docs/superpowers/specs/2026-09-03-apex-mcp-vertical-slice-design.md`

## Global Constraints

- The initial MCP transport is the official MCP stdio transport.
- The first tool is exactly `portfolio.read`; no trade, write, mutation, or second tool is added.
- Caller identity and workspace/namespace scope come from injected authenticated context, never from tool arguments.
- The gateway must not own mutable policy rules, approval state, audit storage, or a second governance ledger.
- Raw prompts, full client records, and full tool responses must not be logged or placed in governance events.
- An allowed tool result is returned only after `ApexEvents.emit` resolves successfully.
- Denials never execute the portfolio adapter; denied-event admission failure does not turn a denial into success.
- Response filtering is an allowlist and fails closed on malformed adapter output or filtering errors.
- Every behavior change follows a red-green-refactor cycle with a focused failing test before production code.

---

### Task 1: Scaffold the standalone TypeScript package and MCP transport

**Files:**
- Create: `apps/mcp-gateway/package.json`
- Create: `apps/mcp-gateway/tsconfig.json`
- Create: `apps/mcp-gateway/src/server.ts`
- Create: `apps/mcp-gateway/src/server.test.ts`
- Create: `apps/mcp-gateway/src/schemas.ts`
- Create: `apps/mcp-gateway/src/schemas.test.ts`
- Create: `apps/mcp-gateway/pnpm-lock.yaml`

**Interfaces:**
- Consumes: the MCP SDK and the strict `PortfolioReadInputSchema` created in this task.
- Produces: `createMcpServer(executor)` returning an `McpServer` that registers only `portfolio.read`.

- [ ] **Step 1: Write the failing transport test**

Create a schema test that rejects unknown fields, invalid portfolio IDs, and impossible dates. Create a second test using the SDK's linked in-memory transports. The transport test must connect an SDK `Client` to the server, list tools, and assert there is exactly one tool named `portfolio.read` with no `portfolio.write` or `portfolio.trade` entry.

```ts
test("exposes only the read-only portfolio tool", async () => {
  const executor = { executePortfolioRead: async () => ({
    content: [{ type: "text", text: "{}" }],
  }) };
  const server = createMcpServer(executor);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "gateway-test", version: "0.1.0" });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  const result = await client.listTools();

  assert.deepEqual(result.tools.map((tool) => tool.name), ["portfolio.read"]);
  await client.close();
  await server.close();
});
```

```ts
test("rejects arbitrary queries and impossible dates", () => {
  assert.throws(() => parsePortfolioReadInput({
    portfolioId: "Northstar/401k",
    query: "select * from client_records",
  }));
  assert.throws(() => parsePortfolioReadInput({
    portfolioId: "northstar-401k",
    asOf: "2026-02-31",
  }));
});
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run from `apps/mcp-gateway`:

```text
pnpm test -- src/server.test.ts
```

Expected: FAIL because `src/server.ts`, `src/schemas.ts`, and the package configuration do not exist yet.

- [ ] **Step 3: Add the package and TypeScript configuration**

Create `package.json` with these scripts and dependency floors:

```json
{
  "name": "@apex/mcp-gateway",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "engines": { "node": ">=24" },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "test": "tsx --test \"src/**/*.test.ts\"",
    "typecheck": "tsc --noEmit -p tsconfig.json"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.30.0",
    "zod": "^4.5.4"
  },
  "devDependencies": {
    "@types/node": "^24.0.0",
    "tsx": "^4.23.13",
    "typescript": "^5.9.3"
  }
}
```

Set `module` and `moduleResolution` to `NodeNext`, `target` to `ES2022`, and enable `strict`, `noUnusedLocals`, `noUnusedParameters`, `rootDir: "src"`, `outDir: "dist"`, `declaration: true`, and `sourceMap: true`. Include only `src`.

Run `pnpm install` from `apps/mcp-gateway` to resolve the exact dependency graph and generate the committed `pnpm-lock.yaml`.

- [ ] **Step 4: Implement the strict input schema**

Use a Zod strict object with:

```ts
const portfolioId = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/);
const asOf = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional();
export const PortfolioReadInputSchema = z.object({ portfolioId, asOf }).strict();
export type PortfolioReadInput = z.infer<typeof PortfolioReadInputSchema>;
export function parsePortfolioReadInput(value: unknown): PortfolioReadInput;
```

Reject impossible calendar dates with a UTC date round-trip check. Do not accept scope, identity, policy, query, sort, or backend fields.

- [ ] **Step 5: Implement the one-tool MCP server**

Register `portfolio.read` with the SDK using the Zod input shape. The handler delegates to `executor.executePortfolioRead(input)` and returns its MCP result unchanged. Do not register any other tool or read scope, policy, or caller fields from the tool input.

```ts
export interface PortfolioReadExecutor {
  executePortfolioRead(input: unknown): Promise<CallToolResult>;
}

export function createMcpServer(executor: PortfolioReadExecutor): McpServer;
```

Use `new McpServer({ name: "apex-mcp-gateway", version: "0.1.0" })`. Keep all diagnostics on stderr; stdout is reserved for MCP protocol messages. The executable `start()` composition is added in Task 4 after the executor exists.

- [ ] **Step 6: Run the focused tests to verify they pass**

Run `pnpm test -- src/server.test.ts src/schemas.test.ts`. Expected: PASS with one exposed tool and strict input rejection.

- [ ] **Step 7: Commit the transport and schema scaffold**

```text
git add apps/mcp-gateway
git commit -m "feat: scaffold TypeScript MCP gateway"
```

### Task 2: Define authenticated context and Apex-shaped TypeScript contracts

**Files:**
- Create: `apps/mcp-gateway/src/contracts.ts`
- Create: `apps/mcp-gateway/src/context.ts`
- Create: `apps/mcp-gateway/src/context.test.ts`

**Interfaces:**
- Consumes: the package, server, and strict input schema from Task 1.
- Produces: `PortfolioReadInput`, `AuthenticatedContext`, `ApexGovernance`, `ApexEvents`, `AuthorizationRequest`, `AuthorizationDecision`, `PolicySnapshot`, `ToolExecutionEvent`, and safe gateway error codes.

- [ ] **Step 1: Write failing context tests**

Cover one behavior per test:

```ts
test("context parser requires authenticated identity and exact scope", () => {
  assert.deepEqual(parseAuthenticatedContext({
    APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research",
    APEX_MCP_AGENT_ID: "research-agent",
    APEX_MCP_WORKSPACE_ID: "northstar",
    APEX_MCP_NAMESPACE_ID: "research",
    APEX_MCP_TRACE_ID: "trace-001",
  }), {
    principal: "spiffe://apex/agent/research",
    agentId: "research-agent",
    workspaceId: "northstar",
    namespaceId: "research",
    traceId: "trace-001",
  });
});
```

Also assert missing or malformed context variables fail without echoing their values in the thrown safe error.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run `pnpm test -- src/context.test.ts`. Expected: FAIL because the context parser and contract types do not exist.

- [ ] **Step 3: Implement the authenticated context parser**

Parse environment context with required non-empty bounded values, construct the canonical `workspaceId/namespaceId` key internally, and never accept scope or identity from `PortfolioReadInput`.

- [ ] **Step 4: Implement the transport-neutral contract types**

Define these exact shapes:

```ts
export type AuthenticatedContext = {
  readonly principal: string;
  readonly agentId: string;
  readonly workspaceId: string;
  readonly namespaceId: string;
  readonly traceId: string;
};

export type AuthorizationRequest = {
  readonly caller: AuthenticatedContext;
  readonly scope: { readonly workspaceId: string; readonly namespaceId: string };
  readonly tool: "portfolio.read";
  readonly action: "read";
  readonly resource: string;
  readonly classification: "confidential";
  readonly trace: { readonly traceId: string; readonly spanId: string };
};

export type AuthorizationDecision = {
  readonly outcome: "allowed" | "denied" | "requires_approval";
  readonly policyId: string;
  readonly reasonCode: string;
  readonly fieldRestrictions: readonly string[];
};

export interface ApexGovernance {
  authorize(request: AuthorizationRequest): Promise<AuthorizationDecision>;
  getPolicy(scope: AuthorizationRequest["scope"]): Promise<PolicySnapshot>;
}

export interface ApexEvents {
  emit(event: ToolExecutionEvent): Promise<{ readonly eventId: string }>;
}
```

`ToolExecutionEvent` must contain only caller/scope/tool/action/resource/backend/status/latency/retry/sizes/filtering/policy/trace metadata. Define `GatewayError` with stable codes `INVALID_INPUT`, `AUTHORIZATION_DENIED`, `APPROVAL_REQUIRED`, `GOVERNANCE_UNAVAILABLE`, `ADAPTER_FAILED`, `FILTERING_FAILED`, and `EVENT_ADMISSION_FAILED`; its public message contains only the code and safe explanation.

- [ ] **Step 5: Run the focused tests and typecheck**

Run `pnpm test -- src/context.test.ts` and `pnpm typecheck`. Expected: PASS with no diagnostics.

- [ ] **Step 6: Commit the contract boundary**

```text
git add apps/mcp-gateway/src/contracts.ts apps/mcp-gateway/src/context.ts apps/mcp-gateway/src/context.test.ts
git commit -m "feat: define MCP gateway contracts and context"
```

### Task 3: Add the deterministic read-only portfolio adapter and policy filtering

**Files:**
- Create: `apps/mcp-gateway/src/adapters/portfolio.ts`
- Create: `apps/mcp-gateway/src/filtering.ts`
- Create: `apps/mcp-gateway/src/adapters/portfolio.test.ts`
- Create: `apps/mcp-gateway/src/filtering.test.ts`

**Interfaces:**
- Consumes: `PortfolioReadInput`, `AuthorizationDecision`, and error contracts from Task 2.
- Produces: `PortfolioAdapter.read(input)`, immutable `RawPortfolioRecord`, `PortfolioPublicView`, and `filterPortfolioRecord(raw, decision)`.

Use this raw-record shape in both the adapter and filtering tests:

```ts
export type RawPortfolioRecord = {
  readonly portfolio_id: string;
  readonly as_of: string;
  readonly base_currency: string;
  readonly total_value: number;
  readonly client: {
    readonly display_name: string;
    readonly account_number: string;
    readonly tax_id: string;
  };
  readonly positions: ReadonlyArray<{
    readonly symbol: string;
    readonly quantity: number;
    readonly market_value: number;
    readonly cost_basis: number;
  }>;
};
```

Use this fixture in the filtering test so the restricted values are known test-only data:

```ts
const rawPortfolioFixture: RawPortfolioRecord = {
  portfolio_id: "northstar-401k",
  as_of: "2026-08-31",
  base_currency: "USD",
  total_value: 125000,
  client: {
    display_name: "Northstar Research",
    account_number: "client-record-raw",
    tax_id: "tax-record-raw",
  },
  positions: [{
    symbol: "APEX",
    quantity: 100,
    market_value: 10000,
    cost_basis: 7000,
  }],
};
```

- [ ] **Step 1: Write failing adapter and filtering tests**

The adapter test must prove deterministic read behavior and the absence of mutation methods. The filtering test must prove restricted fields never appear in output or serialized output:

```ts
test("returns the same immutable portfolio record for the same read", async () => {
  const adapter = new LocalPortfolioAdapter();
  const first = await adapter.read({ portfolioId: "northstar-401k" });
  const second = await adapter.read({ portfolioId: "northstar-401k" });
  assert.deepEqual(first, second);
  assert.equal(Object.isFrozen(first), true);
  assert.equal("write" in adapter, false);
  assert.equal("trade" in adapter, false);
});

test("filters restricted client and position fields before model access", () => {
  const result = filterPortfolioRecord(rawPortfolioFixture, {
    outcome: "allowed",
    policyId: "local-read-v1",
    reasonCode: "policy.allowed",
    fieldRestrictions: ["client.account_number", "client.tax_id", "positions.cost_basis"],
  });
  const serialized = JSON.stringify(result.view);
  assert.equal(serialized.includes("account_number"), false);
  assert.equal(serialized.includes("tax_id"), false);
  assert.equal(serialized.includes("cost_basis"), false);
  assert.deepEqual(result.removedFields, [
    "client.account_number",
    "client.tax_id",
    "positions.cost_basis",
  ]);
});
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run `pnpm test -- src/adapters/portfolio.test.ts src/filtering.test.ts`. Expected: FAIL because the adapter and filtering functions do not exist.

- [ ] **Step 3: Implement the immutable local adapter**

Define a read-only interface with no write-shaped method:

```ts
export interface PortfolioAdapter {
  read(input: PortfolioReadInput): Promise<RawPortfolioRecord>;
}
```

Seed one frozen `northstar-401k` record containing allowlisted fields plus deliberately restricted `client.account_number`, `client.tax_id`, and `positions[].cost_basis` fields. Return a deep-frozen clone for every read. An unknown portfolio produces `ADAPTER_FAILED` without exposing the requested value in an error message. The adapter must not accept arbitrary SQL, query strings, sort clauses, or caller-provided scope.

- [ ] **Step 4: Implement the allowlist filter**

Return:

```ts
export type PortfolioPublicView = {
  readonly portfolioId: string;
  readonly asOf: string;
  readonly baseCurrency: string;
  readonly totalValue: number;
  readonly client: { readonly displayName: string };
  readonly positions: ReadonlyArray<{
    readonly symbol: string;
    readonly quantity: number;
    readonly marketValue: number;
  }>;
};

export type FilterResult = {
  readonly view: PortfolioPublicView;
  readonly removedFields: readonly string[];
  readonly sourceBytes: number;
  readonly filteredBytes: number;
};
```

Construct the output field-by-field. Apply `fieldRestrictions` while traversing and record restricted paths in stable order. Reject non-finite numeric values and missing required raw fields with `FILTERING_FAILED`; never fall back to returning raw data.

- [ ] **Step 5: Run focused tests, typecheck, and commit**

Run `pnpm test -- src/adapters/portfolio.test.ts src/filtering.test.ts` and `pnpm typecheck`. Expected: PASS. Commit:

```text
git add apps/mcp-gateway/src/adapters apps/mcp-gateway/src/filtering.ts apps/mcp-gateway/src/filtering.test.ts
git commit -m "feat: add read-only portfolio adapter and filtering"
```

### Task 4: Implement governance orchestration, safe telemetry, and local Apex adapters

**Files:**
- Create: `apps/mcp-gateway/src/governance/local.ts`
- Create: `apps/mcp-gateway/src/telemetry.ts`
- Create: `apps/mcp-gateway/src/execution.ts`
- Create: `apps/mcp-gateway/src/execution.test.ts`
- Modify: `apps/mcp-gateway/src/server.ts`
- Create: `apps/mcp-gateway/src/index.ts`
- Create: `apps/mcp-gateway/README.md`
- Create: `apps/mcp-gateway/.env.example`

**Interfaces:**
- Consumes: the server from Task 1 and all schemas, contracts, adapter, and filter types from Tasks 2-3.
- Produces: `GatewayExecutor`, `StaticLocalApex`, and the complete request path `authorize → read → filter → emit → return`.

The recording test fakes must implement `ApexGovernance`, `ApexEvents`, and `PortfolioAdapter`; expose `readCount`, `events`, and configurable safe failures so assertions observe the real executor rather than mocked internal functions.

`GatewayExecutor` accepts a `GatewayDependencies` object with the required `context`, `governance`, `events`, and `portfolio` values plus optional `filter` and `telemetry` seams. Production composition uses `filterPortfolioRecord`; tests inject a throwing filter to exercise the fail-closed path. `SafeTelemetry.record(code)` receives only a `GatewayErrorCode` and is used when a denied event cannot be admitted.

- [ ] **Step 1: Write failing orchestration tests**

Use recording fakes that implement the interfaces rather than mocking internal functions. Cover these independent behaviors:

```ts
test("allowed reads filter, emit metadata, and return only the public view", async () => {
  const { executor, events, adapter } = fixture({ decision: allowedDecision() });
  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });
  assert.equal(result.isError, undefined);
  assert.equal(adapter.readCount, 1);
  assert.equal(events.events.length, 1);
  assert.equal(JSON.stringify(result.structuredContent).includes("account_number"), false);
  assert.equal(JSON.stringify(events.events[0]).includes("client-record-raw"), false);
});

test("denials never execute the adapter", async () => {
  const { executor, adapter } = fixture({ decision: deniedDecision() });
  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });
  assert.equal(result.isError, true);
  assert.equal(adapter.readCount, 0);
});

test("event admission failure prevents an allowed result", async () => {
  const { executor } = fixture({ emitError: new GatewayError("EVENT_ADMISSION_FAILED", "event admission failed") });
  const result = await executor.executePortfolioRead({ portfolioId: "northstar-401k" });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /EVENT_ADMISSION_FAILED/);
});
```

Also test invalid input before authorization, `requires_approval` without adapter execution, authorization service failure, policy mismatch, adapter failure, filtering failure, and denied-event admission failure. Assert all returned messages are stable safe codes and never include raw input, portfolio records, or backend error strings.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run `pnpm test -- src/execution.test.ts`. Expected: FAIL because `GatewayExecutor` and the local adapter do not exist.

- [ ] **Step 3: Implement the local Apex adapter**

`StaticLocalApex` must implement `ApexGovernance` and `ApexEvents` with an immutable allowed-portfolio set, fixed policy identity `local-read-v1`, revision `1`, and restrictions for the seeded sensitive fields. `authorize` evaluates only the exact request fields and returns `denied` for an unlisted portfolio. `getPolicy` returns metadata for the exact scope. `emit` accepts only metadata events and returns a generated safe event ID; retain events only in an explicitly test-provided sink.

- [ ] **Step 4: Implement metadata-only telemetry helpers**

Add safe size calculation using `TextEncoder` over JSON representations and a trace helper that derives a per-call span from the injected context. Define event fields for status `succeeded`, `denied`, or `failed`, elapsed milliseconds, retry count, input/source/filtered/output sizes, removed fields, policy decision, and trace IDs. Do not accept or serialize raw adapter input/output into events. Define `SafeTelemetry.record(code: GatewayErrorCode): void`; its implementation receives codes only and never raw exceptions or request data.

- [ ] **Step 5: Implement the executor in the required order**

`GatewayExecutor.executePortfolioRead(input: unknown)` must:

1. Parse the strict input.
2. Build `AuthorizationRequest` from injected context and generated trace metadata.
3. Call `authorize`; return a safe denial for `denied` or `requires_approval` without adapter access.
4. Call `getPolicy` for the exact scope and fail safely if the policy identity does not match the decision.
5. Call the read-only adapter.
6. Filter and minimize the raw record.
7. Call `ApexEvents.emit` with metadata only.
8. Return the filtered structured result only after event admission succeeds.

For denied requests, attempt a metadata-only denied event but preserve the denial if event admission fails, and call `SafeTelemetry.record("EVENT_ADMISSION_FAILED")`. For allowed reads, any event-admission error becomes `EVENT_ADMISSION_FAILED`; do not return the tool result. Never log raw exceptions. Convert all unexpected failures into the declared safe gateway codes.

- [ ] **Step 6: Wire composition and run the focused tests**

Have `index.ts` parse environment context, instantiate `StaticLocalApex` and `LocalPortfolioAdapter`, construct `GatewayExecutor`, add `"start": "node dist/index.js"` to `package.json`, and connect the executor-backed server to `StdioServerTransport`. Run:

```text
pnpm test -- src/execution.test.ts src/server.test.ts
pnpm typecheck
pnpm build
```

Expected: PASS, one MCP tool, and a successful TypeScript build.

- [ ] **Step 7: Commit the complete gateway path**

```text
git add apps/mcp-gateway
git commit -m "feat: execute governed portfolio reads through MCP"
```

### Task 5: Verify the checkpoint and update the active roadmap

**Files:**
- Modify: `docs/roadmap.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `apps/mcp-gateway/README.md`

**Interfaces:**
- Consumes: the complete gateway path and package scripts from Tasks 1-4.
- Produces: a documented milestone state that identifies the TypeScript gateway and local read tool as implemented while keeping live Apex transport, operator wiring, and all unrelated roadmap work paused.

- [ ] **Step 1: Run the complete gateway verification**

From `apps/mcp-gateway`, run:

```text
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build
```

From the repository root, rerun `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` to confirm the Rust governance boundary remains green. Run `git diff --check` and confirm no raw-content fixture is outside test-only code.

- [ ] **Step 2: Document the completed gateway checkpoint**

Update only the active-status portions of `docs/roadmap.md`, `README.md`, and `CLAUDE.md` to say that the thin stdio MCP gateway and deterministic local `portfolio.read` path are implemented. State that the remaining active work is live Apex authorization/event clients and the narrow operator-visible vertical slice. Do not mark the live completion gate complete and do not activate deferred work.

- [ ] **Step 3: Run the final verification and commit documentation**

Run the complete gateway verification again after the documentation edits, then commit:

```text
git add docs/roadmap.md README.md CLAUDE.md apps/mcp-gateway/README.md
git commit -m "docs: record MCP gateway checkpoint"
```

- [ ] **Step 4: Review the diff for scope**

Confirm the final diff contains only the new gateway package, its tests/documentation, and active roadmap status. Confirm there is no HTTP server, live network client, operator UI route, trade capability, policy database, second audit store, or unrelated feature work.
