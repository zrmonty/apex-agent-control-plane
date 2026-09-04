# MCP Proxy Operator UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an accessible `MCP proxies` console with a prominent plus action, guided creation flow, proxy detail tabs, immutable revision actions, and live server-derived activity.

**Architecture:** Preserve the existing React 19 + Vite shell and add a focused feature module. Use generated clients from the versioned control-plane contract, TanStack Query for server state, TanStack Router for typed routes, and local state only for draft form interaction. The browser never stores secrets or decides authorization.

**Tech Stack:** React 19, TypeScript strict mode, Vite, TanStack Router, TanStack Query, existing Apex design tokens/styles, Vitest, Testing Library, user-event, Playwright, and the generated proxy API client.

**Spec:** `docs/superpowers/specs/2026-09-04-mcp-proxy-platform-design.md`

## Global Constraints

- Add only the approved MCP proxy surface; unrelated Operator UI routes remain on hold.
- The browser requests and displays state; it never owns policy, identity, secrets, or deployment authority.
- Secret values never enter browser state, DOM, local/session storage, query keys, logs, or error details.
- Server-side authorization and redaction are authoritative; client guards improve UX only.
- The collection page has a prominent large `+ New proxy` action.
- Published revisions are immutable and shown with redacted diffs.
- Every changed source and test file must remain at or below 600 lines.

## File map

- Create: `apps/operator-ui/src/app/router.tsx` — route tree and typed proxy paths.
- Create: `apps/operator-ui/src/layout/AppShell.tsx` — existing shell extracted from `main.tsx`.
- Create: `apps/operator-ui/src/features/mcp-proxies/api.ts` — generated-client adapter and query/mutation keys.
- Create: `apps/operator-ui/src/features/mcp-proxies/types.ts` — generated types re-export and view-state types.
- Create: `apps/operator-ui/src/features/mcp-proxies/ProxyListPage.tsx` — inventory, filters, empty/loading/offline states.
- Create: `apps/operator-ui/src/features/mcp-proxies/ProxyCard.tsx` — compact proxy status card/row.
- Create: `apps/operator-ui/src/features/mcp-proxies/NewProxyWizard.tsx` — seven-step creation flow.
- Create: `apps/operator-ui/src/features/mcp-proxies/ProxyDetailPage.tsx` — proxy summary, actions, and tabs.
- Create: `apps/operator-ui/src/features/mcp-proxies/ProxyTabs.tsx` — upstreams, auth, CLI, governance, runtime, activity, revisions.
- Create: `apps/operator-ui/src/features/mcp-proxies/components/*.tsx` — focused form panels and redacted diff.
- Create: `apps/operator-ui/src/features/mcp-proxies/*.test.tsx` — component and interaction tests.
- Modify: `apps/operator-ui/src/main.tsx` — render providers and imported router/app shell.
- Modify: `apps/operator-ui/src/styles.css` — token-backed proxy layout and responsive states.
- Modify: `apps/operator-ui/package.json` and lockfile — Vitest, Testing Library, and Playwright only when absent.
- Create: `apps/operator-ui/e2e/mcp-proxies.spec.ts` — browser acceptance paths.

## Interfaces

```typescript
export interface McpProxyApi {
  list(query: ListProxiesQuery): Promise<ListProxiesPage>;
  create(input: CreateProxyInput): Promise<McpProxyDraft>;
  updateDraft(input: UpdateProxyDraftInput): Promise<McpProxyDraft>;
  validate(input: ValidateProxyInput): Promise<ValidationReport>;
  publish(input: PublishRevisionInput): Promise<McpProxyRevision>;
  deploy(input: DeployProxyInput): Promise<McpProxyStatus>;
  action(input: ProxyActionInput): Promise<McpProxyStatus>;
  activity(query: ProxyActivityQuery): Promise<ProxyActivityPage>;
}

export type ListProxiesQuery = Readonly<{
  workspaceId: string;
  namespaceId: string;
  search?: string;
  status?: string;
  cursor?: string;
}>;

export type CreateProxyInput = Readonly<{
  displayName: string;
  slug: string;
  workspaceId: string;
  namespaceId: string;
  requestId: string;
}>;

export type UpdateProxyDraftInput = Readonly<{
  proxyId: string;
  expectedRevisionId: string;
  patch: unknown;
  requestId: string;
}>;

export type ValidateProxyInput = Readonly<{
  proxyId: string;
  revisionId: string;
}>;

export type PublishRevisionInput = Readonly<{
  proxyId: string;
  expectedRevisionId: string;
  requestId: string;
}>;

export type DeployProxyInput = Readonly<{
  proxyId: string;
  revisionId: string;
  requestId: string;
}>;

export type ProxyActionInput = Readonly<{
  proxyId: string;
  expectedRevisionId: string;
  requestId: string;
  reasonCode?: string;
}>;

export type ProxyActivityQuery = Readonly<{
  proxyId: string;
  cursor?: string;
  limit: number;
}>;

export type ListProxiesPage = Readonly<{
  items: readonly unknown[];
  nextCursor?: string;
}>;

export type McpProxyDraft = Readonly<{
  proxyId: string;
  revisionId: string;
  status: string;
}>;

export type McpProxyRevision = Readonly<{
  proxyId: string;
  revisionId: string;
  configHash: string;
}>;

export type McpProxyStatus = Readonly<{
  proxyId: string;
  revisionId: string;
  lifecycleState: string;
  readiness: string;
}>;

export type ValidationReport = Readonly<{
  valid: boolean;
  errors: readonly string[];
}>;

export type ProxyActivityPage = Readonly<{
  events: readonly unknown[];
  nextCursor?: string;
}>;
```

## Task 1: Split the shell and add typed routes

**Files:** Create `src/app/router.tsx` and `src/layout/AppShell.tsx`; modify `src/main.tsx`.

- [ ] **Step 1: Write route registration tests**

Test that `/mcp-proxies`, `/mcp-proxies/$proxyId`, and `/mcp-proxies/$proxyId/activity` resolve to the proxy feature and that existing routes remain registered.

- [ ] **Step 2: Run the current UI typecheck**

Run `pnpm --dir apps/operator-ui typecheck`. Expected: current scaffold passes before extraction.

- [ ] **Step 3: Extract the shell**

Move the sidebar, workspace picker, identity footer, providers, and route tree into focused files. Add `MCP proxies` below `Agent groups`. Preserve current labels, links, and preview messaging.

- [ ] **Step 4: Add typed proxy routes**

Use TanStack Router params for `proxyId`, preserve scope in query/navigation state, and render the proxy pages through the existing `RootLayout`.

- [ ] **Step 5: Run typecheck and commit**

Run `pnpm --dir apps/operator-ui typecheck`; expected: pass. Commit with `git commit -m "feat: add MCP proxy UI routes"`.

## Task 2: Build the inventory and large-plus entry point

**Files:** Create `ProxyListPage.tsx`, `ProxyCard.tsx`, `api.ts`, `types.ts`, and tests; modify `styles.css`.

- [ ] **Step 1: Write view-state tests**

Cover loading, empty, offline, stale, denied, failed, and populated inventory states. Assert the large button has accessible name `New proxy` and is keyboard reachable.

- [ ] **Step 2: Run focused tests**

Run `pnpm --dir apps/operator-ui test -- ProxyListPage.test.tsx`. Expected: failures identify missing inventory components.

- [ ] **Step 3: Implement server-state queries**

Use TanStack Query keys containing workspace, namespace, filters, and cursor. Map server errors to explicit view states. Do not put access tokens or secret values in query keys or view models.

- [ ] **Step 4: Implement inventory UI**

Show name, status, scope, environment, active revision, upstream count, exposed tool count, policy state, health, and last deployment. Add search and server-supported filters. Add a large `+ New proxy` button in the page header.

- [ ] **Step 5: Run tests, typecheck, and commit**

Run `pnpm --dir apps/operator-ui test`, `pnpm --dir apps/operator-ui typecheck`, and `pnpm --dir apps/operator-ui build`; expected: pass. Commit with `git commit -m "feat: add MCP proxy inventory"`.

## Task 3: Implement the seven-step creation wizard

**Files:** Create `NewProxyWizard.tsx`, `components/IdentityStep.tsx`, `IngressStep.tsx`, `UpstreamsStep.tsx`, `ToolsStep.tsx`, `CliStep.tsx`, `GovernanceStep.tsx`, `ReviewStep.tsx`, and tests.

- [ ] **Step 1: Write wizard behavior tests**

Test draft creation on entry, step navigation, keyboard focus, required-field messages, upstream discovery quarantine, secret-reference-only fields, unsafe CLI profile rejection, redacted review, cancel, save draft, validate, and deploy confirmation.

- [ ] **Step 2: Run focused tests**

Run `pnpm --dir apps/operator-ui test -- NewProxyWizard.test.tsx`. Expected: failures identify missing wizard behavior.

- [ ] **Step 3: Implement draft lifecycle**

Create a server draft immediately, autosave bounded form state through `UpdateProxyDraft`, and invalidate the collection query after successful creation. Keep raw form values out of URL parameters and browser storage.

- [ ] **Step 4: Implement configuration steps**

Collect identity, ingress, upstream transport, explicit tool exposure, fixed CLI profile references, auth bindings, Apex policy, approval, classification, budget, rate, and retention. Display discovery results as quarantined until selected.

- [ ] **Step 5: Implement review and deploy**

Call server validation, render a redacted diff, list secret reference names without values, require explicit deploy confirmation, and show provisioning progress from server status.

- [ ] **Step 6: Run UI verification and commit**

Run `pnpm --dir apps/operator-ui test`, `pnpm --dir apps/operator-ui typecheck`, and `pnpm --dir apps/operator-ui build`; expected: pass. Commit with `git commit -m "feat: add MCP proxy creation wizard"`.

## Task 4: Add proxy detail, actions, revisions, and activity

**Files:** Create `ProxyDetailPage.tsx`, `ProxyTabs.tsx`, tab components, tests; modify `styles.css`.

- [ ] **Step 1: Write detail/action tests**

Cover status rendering, scope-denied response, deploy, pause, resume, rotate, rollback, duplicate, retire confirmation, redacted revision diff, activity pagination, stale state, and live update reconnect.

- [ ] **Step 2: Implement detail queries and actions**

Use generated mutations with optimistic UI only for non-authoritative pending indicators. After every mutation, refetch proxy status and activity. Never claim readiness from a local optimistic state.

- [ ] **Step 3: Implement tabs**

Render Overview, Upstreams and tools, Authentication, CLI runners, Governance, Runtime, Activity, and Revisions. Hide secret values and full tool content. Render untrusted labels, errors, and result text as text.

- [ ] **Step 4: Implement live activity**

Consume the existing scoped SSE/WebSocket boundary with reconnect/backoff, stale indicators, and server-derived events. Show call ID, decision, policy, revision, status, timing, sizes, and evidence receipt metadata.

- [ ] **Step 5: Run accessibility and build checks**

Run `pnpm --dir apps/operator-ui test`, `pnpm --dir apps/operator-ui typecheck`, `pnpm --dir apps/operator-ui build`, and `python scripts/test_check_source_line_limits.py`; expected: pass. Commit with `git commit -m "feat: add MCP proxy operations UI"`.

## Task 5: Browser acceptance proof

**Files:** Create `apps/operator-ui/e2e/mcp-proxies.spec.ts`; modify Playwright setup only for the scoped authenticated test fixture.

- [ ] **Step 1: Write the browser flow**

Test keyboard navigation from the sidebar to `MCP proxies`, click the large plus, create a read-only draft, review redacted config, submit validation, deploy, open activity, and confirm the server-derived status path.

- [ ] **Step 2: Add denied and offline paths**

Assert scope denial, expired session, unavailable API, stale activity, and failed deployment are visible and actionable without exposing credentials.

- [ ] **Step 3: Run browser checks and commit**

Run `pnpm --dir apps/operator-ui exec playwright test e2e/mcp-proxies.spec.ts`; expected: pass against the integration environment. Commit with `git commit -m "test: prove MCP proxy operator flow"`.
