import type { McpProxyApi, ProxyActivityEvent, ProxyDraft, ProxyRevision, ProxyStatus, ProxySummary, UpdateProxyDraftInput } from "./types";

export const proxyQueryKeys = {
  all: ["mcp-proxies"] as const,
  list: (workspaceId: string, namespaceId: string, search: string, status: string) => ["mcp-proxies", "list", workspaceId, namespaceId, search, status] as const,
  detail: (proxyId: string) => ["mcp-proxies", "detail", proxyId] as const,
  activity: (proxyId: string) => ["mcp-proxies", "activity", proxyId] as const,
};

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();

const seed: ProxySummary = {
  proxyId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1001",
  displayName: "Research portfolio tools",
  slug: "research-portfolio-tools",
  workspaceId: "northstar-research",
  namespaceId: "research",
  environment: "local",
  lifecycleState: "ready",
  readiness: "ready",
  activeRevisionId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1002",
  upstreamCount: 1,
  exposedToolCount: 1,
  policyState: "configured",
  lastDeployment: "2026-09-04T15:26:00.000Z",
  updatedAt: "2026-09-04T15:26:00.000Z",
};

const summaries = new Map<string, ProxySummary>([[seed.proxyId, seed]]);
const drafts = new Map<string, { revisionId: string; form: Record<string, unknown> }>();
const activity = new Map<string, ProxyActivityEvent[]>([[seed.proxyId, [{
  eventId: "0191b7f1-7f2c-7c13-9a61-2f29f2be1003",
  callId: "call_01J7MCP7NQ",
  status: "allowed",
  tool: "portfolio.read",
  policy: "research-read-only",
  revisionId: seed.activeRevisionId,
  latencyMs: 184,
  inputBytes: 96,
  outputBytes: 412,
  occurredAt: "2026-09-04T15:26:04.000Z",
}]]]);

function scoped(items: Iterable<ProxySummary>, workspaceId: string, namespaceId: string): ProxySummary[] {
  return [...items].filter((item) => item.workspaceId === workspaceId && item.namespaceId === namespaceId);
}

export const previewProxyApi: McpProxyApi = {
  async list({ workspaceId, namespaceId, search, status }) {
    const normalized = search?.trim().toLowerCase() ?? "";
    const items = scoped(summaries.values(), workspaceId, namespaceId).filter((item) =>
      (!normalized || `${item.displayName} ${item.slug}`.toLowerCase().includes(normalized)) &&
      (!status || item.lifecycleState === status),
    );
    return { items };
  },

  async get(proxyId) {
    const proxy = summaries.get(proxyId);
    if (!proxy) throw new Error("proxy unavailable");
    return proxy;
  },

  async create({ displayName, slug, workspaceId, namespaceId }) {
    const proxyId = id();
    const revisionId = id();
    const proxy: ProxySummary = {
      proxyId,
      displayName,
      slug,
      workspaceId,
      namespaceId,
      environment: "local",
      lifecycleState: "draft",
      readiness: "unknown",
      activeRevisionId: revisionId,
      upstreamCount: 0,
      exposedToolCount: 0,
      policyState: "needs-review",
      lastDeployment: "never",
      updatedAt: now(),
    };
    summaries.set(proxyId, proxy);
    drafts.set(proxyId, { revisionId, form: {} });
    activity.set(proxyId, []);
    return { proxyId, revisionId, status: "draft" } satisfies ProxyDraft;
  },

  async updateDraft({ proxyId, expectedRevisionId, patch }: UpdateProxyDraftInput) {
    const draft = drafts.get(proxyId);
    if (!draft || draft.revisionId !== expectedRevisionId) throw new Error("draft changed; refresh and retry");
    drafts.set(proxyId, { revisionId: draft.revisionId, form: { ...draft.form, ...patch } });
    const current = summaries.get(proxyId);
    if (current) summaries.set(proxyId, { ...current, displayName: patch.displayName || current.displayName, slug: patch.slug || current.slug, environment: patch.environment, upstreamCount: patch.upstreamName ? 1 : 0, exposedToolCount: patch.exposedTool ? 1 : 0, policyState: patch.policyId ? "configured" : "needs-review", updatedAt: now() });
    return { proxyId, revisionId: expectedRevisionId, status: "draft" } satisfies ProxyDraft;
  },

  async validate({ proxyId, revisionId }) {
    const draft = drafts.get(proxyId);
    if (!draft || draft.revisionId !== revisionId) return { valid: false, errors: ["The draft revision is no longer current."] };
    const required = ["displayName", "slug", "endpoint", "upstreamName", "exposedTool", "policyId"];
    const errors = required.filter((field) => !draft.form[field]).map((field) => `${field} is required`);
    return { valid: errors.length === 0, errors };
  },

  async publish({ proxyId, expectedRevisionId }) {
    const proxy = summaries.get(proxyId);
    if (!proxy || proxy.activeRevisionId !== expectedRevisionId) throw new Error("revision changed; refresh and retry");
    const revision: ProxyRevision = { proxyId, revisionId: expectedRevisionId, configHash: "preview-" + expectedRevisionId.slice(0, 8) };
    summaries.set(proxyId, { ...proxy, lifecycleState: "published", updatedAt: now() });
    return revision;
  },

  async deploy({ proxyId, revisionId }) {
    const proxy = summaries.get(proxyId);
    if (!proxy) throw new Error("proxy unavailable");
    const updated = { ...proxy, lifecycleState: "ready" as const, readiness: "ready" as const, activeRevisionId: revisionId, lastDeployment: now(), updatedAt: now() };
    summaries.set(proxyId, updated);
    return { proxyId, revisionId, lifecycleState: updated.lifecycleState, readiness: updated.readiness } satisfies ProxyStatus;
  },

  async action({ proxyId, expectedRevisionId, action }) {
    const proxy = summaries.get(proxyId);
    if (!proxy || proxy.activeRevisionId !== expectedRevisionId) throw new Error("revision changed; refresh and retry");
    const lifecycleState = action === "pause" ? "paused" : action === "resume" ? "ready" : "retired";
    const readiness = lifecycleState === "ready" ? "ready" : lifecycleState === "retired" ? "unknown" : "degraded";
    const updated = { ...proxy, lifecycleState, readiness, updatedAt: now() } as ProxySummary;
    summaries.set(proxyId, updated);
    return { proxyId, revisionId: expectedRevisionId, lifecycleState, readiness } satisfies ProxyStatus;
  },

  async activity({ proxyId, limit }) {
    return { events: (activity.get(proxyId) ?? []).slice(0, limit) };
  },
};

export function requestId(): string {
  return id();
}
