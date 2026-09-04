export type ProxyLifecycleState = "draft" | "published" | "provisioning" | "ready" | "paused" | "failed" | "retired";

export type ProxySummary = Readonly<{
  proxyId: string;
  displayName: string;
  slug: string;
  workspaceId: string;
  namespaceId: string;
  environment: "local" | "staging" | "production";
  lifecycleState: ProxyLifecycleState;
  readiness: "unknown" | "ready" | "degraded" | "failed";
  activeRevisionId: string;
  upstreamCount: number;
  exposedToolCount: number;
  policyState: "configured" | "needs-review" | "blocked";
  lastDeployment: string;
  updatedAt: string;
}>;

export type ProxyActivityEvent = Readonly<{
  eventId: string;
  callId: string;
  status: "allowed" | "denied" | "failed";
  tool: string;
  policy: string;
  revisionId: string;
  latencyMs: number;
  inputBytes: number;
  outputBytes: number;
  occurredAt: string;
}>;

export type ProxyDraft = Readonly<{
  proxyId: string;
  revisionId: string;
  status: "draft" | "published";
}>;

export type ProxyRevision = Readonly<{
  proxyId: string;
  revisionId: string;
  configHash: string;
}>;

export type ProxyStatus = Readonly<{
  proxyId: string;
  revisionId: string;
  lifecycleState: ProxyLifecycleState;
  readiness: ProxySummary["readiness"];
}>;

export type ValidationReport = Readonly<{ valid: boolean; errors: readonly string[] }>;

export type ProxyActivityPage = Readonly<{ events: readonly ProxyActivityEvent[]; nextCursor?: string }>;

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
  patch: ProxyWizardDraft;
  requestId: string;
}>;

export type ProxyWizardDraft = Readonly<{
  displayName: string;
  slug: string;
  environment: ProxySummary["environment"];
  ingress: "stdio" | "streamable-http";
  endpoint: string;
  upstreamName: string;
  upstreamCredentialRef: string;
  exposedTool: string;
  cliProfile: string;
  authIssuer: string;
  authAudience: string;
  policyId: string;
  classification: "public" | "internal" | "confidential" | "restricted";
  approvalMode: "none" | "on-demand" | "always";
  budgetPerMinute: string;
}>;

export interface McpProxyApi {
  list(query: Readonly<{ workspaceId: string; namespaceId: string; search?: string; status?: string }>): Promise<Readonly<{ items: readonly ProxySummary[]; nextCursor?: string }>>;
  get(proxyId: string): Promise<ProxySummary>;
  create(input: CreateProxyInput): Promise<ProxyDraft>;
  updateDraft(input: UpdateProxyDraftInput): Promise<ProxyDraft>;
  validate(input: Readonly<{ proxyId: string; revisionId: string }>): Promise<ValidationReport>;
  publish(input: Readonly<{ proxyId: string; expectedRevisionId: string; requestId: string }>): Promise<ProxyRevision>;
  deploy(input: Readonly<{ proxyId: string; revisionId: string; requestId: string }>): Promise<ProxyStatus>;
  action(input: Readonly<{ proxyId: string; expectedRevisionId: string; requestId: string; action: "pause" | "resume" | "retire" }>): Promise<ProxyStatus>;
  activity(query: Readonly<{ proxyId: string; limit: number; cursor?: string }>): Promise<ProxyActivityPage>;
}

export const emptyWizardDraft = (displayName = "", slug = ""): ProxyWizardDraft => ({
  displayName,
  slug,
  environment: "local",
  ingress: "streamable-http",
  endpoint: "https://",
  upstreamName: "",
  upstreamCredentialRef: "secret://",
  exposedTool: "",
  cliProfile: "",
  authIssuer: "https://",
  authAudience: "apex-mcp-proxy",
  policyId: "",
  classification: "confidential",
  approvalMode: "on-demand",
  budgetPerMinute: "60",
});
