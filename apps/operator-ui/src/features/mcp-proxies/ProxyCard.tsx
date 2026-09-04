import { ChevronRight, CircleCheck, CircleX, Clock3, PauseCircle } from "lucide-react";
import { Link } from "@tanstack/react-router";
import type { ProxySummary } from "./types";

const statusCopy: Record<ProxySummary["lifecycleState"], string> = {
  draft: "Draft",
  published: "Published",
  provisioning: "Provisioning",
  ready: "Ready",
  paused: "Paused",
  failed: "Failed",
  retired: "Retired",
};

function StatusIcon({ state }: { state: ProxySummary["lifecycleState"] }) {
  if (state === "ready") return <CircleCheck size={16} />;
  if (state === "failed") return <CircleX size={16} />;
  if (state === "paused" || state === "retired") return <PauseCircle size={16} />;
  return <Clock3 size={16} />;
}

export function ProxyCard({ proxy }: { proxy: ProxySummary }) {
  return <article className="proxy-card">
    <div className="proxy-card-top"><div className={`proxy-status status-${proxy.lifecycleState}`}><StatusIcon state={proxy.lifecycleState} />{statusCopy[proxy.lifecycleState]}</div><span className="proxy-environment">{proxy.environment}</span></div>
    <div className="proxy-card-title"><div><h2>{proxy.displayName}</h2><p>{proxy.slug}</p></div><Link className="proxy-card-open" to="/mcp-proxies/$proxyId" params={{ proxyId: proxy.proxyId }} aria-label={`Open ${proxy.displayName}`}><ChevronRight size={18} /></Link></div>
    <div className="proxy-scope"><span>Scope</span><strong>{proxy.workspaceId} / {proxy.namespaceId}</strong></div>
    <dl className="proxy-metrics"><div><dt>Revision</dt><dd>{proxy.activeRevisionId.slice(0, 8)}…</dd></div><div><dt>Upstreams</dt><dd>{proxy.upstreamCount}</dd></div><div><dt>Tools</dt><dd>{proxy.exposedToolCount}</dd></div><div><dt>Policy</dt><dd className={`policy-${proxy.policyState}`}>{proxy.policyState === "configured" ? "Configured" : proxy.policyState === "needs-review" ? "Needs review" : "Blocked"}</dd></div></dl>
    <div className="proxy-card-foot"><span className={`readiness readiness-${proxy.readiness}`}>{proxy.readiness === "ready" ? "Healthy" : proxy.readiness}</span><span>Deployed {proxy.lastDeployment === "never" ? "never" : new Date(proxy.lastDeployment).toLocaleDateString()}</span></div>
  </article>;
}
