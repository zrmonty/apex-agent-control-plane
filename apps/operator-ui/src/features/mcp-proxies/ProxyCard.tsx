import { ChevronRight, Clock3 } from "lucide-react";
import { Link } from "@tanstack/react-router";
import type { McpProxySummary } from "@apex/contracts";
import { lifecycleCopy } from "./presentation";

export function ProxyCard({ proxy }: { proxy: McpProxySummary }) {
  const state = lifecycleCopy[proxy.lifecycleState] ?? "Unknown";
  return <article className="proxy-card">
    <div className="proxy-card-top"><div className={"proxy-status status-" + state.toLowerCase().replaceAll(" ", "-")}><Clock3 size={16} />{state}</div><span className="proxy-environment">Control-plane state</span></div>
    <div className="proxy-card-title"><div><h2>{proxy.displayName}</h2><p>{proxy.slug}</p></div><Link className="proxy-card-open" to="/mcp-proxies/$proxyId" params={{ proxyId: proxy.proxyId }} aria-label={"Open " + proxy.displayName}><ChevronRight size={18} /></Link></div>
    <div className="proxy-scope"><span>Scope</span><strong>{proxy.workspaceId} / {proxy.namespaceId}</strong></div>
    <dl className="proxy-metrics"><div><dt>Active revision</dt><dd>{proxy.activeRevisionId || "Not configured"}</dd></div></dl>
    <div className="proxy-card-foot"><span>Readiness unavailable</span></div>
  </article>;
}
