import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, CheckCircle2, CircleAlert, CirclePause, ExternalLink, History, Play, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { proxyQueryKeys, previewProxyApi, requestId } from "./api";
import { ProxyTabs } from "./ProxyTabs";
import type { ProxySummary } from "./types";

export function ProxyDetailPage({ proxyId, activityOnly = false }: { proxyId: string; activityOnly?: boolean }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const proxyQuery = useQuery({ queryKey: proxyQueryKeys.detail(proxyId), queryFn: () => previewProxyApi.get(proxyId), enabled: Boolean(proxyId) });
  const proxy = proxyQuery.data;

  async function action(actionName: "pause" | "resume" | "retire") {
    if (!proxy || (actionName === "retire" && !window.confirm("Retire this proxy? This cannot be undone from the UI."))) return;
    setBusy(true);
    try {
      await previewProxyApi.action({ proxyId: proxy.proxyId, expectedRevisionId: proxy.activeRevisionId, requestId: requestId(), action: actionName });
      await queryClient.invalidateQueries({ queryKey: proxyQueryKeys.detail(proxy.proxyId) });
      await queryClient.invalidateQueries({ queryKey: proxyQueryKeys.all });
      setMessage(`Server accepted ${actionName}. Readiness is now authoritative.`);
    } catch { setMessage("The action was rejected safely. Refresh and verify the current revision."); }
    finally { setBusy(false); }
  }

  if (proxyQuery.isLoading) return <main id="main-content" className="proxy-page"><DetailHeader /><div className="proxy-state"><h2>Loading proxy</h2><p>Reading server-derived status…</p></div></main>;
  if (proxyQuery.isError || !proxy) return <main id="main-content" className="proxy-page"><DetailHeader /><div className="proxy-state proxy-state-error"><CircleAlert size={22} /><h2>Proxy unavailable</h2><p>This proxy is outside your scope or no longer exists.</p><Link className="secondary-button" to="/mcp-proxies"><ArrowLeft size={15} /> Back to proxies</Link></div></main>;

  const tab = activityOnly ? "activity" : "";
  return <main id="main-content" className="proxy-page"><DetailHeader /><div className="detail-heading"><div><p className="eyebrow">Managed MCP boundary</p><h1>{proxy.displayName}</h1><p>{proxy.slug} · {proxy.workspaceId} / {proxy.namespaceId}</p></div><div className={`proxy-status status-${proxy.lifecycleState}`}><StateIcon state={proxy.lifecycleState} />{proxy.lifecycleState}</div></div>
    <div className="detail-actions"><Link className="secondary-button" to="/mcp-proxies"><ArrowLeft size={15} /> All proxies</Link><div>{proxy.lifecycleState === "paused" ? <button className="secondary-button" type="button" onClick={() => void action("resume")} disabled={busy}><Play size={15} /> Resume</button> : proxy.lifecycleState !== "retired" && <button className="secondary-button" type="button" onClick={() => void action("pause")} disabled={busy}><CirclePause size={15} /> Pause</button>}{proxy.lifecycleState !== "retired" && <button className="danger-button" type="button" onClick={() => void action("retire")} disabled={busy}>Retire</button>}</div></div>{message && <div className="action-message" role="status"><ShieldCheck size={16} />{message}</div>}
    <ProxyTabs proxy={proxy} activeTab={tab} />
    {activityOnly ? <ActivityPanel proxy={proxy} /> : <Overview proxy={proxy} onActivity={() => void navigate({ to: "/mcp-proxies/$proxyId/activity", params: { proxyId: proxy.proxyId } })} />}
  </main>;
}

function DetailHeader() { return <header className="app-header"><div className="crumb"><Link to="/mcp-proxies">MCP proxies</Link><span>/</span><strong>Proxy detail</strong></div><span className="detail-live"><i /> scope: Northstar research / research</span></header>; }

function StateIcon({ state }: { state: ProxySummary["lifecycleState"] }) { return state === "ready" ? <CheckCircle2 size={17} /> : state === "paused" ? <CirclePause size={17} /> : <CircleAlert size={17} />; }

function Overview({ proxy, onActivity }: { proxy: ProxySummary; onActivity: () => void }) {
  return <section className="detail-overview"><div className="detail-stat-grid"><Stat label="Readiness" value={proxy.readiness} /><Stat label="Active revision" value={proxy.activeRevisionId.slice(0, 8) + "…"} /><Stat label="Upstreams" value={String(proxy.upstreamCount)} /><Stat label="Exposed tools" value={String(proxy.exposedToolCount)} /></div><div className="detail-panels"><section className="detail-panel"><div className="panel-title"><div><p>Control boundary</p><h2>Explicit and isolated</h2></div><ShieldCheck size={20} /></div><dl className="detail-list"><div><dt>Environment</dt><dd>{proxy.environment}</dd></div><div><dt>Policy</dt><dd>{proxy.policyState}</dd></div><div><dt>Last deployment</dt><dd>{proxy.lastDeployment === "never" ? "Never" : new Date(proxy.lastDeployment).toLocaleString()}</dd></div><div><dt>Health source</dt><dd>Control plane</dd></div></dl></section><section className="detail-panel"><div className="panel-title"><div><p>Recent evidence</p><h2>Activity is scoped to this proxy</h2></div><History size={20} /></div><p className="panel-copy">Calls, decisions, policy revisions, timing, and bounded sizes are recorded without raw tool output or secret values.</p><button className="text-button" type="button" onClick={onActivity}>Open activity <ExternalLink size={14} /></button></section></div></section>;
}

function ActivityPanel({ proxy }: { proxy: ProxySummary }) {
  const activityQuery = useQuery({ queryKey: proxyQueryKeys.activity(proxy.proxyId), queryFn: () => previewProxyApi.activity({ proxyId: proxy.proxyId, limit: 25 }) });
  const events = activityQuery.data?.events ?? [];
  return <section className="activity-panel"><div className="panel-title"><div><p>Server-derived evidence</p><h2>Activity</h2></div><span className="activity-fresh"><i />live boundary</span></div>{activityQuery.isError ? <div className="inline-empty"><CircleAlert size={18} />Activity is temporarily unavailable.</div> : activityQuery.isLoading ? <div className="inline-empty">Loading activity…</div> : events.length === 0 ? <div className="inline-empty">No calls have been admitted for this proxy.</div> : <div className="activity-table"><div className="activity-row activity-head"><span>Call</span><span>Tool / decision</span><span>Policy</span><span>Timing</span></div>{events.map((event) => <div className="activity-row" key={event.eventId}><span><strong>{event.callId}</strong><small>{new Date(event.occurredAt).toLocaleString()}</small></span><span><strong>{event.tool}</strong><small className={`event-${event.status}`}>{event.status}</small></span><span>{event.policy}<small>{event.revisionId.slice(0, 8)}…</small></span><span>{event.latencyMs} ms<small>{event.inputBytes} in / {event.outputBytes} out</small></span></div>)}</div>}</section>;
}

function Stat({ label, value }: { label: string; value: string }) { return <div className="detail-stat"><span>{label}</span><strong>{value}</strong></div>; }
