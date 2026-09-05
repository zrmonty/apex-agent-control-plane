import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { ApiError } from "../../api/client";
import { useOperatorSession } from "../../api/session-context";
import { proxyQueryKeys, useProxyApi } from "./api";
import { lifecycleCopy } from "./presentation";
import { ProxyTabs } from "./ProxyTabs";

export function ProxyDetailPage({ proxyId, activityOnly = false }: { proxyId: string; activityOnly?: boolean }) {
  const { queryPrefix } = useOperatorSession();
  return <Detail key={JSON.stringify([queryPrefix, proxyId])} proxyId={proxyId} activityOnly={activityOnly} />;
}
function Detail({ proxyId, activityOnly }: { proxyId: string; activityOnly: boolean }) {
  const { scope, queryPrefix } = useOperatorSession();
  const api = useProxyApi();
  const query = useQuery({
    queryKey: proxyQueryKeys.detail(queryPrefix ?? [], proxyId), enabled: Boolean(scope && proxyId),
    queryFn: async ({ signal }) => {
      if (!scope) throw new ApiError("unauthenticated");
      const result = await api.getProxy({ ...scope, proxyId }, signal);
      if (!result.proxy || result.proxy.proxyId !== proxyId || result.proxy.workspaceId !== scope.workspaceId
        || result.proxy.namespaceId !== scope.namespaceId) throw new ApiError("invalid-response");
      return result.proxy;
    },
  });
  const proxy = query.data;
  return <main id="main-content" className="proxy-page">
    <header className="app-header"><div className="crumb"><Link to="/mcp-proxies">MCP proxies</Link><span>/</span><strong>Proxy detail</strong></div><span>{scope?.workspaceId} / {scope?.namespaceId}</span></header>
    {query.isPending ? <section className="proxy-state" role="status"><h2>Loading proxy</h2></section>
      : !proxy ? <section className="proxy-state proxy-state-error" role="alert"><h2>Proxy unavailable</h2><p>No verified record is available for this scope and identity.</p><button className="secondary-button" onClick={() => void query.refetch()}>Retry</button></section>
      : <>
        <div className="detail-heading"><div><h1>{proxy.displayName}</h1><p>{proxy.slug} · {proxy.workspaceId} / {proxy.namespaceId}</p></div><span className="proxy-status">{lifecycleCopy[proxy.lifecycleState] ?? "Unknown"}</span></div>
        <div className="detail-actions"><Link className="secondary-button" to="/mcp-proxies">All proxies</Link><button className="secondary-button" disabled={query.isFetching} onClick={() => void query.refetch()}>Refresh proxy</button></div>
        {query.isError && <p role="alert">Stale proxy record. Refresh failed; current runtime health is unavailable.</p>}
        <p>Proxy last received <time dateTime={new Date(query.dataUpdatedAt).toISOString()}>{new Date(query.dataUpdatedAt).toLocaleTimeString()}</time>. Runtime readiness is unavailable.</p>
        <ProxyTabs proxyId={proxy.proxyId} activeTab={activityOnly ? "activity" : ""} />
        {activityOnly ? <ActivityPanel proxyId={proxyId} revisionId={proxy.activeRevisionId} /> : <section className="detail-panel">
          <h2>Configuration</h2><dl className="detail-list">
            <div><dt>Active revision</dt><dd>{proxy.activeRevisionId || "Not configured"}</dd></div>
            <div><dt>Draft revision</dt><dd>{proxy.draftRevisionId || "Not configured"}</dd></div>
            <div><dt>Upstreams</dt><dd>{proxy.spec ? proxy.spec.upstreams.length : "Not configured"}</dd></div>
            <div><dt>Runtime readiness</dt><dd>Unavailable</dd></div>
          </dl><p>Runtime configuration, authentication bindings and governance controls are being connected to the server. Deployment actions remain unavailable until those capabilities are verified.</p>
        </section>}
      </>}
  </main>;
}
function ActivityPanel({ proxyId, revisionId }: { proxyId: string; revisionId: string }) {
  const { scope, queryPrefix } = useOperatorSession();
  const api = useProxyApi();
  const [pages, setPages] = useState([""]);
  const token = pages[pages.length - 1];
  const query = useQuery({
    queryKey: proxyQueryKeys.activity(queryPrefix ?? [], proxyId, revisionId, token),
    enabled: Boolean(scope),
    queryFn: async ({ signal }) => {
      if (!scope) throw new ApiError("unauthenticated");
      const result = await api.listProxyActivity({ ...scope, proxyId, pageSize: 25, pageToken: token }, signal);
      if (result.activity.some(entry => entry.proxyId !== proxyId)) throw new ApiError("invalid-response");
      return result;
    },
  });
  const activity = query.data;
  return <section className="activity-panel" aria-labelledby="activity-heading"><h2 id="activity-heading">Activity</h2>
    <div className="detail-actions"><button className="secondary-button" disabled={query.isFetching} onClick={() => void query.refetch()}>Refresh activity</button></div>
    {query.isFetching && <p role="status">{activity ? "Refreshing activity…" : "Loading activity…"}</p>}
    {query.isError && <p role="alert">{activity ? "Stale activity. Refresh failed; showing the last received records." : "Activity unavailable. Refresh activity to try again."}</p>}
    {activity && <>
      <p>Activity last received <time dateTime={new Date(query.dataUpdatedAt).toISOString()}>{new Date(query.dataUpdatedAt).toLocaleTimeString()}</time>.</p>
      {activity.activity.length === 0 ? <p>No activity records on this page.</p> : <ul className="proxy-activity-list">{activity.activity.map(entry =>
        <li key={entry.activityId}><strong>{entry.activityType}</strong><p>{entry.summary}</p><time>{entry.occurredAt}</time><small>Revision {entry.revisionId || "not configured"}</small></li>)}</ul>}
      <nav className="proxy-pagination" aria-label="Activity pages"><button className="secondary-button" disabled={pages.length === 1 || query.isFetching} onClick={() => setPages(current => current.slice(0, -1))}>Previous page</button>
        <span>Page {pages.length}</span><button className="secondary-button" disabled={!activity.nextPageToken || query.isFetching || pages.includes(activity.nextPageToken)}
          onClick={() => setPages(current => [...current, activity.nextPageToken])}>Next page</button></nav>
    </>}
  </section>;
}
