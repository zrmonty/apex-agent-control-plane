import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { AlertTriangle, Plus, RefreshCw, Search } from "lucide-react";
import { useState, type ReactNode } from "react";
import { ApiError } from "../../api/client";
import { useOperatorSession } from "../../api/session-context";
import { proxyQueryKeys, useProxyApi } from "./api";
import { ProxyCard } from "./ProxyCard";
import { lifecycleCopy } from "./presentation";

export function ProxyListPage() {
  const { queryPrefix } = useOperatorSession();
  return <Inventory key={JSON.stringify(queryPrefix)} />;
}
function Inventory() {
  const { scope, queryPrefix } = useOperatorSession();
  const api = useProxyApi();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [pages, setPages] = useState([""]);
  const pageToken = pages[pages.length - 1];
  const query = useQuery({
    queryKey: proxyQueryKeys.list(queryPrefix ?? [], pageToken), enabled: Boolean(scope),
    queryFn: async ({ signal }) => {
      if (!scope) throw new ApiError("unauthenticated");
      const page = await api.listProxies({ ...scope, pageSize: 25, pageToken }, signal);
      if (page.proxies.some(proxy => proxy.workspaceId !== scope.workspaceId || proxy.namespaceId !== scope.namespaceId)) {
        throw new ApiError("invalid-response");
      }
      return page;
    },
  });
  const items = (query.data?.proxies ?? []).filter(proxy =>
    (!search.trim() || (proxy.displayName + " " + proxy.slug).toLowerCase().includes(search.trim().toLowerCase()))
    && (!status || String(proxy.lifecycleState) === status));
  return <main id="main-content" className="proxy-page">
    <header className="app-header"><div className="crumb"><span>{scope?.workspaceId} / {scope?.namespaceId}</span><b>/</b><strong>MCP proxies</strong></div></header>
    <div className="proxy-page-intro"><div><h1>MCP proxies</h1><p>Manage scoped tool boundaries, configuration and control-plane evidence.</p></div>
      <Link className="new-proxy-button" to="/mcp-proxies/new"><Plus size={28} aria-hidden="true" /> New proxy</Link></div>
    <div className="proxy-operating-strip">
      <span>{query.data ? query.data.proxies.length + " proxies on this page" : "Inventory not loaded"}</span>
      <span>{scope?.workspaceId} / {scope?.namespaceId}</span>
      <span>{query.isError && query.data ? "Stale — refresh failed" : query.data ? "Last received " + new Date(query.dataUpdatedAt).toLocaleTimeString() : "Awaiting control plane"}</span>
    </div>
    <section className="proxy-toolbar" aria-label="Filter this page">
      <label className="search-field"><Search size={16} aria-hidden="true" /><span className="sr-only">Search this page</span>
        <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search this page" /></label>
      <label className="select-field"><span className="sr-only">Status on this page</span><select value={status} onChange={event => setStatus(event.target.value)}>
        <option value="">All statuses on this page</option>{Object.entries(lifecycleCopy).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      <button className="secondary-button" disabled={query.isFetching} onClick={() => void query.refetch()}><RefreshCw size={15} aria-hidden="true" /> Refresh</button>
    </section>
    {query.isPending ? <ProxyState title="Loading managed proxies" description="Reading this scope from the control plane…" />
      : query.isError && !query.data ? <ProxyState title="Proxy inventory unavailable" description="No verified inventory is available. Check your connection and retry." error
        action={<button className="secondary-button" onClick={() => void query.refetch()}>Retry</button>} />
      : <>{query.isError && <p role="alert">Stale inventory. These previously received records do not establish current runtime health.</p>}
        {items.length === 0 ? <ProxyState title={search || status ? "No matches on this page" : pages.length > 1 ? "No proxies on this page" : "No proxies yet"}
          description={search || status ? "Clear the page filters or move to another page." : "Create a draft to begin configuring an MCP proxy."} />
          : <section className="proxy-grid" aria-label="MCP proxy inventory">{items.map(proxy => <ProxyCard key={proxy.proxyId} proxy={proxy} />)}</section>}
        <nav className="proxy-pagination" aria-label="Inventory pages">
          <button className="secondary-button" disabled={pages.length === 1 || query.isFetching} onClick={() => setPages(current => current.slice(0, -1))}>Previous page</button>
          <span>Page {pages.length}</span>
          <button className="secondary-button" disabled={!query.data?.nextPageToken || query.isFetching || pages.includes(query.data.nextPageToken)}
            onClick={() => { if (query.data?.nextPageToken) setPages(current => [...current, query.data!.nextPageToken]); }}>Next page</button>
        </nav>
      </>}
  </main>;
}
function ProxyState({ title, description, action, error = false }: { title: string; description: string; action?: ReactNode; error?: boolean }) {
  return <section className={"proxy-state " + (error ? "proxy-state-error" : "")} role={error ? "alert" : "status"}>
    <div className="proxy-state-icon">{error ? <AlertTriangle size={22} /> : <Plus size={22} />}</div><h2>{title}</h2><p>{description}</p>{action}
  </section>;
}
