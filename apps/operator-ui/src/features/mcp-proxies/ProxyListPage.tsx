import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { AlertTriangle, Filter, Plus, RefreshCw, Search } from "lucide-react";
import { useState } from "react";
import { proxyQueryKeys, previewProxyApi } from "./api";
import { ProxyCard } from "./ProxyCard";

const scope = { workspaceId: "northstar-research", namespaceId: "research" } as const;

export function ProxyListPage() {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const query = useQuery({ queryKey: proxyQueryKeys.list(scope.workspaceId, scope.namespaceId, search, status), queryFn: () => previewProxyApi.list({ ...scope, search, status }) });
  const items = query.data?.items ?? [];

  return <main id="main-content" className="proxy-page"><header className="app-header"><div className="crumb"><span>Northstar research</span><b>/</b><strong>MCP proxies</strong></div><div className="header-actions"><button type="button" aria-label="Search"><Search size={18} /></button><button className="notification" type="button" aria-label="Notifications"><span>•</span><i /></button><button className="avatar" type="button" aria-label="Account menu">AM</button></div></header>
    <div className="proxy-page-intro"><div><p className="eyebrow">Managed tool boundaries</p><h1>MCP proxies</h1><p>Give agents a clear, governed path to external tools. Each proxy owns its upstream sessions, credentials, policy, and evidence trail.</p></div><Link className="new-proxy-button" to="/mcp-proxies/new"><Plus size={20} /> New proxy</Link></div>
    <div className="proxy-operating-strip"><span><i className="online-dot" />{query.data?.items.length ?? 0} proxies in scope</span><span>Northstar research / research</span><span>Server-authoritative state</span></div>
    <section className="proxy-toolbar" aria-label="Proxy filters"><label className="search-field"><Search size={16} /><span className="sr-only">Search proxies</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search by name or slug" /></label><label className="select-field"><Filter size={15} /><span className="sr-only">Filter by status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option><option value="ready">Ready</option><option value="draft">Draft</option><option value="paused">Paused</option><option value="failed">Failed</option></select></label></section>
    {query.isLoading ? <ProxyState title="Loading managed proxies" description="Reading the current scope from the control plane…" /> : query.isError ? <ProxyState title="Proxy inventory unavailable" description="The control-plane service did not return a safe inventory response." action={<button className="secondary-button" type="button" onClick={() => void query.refetch()}><RefreshCw size={15} /> Retry</button>} error /> : items.length === 0 ? <ProxyState title={search || status ? "No matching proxies" : "No proxies yet"} description={search || status ? "Try a different search or clear the server-supported filters." : "Create the first governed MCP boundary for this scope."} action={!search && !status ? <Link className="secondary-button" to="/mcp-proxies/new"><Plus size={15} /> New proxy</Link> : undefined} /> : <section className="proxy-grid" aria-label="MCP proxy inventory">{items.map((proxy) => <ProxyCard key={proxy.proxyId} proxy={proxy} />)}</section>}
  </main>;
}

function ProxyState({ title, description, action, error = false }: { title: string; description: string; action?: React.ReactNode; error?: boolean }) {
  return <section className={`proxy-state ${error ? "proxy-state-error" : ""}`}><div className="proxy-state-icon">{error ? <AlertTriangle size={22} /> : <Plus size={22} />}</div><h2>{title}</h2><p>{description}</p>{action}</section>;
}
