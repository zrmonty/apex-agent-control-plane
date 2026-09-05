import { Link } from "@tanstack/react-router";

const pending = ["Upstreams & tools", "Authentication", "CLI runners", "Governance", "Runtime", "Revisions"];
export function ProxyTabs({ proxyId, activeTab }: { proxyId: string; activeTab: string }) {
  return <nav className="proxy-tabs" aria-label="Proxy sections">
    <Link className={"proxy-tab " + (activeTab === "" ? "active" : "")} to="/mcp-proxies/$proxyId" params={{ proxyId }}>Overview</Link>
    {pending.map(label => <button key={label} className="proxy-tab" disabled title="Server integration pending">{label}</button>)}
    <Link className={"proxy-tab " + (activeTab === "activity" ? "active" : "")} to="/mcp-proxies/$proxyId/activity" params={{ proxyId }}>Activity</Link>
  </nav>;
}
