import { Link } from "@tanstack/react-router";
import { Activity, KeyRound, Layers3, ListChecks, Scale, TerminalSquare, Wrench } from "lucide-react";
import type { ProxySummary } from "./types";

const tabs = [
  ["Overview", "", Layers3],
  ["Upstreams & tools", "upstreams", Wrench],
  ["Authentication", "auth", KeyRound],
  ["CLI runners", "cli", TerminalSquare],
  ["Governance", "governance", Scale],
  ["Runtime", "runtime", ListChecks],
  ["Activity", "activity", Activity],
  ["Revisions", "revisions", Layers3],
] as const;

export function ProxyTabs({ proxy, activeTab }: { proxy: ProxySummary; activeTab: string }) {
  return <nav className="proxy-tabs" aria-label="Proxy sections">{tabs.map(([label, suffix, Icon]) => <Link key={label} className={activeTab === suffix ? "proxy-tab active" : "proxy-tab"} to={suffix === "activity" ? "/mcp-proxies/$proxyId/activity" : "/mcp-proxies/$proxyId"} params={{ proxyId: proxy.proxyId }} search={suffix ? { tab: suffix } : undefined}><Icon size={15} />{label}</Link>)}</nav>;
}
