import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Link, Outlet, RouterProvider, createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { Activity, Archive, Bell, Bot, Boxes, ChevronDown, ChevronRight, CircleAlert, Database, FileSearch, Network, Plus, Search, Settings, ShieldCheck, UsersRound } from "lucide-react";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/dm-mono/latin-400.css";
import "@fontsource/dm-mono/latin-500.css";
import "@fontsource/manrope/latin-400.css";
import "@fontsource/manrope/latin-500.css";
import "@fontsource/manrope/latin-600.css";
import "@fontsource/manrope/latin-700.css";
import "@fontsource/manrope/latin-800.css";
import "./styles.css";

const navItems = [["Overview", "/", Activity], ["Agent groups", "/agents", UsersRound], ["Event stream", "/events", Network], ["Findings", "/findings", ShieldCheck], ["Evidence vault", "/evidence", Archive], ["Retention", "/retention", Database], ["Deployment", "/deployment", Boxes]] as const;

function RootLayout() {
  return <div className="app-frame">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    <aside className="sidebar" aria-label="Primary navigation">
      <Link to="/" className="apex-logo"><span className="apex-logo-mark" aria-hidden="true" /><span>apex</span></Link>
      <button className="workspace-picker"><span className="workspace-square" aria-hidden="true" />Northstar research<ChevronDown size={15} /></button>
      <nav>{navItems.map(([label, to, Icon]) => <Link key={to} to={to} className="side-link" activeProps={{ className: "side-link current" }}><Icon size={17} strokeWidth={1.9} /><span>{label}</span></Link>)}</nav>
      <div className="sidebar-foot"><Link to="/settings" className="side-link"><Settings size={17} /><span>Settings</span></Link><div className="identity"><span>AM</span><div><strong>Alex Morgan</strong><small>Owner</small></div><ChevronRight size={15} /></div></div>
    </aside>
    <section className="app-workspace"><Outlet /></section>
  </div>;
}

function SystemMap() {
  return <section className="map-panel" aria-labelledby="map-title">
    <div className="map-toolbar"><div><h2 id="map-title">System map</h2><p>Illustrative topology · not live data</p></div><div className="map-tools"><button aria-label="Search the system map"><Search size={17} /></button><button className="map-filter">All scopes <ChevronDown size={14} /></button></div></div>
    <div className="map-canvas" aria-label="Illustrative agent event flow map">
      <svg className="map-lines" viewBox="0 0 900 480" preserveAspectRatio="none" aria-hidden="true"><path d="M116 206 C230 206, 265 122, 380 122 S510 205, 620 205" /><path d="M116 274 C250 274, 272 350, 390 350 S520 278, 620 278" /><path d="M515 122 C585 122, 585 204, 690 204" /><path d="M515 350 C590 350, 590 278, 690 278" /></svg>
      <div className="map-node source n-source"><span className="node-icon"><Bot size={18} /></span><strong>Research agents</strong><small>3 expected</small></div>
      <div className="map-node gateway n-gateway"><span className="node-icon"><Network size={18} /></span><strong>Ingest gateway</strong><small>not connected</small></div>
      <div className="map-node stream n-stream"><span className="node-icon"><Activity size={18} /></span><strong>Durable event stream</strong><small>waiting for event</small></div>
      <div className="map-node store n-store"><span className="node-icon"><Database size={18} /></span><strong>Evidence storage</strong><small>provider not attached</small></div>
      <button className="map-empty n-empty"><Plus size={17} /> Connect first agent</button>
      <div className="map-legend"><span><i className="legend-dot ready" />configured</span><span><i className="legend-dot pending" />awaiting setup</span></div>
    </div>
    <div className="map-caption"><span><b>How to read this map</b> Events travel from a scoped agent through the gateway, then to durable and evidentiary stores.</span><Link to="/events">View event contract <ChevronRight size={15} /></Link></div>
  </section>;
}

function Attention() {
  return <aside className="attention" aria-labelledby="attention-title"><div className="attention-head"><div><p>Needs attention</p><h2 id="attention-title">3 sample findings</h2></div><Link to="/findings">View all</Link></div><ol>
    <li><i className="priority high" /><div><strong>Untrusted control content requires review</strong><span>research / eval-group</span></div><time>3m</time></li>
    <li><i className="priority medium" /><div><strong>Archive receipt pending verification</strong><span>production / claims-agent</span></div><time>18m</time></li>
    <li><i className="priority high" /><div><strong>Scope request exceeded policy boundary</strong><span>research / eval-group</span></div><time>41m</time></li>
  </ol><div className="attention-note"><ShieldCheck size={18} /><p>Findings will appear here when a security store and a scoped gateway are connected.</p></div></aside>;
}

function Dashboard() { return <main id="main-content" className="dashboard">
  <header className="app-header"><div className="crumb"><span>Northstar research</span><ChevronRight size={14} /><b>Overview</b></div><div className="header-actions"><button aria-label="Search"><Search size={18} /></button><button className="notification" aria-label="Notifications"><Bell size={18} /><i /></button><button className="avatar" aria-label="Account menu">AM</button></div></header>
  <div className="view-intro"><div><h1>Trace the shape of your agent system.</h1><p>Start by connecting one scoped agent. Apex will make its event path, evidence posture, and policy findings visible here.</p></div><button className="connect-button"><Plus size={17} />Connect an agent</button></div>
  <div className="operating-strip"><span><i />No live agents connected</span><span>Local installation</span><span>Phase 1 preview data</span><Link to="/deployment">Check deployment <ChevronRight size={14} /></Link></div>
  <div className="overview-grid"><SystemMap /><Attention /></div>
  <section className="lower-row"><div className="setup-list"><div><p>Before you ingest</p><h2>Prepare a safe event path</h2></div><ol><li><b>01</b><span>Bind a workload identity to an agent and scope.</span><Link to="/agents">Identity <ChevronRight size={15} /></Link></li><li><b>02</b><span>Attach a durable event path and projection target.</span><Link to="/deployment">Delivery <ChevronRight size={15} /></Link></li><li><b>03</b><span>Verify evidence storage before strict retention.</span><Link to="/evidence">Evidence <ChevronRight size={15} /></Link></li></ol></div><div className="record-note"><FileSearch size={21} /><h2>Nothing is hidden in the preview.</h2><p>All records on this page are sample data. The interface will distinguish unavailable, loading, empty, and live states when the control-plane API is attached.</p></div></section>
</main>; }

function PlaceholderPage({ title, description }: { title: string; description: string }) { return <main id="main-content" className="placeholder"><header className="app-header"><div className="crumb"><span>Northstar research</span><ChevronRight size={14} /><b>{title}</b></div></header><section><h1>{title}</h1><p>{description}</p><div className="placeholder-box"><CircleAlert size={24} /><h2>No live control-plane data yet.</h2><span>This route is ready for its typed API client and scoped empty, loading, and denied states.</span></div></section></main>; }

const rootRoute = createRootRoute({ component: RootLayout });
const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: Dashboard });
const agentsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/agents", component: () => <PlaceholderPage title="Agent groups" description="Manage scoped agent identities, enrollment state, and operational ownership." /> });
const eventsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/events", component: () => <PlaceholderPage title="Event stream" description="Inspect admitted events, durable delivery state, and correlated error reports." /> });
const findingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/findings", component: () => <PlaceholderPage title="Findings" description="Investigate security and quality signals with scoped evidence and auditable triage." /> });
const evidenceRoute = createRoute({ getParentRoute: () => rootRoute, path: "/evidence", component: () => <PlaceholderPage title="Evidence vault" description="Verify immutable records, receipts, and retrieval readiness." /> });
const retentionRoute = createRoute({ getParentRoute: () => rootRoute, path: "/retention", component: () => <PlaceholderPage title="Retention" description="Configure retention posture and provider capabilities." /> });
const deploymentRoute = createRoute({ getParentRoute: () => rootRoute, path: "/deployment", component: () => <PlaceholderPage title="Deployment" description="Review local service readiness, certificates, and storage connections." /> });
const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings", component: () => <PlaceholderPage title="Settings" description="Set installation-wide identity, policy, and display preferences." /> });
const routeTree = rootRoute.addChildren([indexRoute, agentsRoute, eventsRoute, findingsRoute, evidenceRoute, retentionRoute, deploymentRoute, settingsRoute]);
const router = createRouter({ routeTree });
declare module "@tanstack/react-router" { interface Register { router: typeof router } }
const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 30_000 } } });
createRoot(document.getElementById("root")!).render(<StrictMode><QueryClientProvider client={queryClient}><RouterProvider router={router} /></QueryClientProvider></StrictMode>);
