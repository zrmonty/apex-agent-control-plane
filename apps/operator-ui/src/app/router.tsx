import { useParams, createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import { AppShell, PlaceholderPage } from "../layout/AppShell";
import { SessionGate } from "../api/session-context";
import { NewProxyWizard } from "../features/mcp-proxies/NewProxyWizard";
import { ProxyDetailPage } from "../features/mcp-proxies/ProxyDetailPage";
import { ProxyListPage } from "../features/mcp-proxies/ProxyListPage";

function ProxyDetailRoute({ activityOnly = false }: { activityOnly?: boolean }) {
  const params = useParams({ strict: false });
  return <ProxyDetailPage proxyId={params.proxyId ?? ""} activityOnly={activityOnly} />;
}

function AuthenticatedShell() { return <SessionGate><AppShell /></SessionGate>; }
const rootRoute = createRootRoute({ component: AuthenticatedShell,
  errorComponent: () => <main id="main-content" className="session-screen"><section><h1>Page unavailable</h1><p>The console could not safely display this page.</p><a className="primary-button" href="/mcp-proxies">Return to proxies</a></section></main>,
});
const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/",
  beforeLoad: () => { throw redirect({ to: "/mcp-proxies", replace: true }); },
});
const agentsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/agents", component: () => <PlaceholderPage title="Agent groups" description="Manage scoped agent identities, enrollment state, and operational ownership." /> });
const eventsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/events", component: () => <PlaceholderPage title="Event stream" description="Inspect admitted events, durable delivery state, and correlated error reports." /> });
const findingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/findings", component: () => <PlaceholderPage title="Findings" description="Investigate security and quality signals with scoped evidence and auditable triage." /> });
const evidenceRoute = createRoute({ getParentRoute: () => rootRoute, path: "/evidence", component: () => <PlaceholderPage title="Evidence vault" description="Verify immutable records, receipts, and retrieval readiness." /> });
const retentionRoute = createRoute({ getParentRoute: () => rootRoute, path: "/retention", component: () => <PlaceholderPage title="Retention" description="Configure retention posture and provider capabilities." /> });
const deploymentRoute = createRoute({ getParentRoute: () => rootRoute, path: "/deployment", component: () => <PlaceholderPage title="Deployment" description="Review local service readiness, certificates, and storage connections." /> });
const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/settings", component: () => <PlaceholderPage title="Settings" description="Set installation-wide identity, policy, and display preferences." /> });
const proxyListRoute = createRoute({ getParentRoute: () => rootRoute, path: "/mcp-proxies", component: ProxyListPage });
const proxyNewRoute = createRoute({ getParentRoute: () => rootRoute, path: "/mcp-proxies/new", component: NewProxyWizard });
const proxyDetailRoute = createRoute({ getParentRoute: () => rootRoute, path: "/mcp-proxies/$proxyId", component: () => <ProxyDetailRoute /> });
const proxyActivityRoute = createRoute({ getParentRoute: () => rootRoute, path: "/mcp-proxies/$proxyId/activity", component: () => <ProxyDetailRoute activityOnly /> });

const routeTree = rootRoute.addChildren([
  indexRoute,
  agentsRoute,
  eventsRoute,
  findingsRoute,
  evidenceRoute,
  retentionRoute,
  deploymentRoute,
  settingsRoute,
  proxyListRoute,
  proxyNewRoute,
  proxyDetailRoute,
  proxyActivityRoute,
]);

export const router = createRouter({ routeTree });
declare module "@tanstack/react-router" { interface Register { router: typeof router } }
