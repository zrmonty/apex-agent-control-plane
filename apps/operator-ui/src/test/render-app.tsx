import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { SessionProvider } from "../api/session-context";
import { router as application } from "../app/router";

export function renderApp(path = "/mcp-proxies") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const history = createMemoryHistory({ initialEntries: [path] });
  const router = createRouter({ routeTree: application.routeTree, history, defaultHashScrollIntoView: false });
  const view = render(<QueryClientProvider client={client}><SessionProvider><RouterProvider router={router} /></SessionProvider></QueryClientProvider>);
  return { ...view, client, router };
}

export const testSession = {
  subject: "operator:keycloak:alice", csrfToken: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
  scopes: [{ workspaceId: "acme", namespaceId: "prod" }, { workspaceId: "acme", namespaceId: "dev" }],
  capabilities: { runtimeReadiness: "unknown", approvals: false, traces: false },
};
export const jsonResponse = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { "content-type": "application/json" },
});
