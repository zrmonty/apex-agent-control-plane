import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { expect, test, vi } from "vitest";
import { renderApp, jsonResponse, testSession } from "../../test/render-app";
import { exampleProxy } from "../../test/fixtures/proxies";

function transport(manage: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation(async (url, init) => {
    if (url === "/api/session") return jsonResponse(testSession);
    return manage(String(url), init ?? {});
  });
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
test("real route renders unavailable inventory with no fabricated proxy or health", async () => {
  const fetch = transport(() => new Response(null, { status: 503 }));
  renderApp();
  expect(await screen.findByText("Proxy inventory unavailable")).toBeInTheDocument();
  expect(screen.queryByText(exampleProxy.displayName)).not.toBeInTheDocument();
  expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  expect(fetch.mock.calls.map(([url]) => url)).toContain("/api/apex/v1/McpProxyService/ListProxies");
  expect(screen.getByRole("combobox", { name: "Workspace and namespace" })).toHaveValue("acme/prod");
});
test("server inventory has opaque pagination and does not invent fields absent from the contract", async () => {
  const fetch = transport((_url, init) => {
    const input = JSON.parse(String(init.body));
    return jsonResponse(input.pageToken ? { proxies: [] } : { proxies: [exampleProxy], nextPageToken: "opaque-next" });
  });
  renderApp();
  expect(await screen.findByText(exampleProxy.displayName)).toBeInTheDocument();
  expect(screen.getByText("Readiness unavailable")).toBeInTheDocument();
  expect(screen.queryByText(/Deployed/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  expect(await screen.findByText("No proxies on this page")).toBeInTheDocument();
  const body = JSON.parse(String(fetch.mock.calls.at(-1)?.[1]?.body));
  expect(body).toEqual({ workspaceId: "acme", namespaceId: "prod", pageSize: 25, pageToken: "opaque-next" });
});
test("scope picker fences an old inventory response and never renders it in the new scope", async () => {
  let deliver!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { deliver = resolve; });
  const fetch = transport((_url, init) => JSON.parse(String(init.body)).namespaceId === "prod" ? pending : jsonResponse({ proxies: [] }));
  renderApp();
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  fireEvent.change(screen.getByRole("combobox", { name: "Workspace and namespace" }), { target: { value: "acme/dev" } });
  expect(await screen.findByText("No proxies yet")).toBeInTheDocument();
  await act(async () => deliver(jsonResponse({ proxies: [exampleProxy] })));
  expect(screen.queryByText(exampleProxy.displayName)).not.toBeInTheDocument();
});
test("new proxy creates only on submit, uses the session scope, and retains mutation IDs on retry", async () => {
  let attempts = 0;
  const fetch = transport((url, init) => {
    if (url.endsWith("CreateProxy")) {
      attempts++;
      const input = JSON.parse(String(init.body));
      return attempts === 1 ? new Response(null, { status: 503 }) : jsonResponse({ proxy: { ...exampleProxy, proxyId: input.proxyId } });
    }
    return jsonResponse({ proxy: exampleProxy });
  });
  renderApp("/mcp-proxies/new");
  const submit = await screen.findByRole("button", { name: "Create draft" });
  expect(fetch).toHaveBeenCalledTimes(1);
  fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "New tools" } });
  fireEvent.change(screen.getByLabelText("Stable slug"), { target: { value: "new-tools" } });
  fireEvent.click(submit);
  expect(await screen.findByRole("alert")).toHaveTextContent("could not confirm");
  fireEvent.click(screen.getByRole("button", { name: "Retry create draft" }));
  await waitFor(() => expect(attempts).toBe(2));
  const requests = fetch.mock.calls.filter(([url]) => String(url).endsWith("CreateProxy"));
  expect(requests[0][1]?.body).toBe(requests[1][1]?.body);
  const input = JSON.parse(String(requests[0][1]?.body));
  expect(input).toMatchObject({ workspaceId: "acme", namespaceId: "prod", displayName: "New tools", slug: "new-tools" });
  expect(input.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  expect(input.proxyId).toMatch(/^[0-9a-f-]{36}$/);
});

const revisionId = "0191b7f1-7f2c-7c13-9a61-2f29f2be1002";
const activityProxy = { ...exampleProxy, activeRevisionId: revisionId };
const activityPath = `/mcp-proxies/${exampleProxy.proxyId}/activity`;
function activityEntry(summary: string, activityId = "0191b7f1-7f2c-7c13-9a61-2f29f2be1003") {
  return { activityId, proxyId: exampleProxy.proxyId, revisionId, occurredAt: "2026-09-04T10:00:00Z",
    actorId: "operator:keycloak:alice", activityType: "Inspection", summary,
    lifecycleState: "MCP_PROXY_LIFECYCLE_STATE_DRAFT", redactionStatus: "MCP_PROXY_REDACTION_STATUS_REDACTED" };
}
function receivedTime(subject: "Proxy" | "Activity") {
  const time = screen.getByText(new RegExp(`^${subject} last received`)).querySelector("time");
  expect(time).not.toBeNull();
  return time!;
}

test("activity route refresh fetches new evidence with an unchanged active revision", async () => {
  let now = Date.parse("2026-09-04T10:00:00Z");
  vi.spyOn(Date, "now").mockImplementation(() => now);
  let activityCalls = 0;
  const fetch = transport(url => {
    if (url.endsWith("GetProxy")) return jsonResponse({ proxy: activityProxy });
    if (url.endsWith("ListProxyActivity")) return jsonResponse({ activity: ++activityCalls === 1
      ? [activityEntry("Initial evidence")]
      : [activityEntry("Initial evidence"), activityEntry("New evidence", "0191b7f1-7f2c-7c13-9a61-2f29f2be1004")] });
    throw new Error("Unexpected management request");
  });
  renderApp(activityPath);
  expect(await screen.findByText("Initial evidence")).toBeInTheDocument();
  now = Date.parse("2026-09-04T10:01:00Z");
  fireEvent.click(screen.getByRole("button", { name: "Refresh activity" }));
  expect(await screen.findByText("New evidence")).toBeInTheDocument();
  expect(activityCalls).toBe(2);
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("GetProxy"))).toHaveLength(1);
  expect(receivedTime("Activity")).toHaveAttribute("datetime", "2026-09-04T10:01:00.000Z");
  expect(receivedTime("Proxy")).toHaveAttribute("datetime", "2026-09-04T10:00:00.000Z");
  const requests = fetch.mock.calls.filter(([url]) => String(url).endsWith("ListProxyActivity"));
  expect(requests[1][1]?.body).toBe(requests[0][1]?.body);
  for (const [, init] of requests) {
    // Generated ProtoJSON omits the default empty page token.
    expect(JSON.parse(String(init?.body))).toEqual({ workspaceId: "acme", namespaceId: "prod", proxyId: exampleProxy.proxyId, pageSize: 25 });
    expect(init?.signal).toBeDefined();
  }
});

test("failed activity refresh retains stale evidence and proxy refresh cannot advance its timestamp", async () => {
  let now = Date.parse("2026-09-04T10:00:00Z");
  vi.spyOn(Date, "now").mockImplementation(() => now);
  let activityCalls = 0;
  const fetch = transport(url => {
    if (url.endsWith("GetProxy")) return jsonResponse({ proxy: activityProxy });
    if (url.endsWith("ListProxyActivity")) return ++activityCalls === 1
      ? jsonResponse({ activity: [activityEntry("Retained evidence")] }) : new Response(null, { status: 503 });
    throw new Error("Unexpected management request");
  });
  renderApp(activityPath);
  expect(await screen.findByText("Retained evidence")).toBeInTheDocument();
  now = Date.parse("2026-09-04T10:01:00Z");
  fireEvent.click(screen.getByRole("button", { name: "Refresh activity" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/Stale activity.*Refresh failed/);
  expect(screen.getByText("Retained evidence")).toBeInTheDocument();
  expect(receivedTime("Activity")).toHaveAttribute("datetime", "2026-09-04T10:00:00.000Z");
  now = Date.parse("2026-09-04T10:02:00Z");
  fireEvent.click(screen.getByRole("button", { name: "Refresh proxy" }));
  await waitFor(() => expect(receivedTime("Proxy")).toHaveAttribute("datetime", "2026-09-04T10:02:00.000Z"));
  expect(receivedTime("Activity")).toHaveAttribute("datetime", "2026-09-04T10:00:00.000Z");
  expect(screen.getByRole("alert")).toHaveTextContent(/Stale activity/);
  expect(screen.getByText("Retained evidence")).toBeInTheDocument();
  expect(activityCalls).toBe(2);
  expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("GetProxy"))).toHaveLength(2);
});

test("activity refetch failure does not discard cached records even without a button trigger", async () => {
  let activityCalls = 0;
  transport(url => url.endsWith("GetProxy") ? jsonResponse({ proxy: activityProxy })
    : ++activityCalls === 1 ? jsonResponse({ activity: [activityEntry("Cached activity")] }) : new Response(null, { status: 503 }));
  const { client } = renderApp(activityPath);
  expect(await screen.findByText("Cached activity")).toBeInTheDocument();
  // Exercise real query refetch independently of the new control, proving the
  // retained-data rendering regression itself rather than just its button label.
  await act(async () => { await client.refetchQueries({ predicate: query => query.queryKey.includes("activity") }); });
  expect(await screen.findByRole("alert")).toHaveTextContent(/Stale activity/);
  expect(screen.getByText("Cached activity")).toBeInTheDocument();
});

test("activity scope switch cancels old work and retains generation-bearing keys", async () => {
  let deliver!: (response: Response) => void;
  const pending = new Promise<Response>(resolve => { deliver = resolve; });
  const fetch = transport((url, init) => {
    const input = JSON.parse(String(init.body));
    if (url.endsWith("GetProxy")) return jsonResponse({ proxy: { ...activityProxy, namespaceId: input.namespaceId } });
    if (url.endsWith("ListProxyActivity")) return input.namespaceId === "prod" ? pending
      : jsonResponse({ activity: [activityEntry("Current scope evidence")] });
    throw new Error("Unexpected management request");
  });
  const { client } = renderApp(activityPath);
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url).endsWith("ListProxyActivity"))).toBe(true));
  const oldRequest = fetch.mock.calls.find(([url]) => String(url).endsWith("ListProxyActivity"))!;
  const oldKey = client.getQueryCache().getAll().find(query => query.queryKey.includes("activity"))!.queryKey;
  expect(oldKey.slice(0, 4)).toEqual(["mcp", testSession.subject, "acme", "prod"]);
  expect(oldKey.slice(5)).toEqual(["activity", exampleProxy.proxyId, revisionId, ""]);
  fireEvent.change(screen.getByRole("combobox", { name: "Workspace and namespace" }), { target: { value: "acme/dev" } });
  expect(await screen.findByText("Current scope evidence")).toBeInTheDocument();
  expect(oldRequest[1]?.signal?.aborted).toBe(true);
  const newKey = client.getQueryCache().getAll().find(query => query.queryKey.includes("activity"))!.queryKey;
  expect(newKey.slice(0, 4)).toEqual(["mcp", testSession.subject, "acme", "dev"]);
  expect(newKey[4]).toBeGreaterThan(oldKey[4] as number);
  expect(newKey.slice(5)).toEqual(oldKey.slice(5));
  await act(async () => deliver(jsonResponse({ activity: [activityEntry("Old scope evidence")] })));
  expect(screen.queryByText("Old scope evidence")).not.toBeInTheDocument();
});

test("responsive navigation retains explicit accessible names when label spans are hidden", async () => {
  transport(() => jsonResponse({ proxies: [exampleProxy] }));
  renderApp();
  expect(await screen.findByText(exampleProxy.displayName)).toBeInTheDocument();
  const sidebar = screen.getByRole("complementary", { name: "Primary navigation" });
  // JSDOM does not apply media-query layout. Reproduce the incumbent responsive
  // display:none label state directly, without pretending this is a browser run.
  sidebar.querySelectorAll<HTMLElement>(".side-link span").forEach(span => { span.style.display = "none"; });
  for (const label of ["Overview", "Agent groups", "MCP proxies", "Event stream", "Findings", "Evidence vault", "Retention", "Deployment", "Settings"]) {
    const link = within(sidebar).getByRole("link", { name: label });
    expect(link).toHaveAttribute("aria-label", label);
    expect(link.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  }
});

test("direct root entry replaces its history entry with canonical inventory and selects only MCP navigation", async () => {
  const fetch = transport(url => {
    if (url.endsWith("ListProxies")) return jsonResponse({ proxies: [exampleProxy] });
    throw new Error("Unexpected management request");
  });
  const { router } = renderApp("/");
  expect(await screen.findByText(exampleProxy.displayName)).toBeInTheDocument();
  expect(router.state.location.pathname).toBe("/mcp-proxies");
  expect(router.history.location.pathname).toBe("/mcp-proxies");
  expect(router.history.length).toBe(1);
  const sidebar = within(screen.getByRole("complementary", { name: "Primary navigation" }));
  const inventory = sidebar.getByRole("link", { name: "MCP proxies" });
  const overview = sidebar.getByRole("link", { name: "Overview" });
  expect(inventory).toHaveAttribute("href", "/mcp-proxies");
  expect(inventory).toHaveAttribute("aria-current", "page");
  expect(inventory).toHaveClass("current");
  expect(overview).toHaveAttribute("href", "/");
  expect(overview).not.toHaveAttribute("aria-current");
  expect(overview).not.toHaveClass("current");
  const requests = fetch.mock.calls.filter(([url]) => String(url).endsWith("ListProxies"));
  expect(requests).toHaveLength(1);
  expect(JSON.parse(String(requests[0][1]?.body))).toEqual({ workspaceId: "acme", namespaceId: "prod", pageSize: 25 });
});
