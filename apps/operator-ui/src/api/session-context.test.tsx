import { type ReactNode } from "react";
import { act, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { McpProxyService } from "@apex/contracts";
import { expect, test, vi } from "vitest";
import { SessionGate, SessionProvider, useOperatorSession } from "./session-context";

const csrfToken = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const first = { workspaceId: "acme", namespaceId: "prod" };
const second = { workspaceId: "acme", namespaceId: "dev" };
const session = (subject = "operator:keycloak:alice", scopes = [first, second]) => ({
  subject, scopes, csrfToken, capabilities: { runtimeReadiness: "unknown", approvals: false, traces: false },
});
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { "content-type": "application/json" },
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(deliver => { resolve = deliver; });
  return { promise, resolve };
}
function harness() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  function wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}><SessionProvider>{children}</SessionProvider></QueryClientProvider>;
  }
  return { queryClient, wrapper };
}
function transport() {
  const fetch = vi.fn<typeof globalThis.fetch>();
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
async function ready(result: { current: ReturnType<typeof useOperatorSession> }) {
  await waitFor(() => expect(result.current.phase).toBe("ready"));
}

test("session gate waits for the real BFF and never renders protected content anonymously", async () => {
  const pending = deferred<Response>();
  const fetch = transport().mockReturnValue(pending.promise);
  render(<SessionGate><p>Protected proxy inventory</p></SessionGate>, { wrapper: harness().wrapper });
  expect(screen.queryByText("Protected proxy inventory")).not.toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("Checking your session");
  await act(async () => pending.resolve(new Response(null, { status: 401 })));
  expect(await screen.findByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/auth/login");
  expect(screen.queryByText("Protected proxy inventory")).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledOnce();
});

test("scope and query identity come only from the validated server session", async () => {
  const fetch = transport().mockResolvedValue(json(session()));
  const { result } = renderHook(useOperatorSession, { wrapper: harness().wrapper });
  await ready(result);
  expect(result.current.scope).toEqual(first);
  expect(result.current.queryPrefix).toEqual(["mcp", session().subject, first.workspaceId, first.namespaceId, expect.any(Number)]);
  expect(fetch.mock.calls[0][0]).toBe("/api/session");
  expect(result.current.session?.capabilities.runtimeReadiness).toBe("unknown");
});

test("provider outage renders unavailable and an explicit retry, not sample authority", async () => {
  const fetch = transport().mockRejectedValueOnce(new TypeError("private-provider-error"))
    .mockResolvedValueOnce(json(session()));
  render(<SessionGate><p>Protected proxy inventory</p></SessionGate>, { wrapper: harness().wrapper });
  expect(await screen.findByRole("alert")).toHaveTextContent("Session unavailable");
  expect(screen.queryByText(/private-provider-error/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("Protected proxy inventory")).toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(2);
});

test("a valid login without grants displays no authorized scopes and cannot dispatch management", async () => {
  const fetch = transport().mockResolvedValue(json(session(undefined, [])));
  const { result } = renderHook(useOperatorSession, { wrapper: harness().wrapper });
  await ready(result);
  expect(result.current.scope).toBeUndefined();
  expect(result.current.queryPrefix).toBeUndefined();
  await expect(result.current.client.call(McpProxyService.method.listProxies, first)).rejects.toMatchObject({ code: "unauthenticated" });
  expect(fetch).toHaveBeenCalledOnce();
});

test("scope changes synchronously evict caches, use a new proof and reject an old response", async () => {
  const pending = deferred<Response>();
  transport().mockResolvedValueOnce(json(session())).mockReturnValueOnce(pending.promise);
  const { queryClient, wrapper } = harness();
  const { result } = renderHook(useOperatorSession, { wrapper });
  await ready(result);
  const oldPrefix = result.current.queryPrefix!;
  queryClient.setQueryData([...oldPrefix, "proxies"], { private: "old-scope-data" });
  queryClient.getMutationCache().build(queryClient, { mutationKey: [...oldPrefix, "create"] });
  const outcome = result.current.client.call(McpProxyService.method.listProxies, first).catch(error => error);
  act(() => result.current.selectScope(second));
  expect(result.current.scope).toEqual(second);
  expect(result.current.queryPrefix).not.toEqual(oldPrefix);
  expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  expect(queryClient.getMutationCache().getAll()).toHaveLength(0);
  pending.resolve(json({ proxies: [], nextPageToken: "old-secret-cursor" }));
  expect(await outcome).toMatchObject({ code: "session-changed" });
});

test("unknown scopes cannot be selected and choosing the same scope does not reset its cache", async () => {
  transport().mockResolvedValue(json(session()));
  const { queryClient, wrapper } = harness();
  const { result } = renderHook(useOperatorSession, { wrapper });
  await ready(result);
  const prefix = result.current.queryPrefix!;
  queryClient.setQueryData(prefix, "current");
  act(() => result.current.selectScope({ ...first }));
  expect(result.current.queryPrefix).toEqual(prefix);
  expect(queryClient.getQueryData(prefix)).toBe("current");
  expect(() => result.current.selectScope({ workspaceId: "ungranted", namespaceId: "prod" })).toThrow();
  expect(result.current.scope).toEqual(first);
});

test("late unauthorized response from an old scope cannot sign out the new context", async () => {
  const pending = deferred<Response>();
  transport().mockResolvedValueOnce(json(session())).mockReturnValueOnce(pending.promise);
  const { result } = renderHook(useOperatorSession, { wrapper: harness().wrapper });
  await ready(result);
  const outcome = result.current.client.call(McpProxyService.method.listProxies, first).catch(error => error);
  act(() => result.current.selectScope(second));
  await act(async () => pending.resolve(new Response(null, { status: 401 })));
  expect(await outcome).toMatchObject({ code: "session-changed" });
  expect(result.current.phase).toBe("ready");
  expect(result.current.scope).toEqual(second);
});

test("current unauthorized response removes authority and all prior cache state", async () => {
  transport().mockResolvedValueOnce(json(session())).mockResolvedValueOnce(new Response(null, { status: 401 }));
  const { queryClient, wrapper } = harness();
  const { result } = renderHook(useOperatorSession, { wrapper });
  await ready(result);
  queryClient.setQueryData(result.current.queryPrefix!, "private");
  await act(async () => {
    await expect(result.current.client.call(McpProxyService.method.listProxies, first)).rejects.toThrow();
  });
  expect(result.current.phase).toBe("anonymous");
  expect(result.current.session).toBeUndefined();
  expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
});

test("failed logout immediately disables management and clears cache but does not claim server sign-out", async () => {
  const fetch = transport().mockResolvedValueOnce(json(session()))
    .mockResolvedValueOnce(new Response(null, { status: 503 }))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const { queryClient, wrapper } = harness();
  const { result } = renderHook(useOperatorSession, { wrapper });
  await ready(result);
  queryClient.setQueryData(result.current.queryPrefix!, "private");
  await act(async () => result.current.logout());
  expect(result.current.phase).toBe("logout-unconfirmed");
  expect(result.current.session).toBeUndefined();
  expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  await expect(result.current.client.call(McpProxyService.method.listProxies, first)).rejects.toThrow();
  await act(async () => result.current.logout());
  expect(result.current.phase).toBe("anonymous");
  expect(fetch.mock.calls.slice(1).map(([url]) => url)).toEqual(["/auth/logout", "/auth/logout"]);
  expect(new Headers(fetch.mock.calls[2][1]?.headers).get("x-apex-csrf")).toBe(csrfToken);
});

test("overlapping session reloads reject late old authority even when fetch ignores abort", async () => {
  const old = deferred<Response>();
  const fetch = transport().mockReturnValueOnce(old.promise).mockResolvedValueOnce(json(session("operator:keycloak:bob")));
  const { result } = renderHook(useOperatorSession, { wrapper: harness().wrapper });
  await act(async () => result.current.reload());
  expect(result.current.session?.subject).toBe("operator:keycloak:bob");
  await act(async () => old.resolve(json(session())));
  expect(result.current.session?.subject).toBe("operator:keycloak:bob");
  expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(true);
});

test("StrictMode cleanup and remount leave one current session and cancel abandoned reads", async () => {
  const old = deferred<Response>();
  const fetch = transport().mockReturnValueOnce(old.promise).mockResolvedValueOnce(json(session()));
  // React 19 only replays effects when StrictMode is at the root, not nested
  // inside a testing-library wrapper. Use the real root option.
  const { result, unmount } = renderHook(useOperatorSession, { wrapper: harness().wrapper, reactStrictMode: true });
  await ready(result);
  expect(fetch.mock.calls[0][1]?.signal?.aborted).toBe(true);
  unmount();
  await act(async () => old.resolve(new Response(null, { status: 401 })));
  expect(fetch).toHaveBeenCalledTimes(2);
});

test.each(["scope", "subject"])("a delayed old mutation cannot adopt the next %s's authority", async transition => {
  const fetch = transport().mockResolvedValueOnce(json(session())).mockImplementation(async url =>
    url === "/api/session" ? json(session("operator:keycloak:bob")) : json({ proxies: [] }));
  const { queryClient, wrapper } = harness();
  const { result } = renderHook(useOperatorSession, { wrapper });
  await ready(result);
  const old = result.current;
  const entered = deferred<void>();
  const released = deferred<void>();
  const mutation = queryClient.getMutationCache().build(queryClient, {
    onMutate: async () => { entered.resolve(); await released.promise; },
    mutationFn: () => old.client.call(McpProxyService.method.listProxies, first),
  });
  const outcome = mutation.execute(undefined).catch(error => error);
  await entered.promise;
  if (transition === "scope") act(() => result.current.selectScope(second));
  else await act(async () => result.current.reload());
  const before = fetch.mock.calls.length;
  released.resolve();
  expect(await outcome).toMatchObject({ code: "session-changed" });
  expect(fetch).toHaveBeenCalledTimes(before);
  // The new generation is usable; fencing does not disable all clients.
  await expect(result.current.client.call(McpProxyService.method.listProxies, result.current.scope!)).resolves.toMatchObject({ proxies: [] });
  expect(fetch).toHaveBeenCalledTimes(before + 1);
});

test("a stale mutation rollback cannot repopulate the cleared cache", async () => {
  const reply = deferred<Response>();
  transport().mockResolvedValueOnce(json(session())).mockReturnValueOnce(reply.promise);
  const { queryClient, wrapper } = harness();
  const { result } = renderHook(useOperatorSession, { wrapper });
  await ready(result);
  const old = result.current;
  queryClient.setQueryData(old.queryPrefix!, "optimistic-private-record");
  const mutation = queryClient.getMutationCache().build(queryClient, {
    mutationFn: () => old.client.call(McpProxyService.method.listProxies, first),
    onError: () => { if (old.isCurrent()) queryClient.setQueryData(old.queryPrefix!, "old-rollback"); },
  });
  const outcome = mutation.execute(undefined).catch(error => error);
  // Let the real Query Core mutation dispatch before switching.
  await act(async () => { await Promise.resolve(); });
  act(() => result.current.selectScope(second));
  reply.resolve(new Response(null, { status: 503 }));
  expect(await outcome).toMatchObject({ code: "session-changed" });
  expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
  expect(old.isCurrent()).toBe(false);
  expect(result.current.isCurrent()).toBe(true);
});
