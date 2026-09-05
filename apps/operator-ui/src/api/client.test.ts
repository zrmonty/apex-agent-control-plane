import { afterEach, expect, test, vi } from "vitest";
import { McpProxyService } from "@apex/contracts";
import { ApiError, createManagementClient, type SessionProof } from "./client";

const list = McpProxyService.method.listProxies;
const scope = { workspaceId: "acme", namespaceId: "prod" };
const session = { subject: "operator:keycloak:alice", csrfToken: "a".repeat(43) };
const key = "0198beae-a521-78fb-940f-f1bb0aecc832";
const json = (body: string, status = 200) => new Response(body, {
  status, headers: { "content-type": "application/json" },
});
function harness() {
  let current: SessionProof | undefined = session;
  const unauthorized = vi.fn();
  const client = createManagementClient(() => current, unauthorized);
  return { client, unauthorized, set: (value: SessionProof | undefined) => { current = value; } };
}
function fetchReply(reply: Response | Promise<Response>) {
  const fetch = vi.fn().mockImplementation(() => reply);
  vi.stubGlobal("fetch", fetch);
  return fetch;
}
afterEach(() => vi.useRealTimers());

test("generated list reaches only the same-origin Rust allowlist with opaque cookies and CSRF", async () => {
  const fetch = fetchReply(json('{"proxies":[],"nextPageToken":"next-page"}'));
  const result = await harness().client.call(list, { ...scope, pageSize: 25 });
  expect(result.proxies).toEqual([]);
  expect(result.nextPageToken).toBe("next-page");
  expect(fetch).toHaveBeenCalledOnce();
  const [url, options] = fetch.mock.calls[0];
  expect(url).toBe("/api/apex/v1/McpProxyService/ListProxies");
  expect(options).toMatchObject({ method: "POST", credentials: "same-origin", mode: "same-origin",
    cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  const headers = new Headers(options.headers);
  expect(headers.get("x-apex-csrf")).toBe(session.csrfToken);
  expect(headers.get("content-type")).toBe("application/json");
  expect(headers.get("authorization")).toBeNull();
  expect(headers.get("cookie")).toBeNull();
  expect(JSON.parse(options.body)).toEqual({ ...scope, pageSize: 25 });
});

test("trace microseconds beyond JS safe integers survive generated decoding as bigint", async () => {
  fetchReply(json('{"trace":{"callId":"call-1","stages":[{"name":"auth","startedAtUnixUs":"9007199254740993","durationUs":"7","durationNs":"7999","clockResolutionNs":"100"}]}}'));
  const result = await harness().client.call(McpProxyService.method.getProxyTrace,
    { scope: { ...scope, proxyId: "research" }, callId: "call-1" });
  expect(result.trace?.stages[0].startedAtUnixUs).toBe(9007199254740993n);
  expect(result.trace?.stages[0].durationUs).toBe(7n);
  expect(result.trace?.stages[0].durationNs).toBe(7999n);
  expect(result.trace?.stages[0].clockUncertaintyUs).toBeUndefined();
});

test("a retry retains the caller's UUIDv7 and never retries automatically", async () => {
  const fetch = vi.fn().mockRejectedValueOnce(new TypeError("offline canary"))
    .mockResolvedValueOnce(json('{"duplicate":true}'));
  vi.stubGlobal("fetch", fetch);
  const client = harness().client;
  const input = { ...scope, requestId: key, proxyId: "research", slug: "research", displayName: "Research" };
  await expect(client.call(McpProxyService.method.createProxy, input)).rejects.toMatchObject({ code: "unavailable" });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect((await client.call(McpProxyService.method.createProxy, input)).duplicate).toBe(true);
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(JSON.parse(fetch.mock.calls[0][1].body).requestId).toBe(key);
  expect(fetch.mock.calls[0][1].body).toBe(fetch.mock.calls[1][1].body);
});

test("absent session refuses management without contacting the API", async () => {
  const fetch = fetchReply(json('{}'));
  const h = harness(); h.set(undefined);
  await expect(h.client.call(list, scope)).rejects.toMatchObject({ code: "unauthenticated" });
  expect(fetch).not.toHaveBeenCalled();
});

test("caller-supplied method descriptors cannot choose a different endpoint", async () => {
  const fetch = fetchReply(json('{}'));
  await expect(harness().client.call({ ...list, name: "../../auth/logout" }, scope))
    .rejects.toMatchObject({ code: "invalid-request" });
  expect(fetch).not.toHaveBeenCalled();
});

test.each(["v4-id", "", "x".repeat(300_000)])("invalid or oversized mutation is refused locally (%#)", async requestId => {
  const fetch = fetchReply(json('{}'));
  await expect(harness().client.call(McpProxyService.method.createProxy, { ...scope, requestId }))
    .rejects.toMatchObject({ code: "invalid-request" });
  expect(fetch).not.toHaveBeenCalled();
});

test.each([
  '{"unknownSecret":"canary"}', '{"proxies":[],"proxies":[]}', '[]', '<html>canary</html>',
  '{"proxies":' , '{"nextPageToken":"' + "x".repeat(262_144) + '"}',
])("malformed, duplicate, unknown or oversized responses do not become inventory (%#)", async body => {
  fetchReply(json(body));
  await expect(harness().client.call(list, scope)).rejects.toMatchObject({ code: "invalid-response" });
});

test("JSON media type is required even for parseable response bytes", async () => {
  fetchReply(new Response('{}', { headers: { "content-type": "text/html" } }));
  await expect(harness().client.call(list, scope)).rejects.toMatchObject({ code: "invalid-response" });
});

test.each([[401, "unauthenticated"], [403, "forbidden"], [409, "conflict"], [429, "rate-limited"],
  [503, "unavailable"], [500, "unavailable"]] as const)("HTTP %i has a sanitized error", async (status, code) => {
  const body = vi.fn(() => { throw Error("error body must not be read"); });
  const response = json('{"message":"credential-canary"}', status);
  Object.defineProperty(response, "body", { get: body });
  fetchReply(response);
  const h = harness();
  const error = await h.client.call(list, scope).catch(error => error);
  expect(error).toBeInstanceOf(ApiError);
  expect(error).toMatchObject({ code });
  expect(String(error)).not.toContain("canary");
  expect(error.cause).toBeUndefined();
  expect(body).not.toHaveBeenCalled();
  expect(h.unauthorized).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
});

test.each([200, 401])("a late %i from a previous session cannot update or log out the new session", async status => {
  let resolve!: (reply: Response) => void;
  fetchReply(new Promise<Response>(done => { resolve = done; }));
  const h = harness();
  const result = h.client.call(list, scope);
  h.set({ ...session, subject: "operator:keycloak:bob" });
  resolve(json('{}', status));
  await expect(result).rejects.toMatchObject({ code: "session-changed" });
  expect(h.unauthorized).not.toHaveBeenCalled();
});

test("an aborted caller cannot dispatch a management request", async () => {
  const fetch = fetchReply(json('{}'));
  const controller = new AbortController(); controller.abort("sensitive reason");
  await expect(harness().client.call(list, scope, controller.signal)).rejects.toMatchObject({ code: "cancelled" });
  expect(fetch).not.toHaveBeenCalled();
});

test("the client bounds a stalled fetch and aborts its transport without retry", async () => {
  vi.useFakeTimers();
  const fetch = fetchReply(new Promise<Response>(() => {}));
  const outcome = harness().client.call(list, scope).catch(error => error);
  await vi.advanceTimersByTimeAsync(45_000);
  expect(await outcome).toMatchObject({ code: "unavailable" });
  expect(fetch).toHaveBeenCalledOnce();
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
});

const canary = "provider-credential-canary";
const encoder = new TextEncoder();
async function safeError(outcome: Promise<unknown>, code: string) {
  const error: unknown = await outcome.catch((reason: unknown) => reason);
  expect(error).toBeInstanceOf(ApiError);
  if (!(error instanceof ApiError)) throw new Error("Expected a sanitized ApiError");
  expect(error.code).toBe(code);
  expect(error.message).toBe(code);
  expect(error.cause).toBeUndefined();
  expect(`${String(error)} ${JSON.stringify(error)}`).not.toContain(canary);
}
function pendingBody(status = 200, onCancel = () => {}) {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let started!: () => void;
  let reads = 0;
  let cancelled = false;
  const reading = new Promise<void>(resolve => { started = resolve; });
  const body = new ReadableStream<Uint8Array>({
    start(value) { controller = value; },
    pull() { reads++; started(); },
    cancel() { cancelled = true; onCancel(); },
  }, { highWaterMark: 0 });
  const response = new Response(body, { status, headers: { "content-type": "application/json" } });
  return { response, controller, reading, reads: () => reads, cancelled: () => cancelled };
}

test.each(["cancelled", "unavailable"])("a stalled body is cancelled on %s and releases its reader", async code => {
  vi.useFakeTimers();
  const body = pendingBody();
  const fetch = fetchReply(body.response);
  const h = harness();
  const caller = new AbortController();
  const outcome = h.client.call(list, scope, caller.signal).catch((error: unknown) => error);
  await body.reading;
  if (code === "cancelled") caller.abort(canary);
  else await vi.advanceTimersByTimeAsync(45_000);
  await safeError(outcome, code);
  expect(body.cancelled()).toBe(true);
  expect(body.response.body?.locked).toBe(false);
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
  expect(fetch).toHaveBeenCalledOnce();
  expect(h.unauthorized).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

test("the body only has the remaining whole-request budget after delayed headers", async () => {
  vi.useFakeTimers();
  let deliver!: (response: Response) => void;
  const body = pendingBody();
  fetchReply(new Promise<Response>(resolve => { deliver = resolve; }));
  const outcome = harness().client.call(list, scope).catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(44_000);
  deliver(body.response);
  await vi.advanceTimersByTimeAsync(1_000);
  await safeError(outcome, "unavailable");
  expect(body.cancelled()).toBe(true);
  expect(body.response.body?.locked).toBe(false);
  expect(vi.getTimerCount()).toBe(0);
});

test("a replaced identity stops streaming before another chunk can become inventory", async () => {
  vi.useFakeTimers();
  const body = pendingBody();
  fetchReply(body.response);
  const h = harness();
  const outcome = h.client.call(list, scope).catch((error: unknown) => error);
  await body.reading;
  h.set({ ...session }); // Same subject and CSRF, different generation identity.
  body.controller.enqueue(encoder.encode('{"proxies":'));
  await vi.advanceTimersByTimeAsync(45_000);
  await safeError(outcome, "session-changed");
  expect(body.cancelled()).toBe(true);
  expect(body.reads()).toBe(1);
  expect(h.unauthorized).not.toHaveBeenCalled();
});

for (const status of [200, 401]) {
  test.each(["cancelled", "unavailable", "session-changed"])(`late HTTP ${status} is discarded after %s`, async code => {
    vi.useFakeTimers();
    let deliver!: (response: Response) => void;
    const fetch = fetchReply(new Promise<Response>(resolve => { deliver = resolve; }));
    const h = harness();
    const caller = new AbortController();
    const outcome = h.client.call(list, scope, caller.signal).catch((error: unknown) => error);
    if (code === "cancelled") caller.abort(canary);
    else if (code === "unavailable") await vi.advanceTimersByTimeAsync(45_000);
    else h.set({ ...session });
    const body = pendingBody(status);
    deliver(body.response);
    await safeError(outcome, code);
    expect(body.reads()).toBe(0);
    expect(body.cancelled()).toBe(true);
    expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
    expect(h.unauthorized).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  test(`late HTTP ${status} cannot beat an elapsed deadline whose timer has not fired`, async () => {
    vi.useFakeTimers({ toFake: ["performance"] });
    let deliver!: (response: Response) => void;
    fetchReply(new Promise<Response>(resolve => { deliver = resolve; }));
    const h = harness();
    const outcome = h.client.call(list, scope).catch((error: unknown) => error);
    vi.advanceTimersByTime(45_000);
    const body = pendingBody(status);
    deliver(body.response);
    await safeError(outcome, "unavailable");
    expect(body.cancelled()).toBe(true);
    expect(body.reads()).toBe(0);
    expect(h.unauthorized).not.toHaveBeenCalled();
  });
}

test.each(["cancelled", "unavailable", "session-changed"])("a queued %s after body completion fences final delivery", async code => {
  vi.useFakeTimers({ toFake: ["performance"] });
  const response = json('{"proxies":[],"nextPageToken":"page-2"}');
  fetchReply(response);
  const caller = new AbortController();
  let current: SessionProof = session;
  let queued = false;
  const client = createManagementClient(() => {
    // At the public authority boundary, queue a user/session event after the
    // body completes. It runs before the awaiting caller receives the result.
    if (response.bodyUsed && !response.body?.locked && !queued) {
      queued = true;
      queueMicrotask(() => {
        if (code === "cancelled") caller.abort(canary);
        else if (code === "unavailable") vi.advanceTimersByTime(45_000);
        else current = { ...session };
      });
    }
    return current;
  }, () => { throw new Error("Success must not invalidate authority"); });
  await safeError(client.call(list, scope, caller.signal), code);
});

test.each(["cancelled", "unavailable", "session-changed"])("HTTP 401 cannot notify authority after cleanup triggers %s", async code => {
  vi.useFakeTimers({ toFake: ["performance"] });
  const h = harness();
  const caller = new AbortController();
  const body = pendingBody(401, () => {
    if (code === "cancelled") caller.abort(canary);
    else if (code === "unavailable") vi.advanceTimersByTime(45_000);
    else h.set({ ...session });
  });
  fetchReply(body.response);
  await safeError(h.client.call(list, scope, caller.signal), code);
  expect(h.unauthorized).not.toHaveBeenCalled();
  expect(body.cancelled()).toBe(true);
  expect(body.reads()).toBe(0);
});

test("a timely 401 may clear the supplied identity and still reports unauthenticated", async () => {
  let current: SessionProof | undefined = session;
  let notified: SessionProof | undefined;
  fetchReply(new Response(null, { status: 401 }));
  const client = createManagementClient(() => current, proof => { notified = proof; current = undefined; });
  await safeError(client.call(list, scope), "unauthenticated");
  expect(notified).toBe(session);
  expect(current).toBeUndefined();
});

test.each(["cancelled", "unavailable", "session-changed"])("encoding cannot dispatch a mutation after %s", async code => {
  vi.useFakeTimers({ toFake: ["performance"] });
  const h = harness();
  const caller = new AbortController();
  const fetch = fetchReply(json('{}'));
  const input = { ...scope, requestId: key, proxyId: "research", slug: "research",
    get displayName() {
      if (code === "cancelled") caller.abort(canary);
      else if (code === "unavailable") vi.advanceTimersByTime(45_000);
      else h.set({ ...session });
      return "Research";
    },
  };
  await safeError(h.client.call(McpProxyService.method.createProxy, input, caller.signal), code);
  expect(fetch).not.toHaveBeenCalled();
  expect(h.unauthorized).not.toHaveBeenCalled();
});

test.each([401, 403, 409, 429, 500, 503])("HTTP %i discards its native body without pulling error bytes", async status => {
  const body = pendingBody(status);
  fetchReply(body.response);
  const h = harness();
  await expect(h.client.call(list, scope)).rejects.toBeInstanceOf(ApiError);
  expect(body.reads()).toBe(0);
  expect(body.cancelled()).toBe(true);
  expect(h.unauthorized).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
});

test.each([null, "text/plain", "application/problem+json", "application/jsonp", "application/json, text/html",
  "application/json; charset=iso-8859-1", "application/json; charset=utf-16",
  "application/json; charset=utf-8; charset=utf-16", "application/json; arbitrary=value"])(
  "rejects non-JSON and unsupported JSON media parameters (%#)", async contentType => {
    vi.useFakeTimers();
    const body = pendingBody();
    if (contentType === null) body.response.headers.delete("content-type");
    else body.response.headers.set("content-type", contentType);
    fetchReply(body.response);
    // Unsupported media must fail before reading, even when the body stays open.
    body.controller.enqueue(encoder.encode('{"proxies":[]}'));
    const outcome = harness().client.call(list, scope).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(45_000);
    await safeError(outcome, "invalid-response");
    expect(body.cancelled()).toBe(true);
    expect(body.reads()).toBe(0);
  },
);

test.each(["application/json", "Application/JSON; charset=utf-8", 'application/json; charset="UTF-8"'])(
  "accepts only supported JSON media with split UTF-8 (%#)", async contentType => {
    const body = new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(encoder.encode('{"proxies":[],"nextPageToken":"page-'));
      controller.enqueue(new Uint8Array([0xc3]));
      controller.enqueue(new Uint8Array([0xa9]));
      controller.enqueue(encoder.encode('"}'));
      controller.close();
    } });
    fetchReply(new Response(body, { headers: { "content-type": contentType } }));
    expect((await harness().client.call(list, scope)).nextPageToken).toBe("page-é");
  },
);

test.each([[0xc3, 0x28], [0xff], [0xe2, 0x82]].map(bytes => ({ bytes })))(
  "fatal UTF-8 failure never replaces invalid bytes with a valid generated value (%#)", async ({ bytes }) => {
    let cancelled = false;
    const response = new Response(new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(encoder.encode('{"nextPageToken":"'));
      controller.enqueue(new Uint8Array(bytes));
      controller.enqueue(encoder.encode('"}'));
    }, cancel() { cancelled = true; } }), { headers: { "content-type": "application/json" } });
    fetchReply(response);
    await safeError(harness().client.call(list, scope), "invalid-response");
    expect(cancelled).toBe(true);
    expect(response.body?.locked).toBe(false);
  },
);

test("a body read failure is sanitized without retaining its provider cause", async () => {
  const body = pendingBody();
  fetchReply(body.response);
  const outcome = harness().client.call(list, scope).catch((error: unknown) => error);
  await body.reading;
  body.controller.error(new Error(canary));
  await safeError(outcome, "invalid-response");
  expect(body.response.body?.locked).toBe(false);
});

test("a fetch rejection cannot smuggle an ApiError instance or provider cause into the client", async () => {
  const error = new ApiError("forbidden");
  error.message = canary;
  error.cause = new Error(canary);
  const fetch = vi.fn<typeof globalThis.fetch>().mockRejectedValue(error);
  vi.stubGlobal("fetch", fetch);
  await safeError(harness().client.call(list, scope), "unavailable");
  expect(fetch).toHaveBeenCalledOnce();
});

test("exact descriptor object identity is required even for the same method name", async () => {
  const fetch = fetchReply(json('{}'));
  await safeError(harness().client.call({ ...list }, scope), "invalid-request");
  expect(fetch).not.toHaveBeenCalled();
});
