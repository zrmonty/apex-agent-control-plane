import { afterEach, describe, expect, test, vi } from "vitest";
import { ApiError, type ClientErrorCode } from "./client";
import { getSession, logoutSession, type OperatorSession } from "./session";

// Public deterministic 32-byte fixture, shared with the Rust security tests.
const csrfToken = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const canary = "provider-secret-canary";
const limit = 128 * 1024;
const encoder = new TextEncoder();
function validSession(): OperatorSession {
  return {
    subject: "operator:keycloak:alice",
    scopes: [{ workspaceId: "acme", namespaceId: "prod" }],
    csrfToken,
    capabilities: { runtimeReadiness: "unknown", approvals: false, traces: false },
  };
}
function json(value: unknown): Response {
  return wire(JSON.stringify(value));
}
function wire(body: BodyInit | null, contentType: string | null = "application/json"): Response {
  return new Response(body, { headers: contentType === null ? {} : { "content-type": contentType } });
}
function fetchReply(reply: Response | Promise<Response>) {
  const transport = vi.fn<typeof globalThis.fetch>().mockImplementation(() => Promise.resolve(reply));
  vi.stubGlobal("fetch", transport);
  return transport;
}
function options(transport: ReturnType<typeof fetchReply>): RequestInit {
  const init = transport.mock.calls[0]?.[1];
  if (!init) throw new Error("Expected a dispatched HTTP request");
  return init;
}
async function safeError(outcome: Promise<unknown>, code: ClientErrorCode): Promise<void> {
  const error: unknown = await outcome.catch((reason: unknown) => reason);
  expect(error).toBeInstanceOf(ApiError);
  if (!(error instanceof ApiError)) throw new Error("Expected a sanitized ApiError");
  expect(error.code).toBe(code);
  expect(error.message).toBe(code);
  expect(error.cause).toBeUndefined();
  expect(`${String(error)} ${JSON.stringify(error)}`).not.toContain(canary);
  expect(`${String(error)} ${JSON.stringify(error)}`).not.toContain(csrfToken);
}
function chunks(...parts: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (const part of parts) controller.enqueue(part);
      controller.close();
    },
  });
}
function stalledBody() {
  let started!: () => void;
  let cancelled = false;
  const reading = new Promise<void>(resolve => { started = resolve; });
  const body = new ReadableStream<Uint8Array>({
    pull() { started(); },
    cancel() { cancelled = true; },
  }, { highWaterMark: 0 });
  return { response: wire(body), reading, wasCancelled: () => cancelled };
}
afterEach(() => vi.useRealTimers());

describe("getSession", () => {
  test("reads the exact server session through a single same-origin GET", async () => {
    const transport = fetchReply(json(validSession()));
    const session = await getSession();
    expect(session).toEqual(validSession());
    expect(transport).toHaveBeenCalledOnce();
    expect(transport.mock.calls[0][0]).toBe("/api/session");
    const init = options(transport);
    expect(init).toMatchObject({ method: "GET", credentials: "same-origin", mode: "same-origin",
      cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
    expect(init.body).toBeUndefined();
    expect(init.signal).toBeDefined();
    const headers = new Headers(init.headers);
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("x-apex-csrf")).toBeNull();
  });

  test("freezes every returned identity and nested value", async () => {
    fetchReply(json(validSession()));
    const session = await getSession();
    if (!session) throw new Error("Expected the authorized session");
    for (const value of [session, session.scopes, ...session.scopes, session.capabilities]) {
      expect(Object.isFrozen(value)).toBe(true);
    }
    expect(Reflect.set(session, "subject", "operator:keycloak:other")).toBe(false);
    expect(Reflect.set(session.scopes[0], "namespaceId", "other")).toBe(false);
    expect(Reflect.set(session.capabilities, "approvals", true)).toBe(false);
    expect(session).toEqual(validSession());
  });

  test("keeps independent request identities and does not cache sessions", async () => {
    const transport = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(json(validSession())).mockResolvedValueOnce(json(validSession()));
    vi.stubGlobal("fetch", transport);
    const first = await getSession();
    const second = await getSession();
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
    expect(transport).toHaveBeenCalledTimes(2);
  });

  test("allows empty authorized scopes without inventing access", async () => {
    fetchReply(json({ ...validSession(), scopes: [] }));
    expect((await getSession())?.scopes).toEqual([]);
  });

  test("preserves capability booleans as display data with unknown runtime readiness", async () => {
    const capabilities = { runtimeReadiness: "unknown", approvals: true, traces: true };
    fetchReply(json({ ...validSession(), scopes: [], capabilities }));
    expect(await getSession()).toEqual({ ...validSession(), scopes: [], capabilities });
  });

  test("accepts exact subject and scope length and count boundaries", async () => {
    const scopes = Array.from({ length: 256 }, (_, i) => ({
      workspaceId: "w".repeat(256), namespaceId: `ns${i}.A_z:-`,
    }));
    scopes[0] = { workspaceId: "w".repeat(256), namespaceId: "n".repeat(256) };
    const expected = { ...validSession(), subject: `operator:keycloak:${"s".repeat(494)}`, scopes };
    fetchReply(json(expected));
    expect(await getSession()).toEqual(expected);
  });

  test("does not confuse distinct scope pairs containing colons", async () => {
    const scopes = [{ workspaceId: "a:b", namespaceId: "c" }, { workspaceId: "a", namespaceId: "b:c" }];
    fetchReply(json({ ...validSession(), scopes }));
    expect((await getSession())?.scopes).toEqual(scopes);
  });

  test.each([csrfToken, "A".repeat(43), `${"-_".repeat(21)}8`])(
    "accepts canonical base64url CSRF fixture (%#)", async token => {
      fetchReply(json({ ...validSession(), csrfToken: token }));
      expect((await getSession())?.csrfToken).toBe(token);
    },
  );

  test("HTTP 401 means absent authority and never reads its body", async () => {
    let reads = 0;
    const body = new ReadableStream<Uint8Array>({ pull() { reads++; } }, { highWaterMark: 0 });
    const transport = fetchReply(new Response(body, { status: 401 }));
    await expect(getSession()).resolves.toBeUndefined();
    expect(reads).toBe(0);
    expect(transport).toHaveBeenCalledOnce();
  });

  test.each(["null", "[]", "true", "42", '"session"', "{}", '{"subject":', "<html>private</html>"])(
    "rejects a malformed or incomplete object (%#)", async body => {
      fetchReply(wire(body));
      await safeError(getSession(), "invalid-response");
    },
  );

  test.each(["subject", "scopes", "csrfToken", "capabilities"])("requires %s", async field => {
    const value: Record<string, unknown> = { ...validSession() };
    delete value[field];
    fetchReply(json(value));
    await safeError(getSession(), "invalid-response");
  });

  test.each(["accessToken", "refresh_token", "idToken", "token", "unexpected", "__proto__"])(
    "rejects unexpected top-level fields (%#)", async field => {
      fetchReply(json({ ...validSession(), [field]: canary }));
      await safeError(getSession(), "invalid-response");
    },
  );

  test.each([null, 1, "", "alice", "operator:keycloak:", "operator:keycloak:alice\n",
    "operator:keycloak:a\u0000b", "operator:keycloak:a\u007fb", "operator:keycloak:é",
    `operator:keycloak:${"s".repeat(495)}`])("rejects invalid subject (%#)", async subject => {
    fetchReply(json({ ...validSession(), subject }));
    await safeError(getSession(), "invalid-response");
  });

  test.each([null, 32, "", "a".repeat(42), "A".repeat(44), `${csrfToken}=`, ` ${csrfToken}`,
    `${"A".repeat(42)}+`, `${"A".repeat(42)}/`, `${"A".repeat(42)}B`, `${"A".repeat(42)}C`,
    `${"A".repeat(42)}D`, `${csrfToken}\n`])("rejects invalid or noncanonical CSRF (%#)", async token => {
    fetchReply(json({ ...validSession(), csrfToken: token }));
    await safeError(getSession(), "invalid-response");
  });

  test.each([null, {}, "acme/prod", [null], [[]], [{}], [{ workspaceId: "acme" }],
    [{ namespaceId: "prod" }], [{ workspaceId: "acme", namespaceId: "prod", token: canary }],
    [validSession().scopes[0], validSession().scopes[0]],
    Array.from({ length: 257 }, (_, i) => ({ workspaceId: "acme", namespaceId: `ns${i}` })),
  ].map(scopes => ({ scopes })))("rejects invalid, duplicate, excessive or extended scopes (%#)", async ({ scopes }) => {
    fetchReply(json({ ...validSession(), scopes }));
    await safeError(getSession(), "invalid-response");
  });

  for (const field of ["workspaceId", "namespaceId"] as const) {
    test.each([null, 1, "", "n".repeat(257), "*", "a b", "a/b", "a\\b", "..", "a..b", "%2f",
      "n\t", "n\n", "n\u0000", "n\u007f", "é"])(`rejects invalid ${field} (%#)`, async value => {
      fetchReply(json({ ...validSession(), scopes: [{ ...validSession().scopes[0], [field]: value }] }));
      await safeError(getSession(), "invalid-response");
    });
  }

  test.each([null, [], {}, { runtimeReadiness: "unknown", approvals: false },
    { approvals: false, traces: false },
    { ...validSession().capabilities, runtimeReadiness: "ready" },
    { ...validSession().capabilities, runtimeReadiness: "new-server-state" },
    { ...validSession().capabilities, approvals: "false" },
    { ...validSession().capabilities, traces: 0 },
    { ...validSession().capabilities, token: canary },
  ].map(capabilities => ({ capabilities })))("rejects invalid, unknown or extended capabilities (%#)", async ({ capabilities }) => {
    fetchReply(json({ ...validSession(), capabilities }));
    await safeError(getSession(), "invalid-response");
  });

  test.each([null, "text/html", "text/json", "application/problem+json", "application/jsonp",
    "application/json, text/html", "application/json; charset=iso-8859-1"])(
    "rejects absent or incorrect JSON media type (%#)", async contentType => {
      fetchReply(wire(encoder.encode(JSON.stringify(validSession())), contentType));
      await safeError(getSession(), "invalid-response");
    },
  );

  test("accepts explicit UTF-8 JSON and streamed chunk boundaries", async () => {
    const bytes = encoder.encode(JSON.stringify(validSession()));
    fetchReply(wire(chunks(bytes.slice(0, 17), bytes.slice(17, 41), bytes.slice(41)),
      "Application/JSON; charset=utf-8"));
    expect(await getSession()).toEqual(validSession());
  });

  test.each([[0xc3, 0x28], [0xff], [0xe2, 0x82]].map(bytes => ({ bytes })))("rejects malformed or truncated UTF-8 (%#)", async ({ bytes }) => {
    fetchReply(wire(chunks(encoder.encode(JSON.stringify(validSession())), new Uint8Array(bytes))));
    await safeError(getSession(), "invalid-response");
  });

  test("rejects a missing response body", async () => {
    fetchReply(wire(null));
    await safeError(getSession(), "invalid-response");
  });

  test("accepts exactly 128 KiB including JSON whitespace", async () => {
    const body = JSON.stringify(validSession()).padEnd(limit, " ");
    fetchReply(wire(chunks(encoder.encode(body.slice(0, 300)), encoder.encode(body.slice(300)))));
    expect(await getSession()).toEqual(validSession());
  });

  test.each([undefined, "1"])("bounds actual streamed bytes despite Content-Length (%#)", async length => {
    let cancelled = false;
    let reads = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        reads++;
        controller.enqueue(encoder.encode(reads === 1 ? JSON.stringify(validSession()).padEnd(limit, " ") : " "));
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    const response = wire(body);
    if (length) response.headers.set("content-length", length);
    fetchReply(response);
    await safeError(getSession(), "invalid-response");
    expect(reads).toBe(2);
    expect(cancelled).toBe(true);
  });

  test("rejects excessive declared length without waiting for body bytes", async () => {
    const body = stalledBody();
    body.response.headers.set("content-length", String(limit + 1));
    fetchReply(body.response);
    await safeError(getSession(), "invalid-response");
  });

  test("sanitizes a failed response stream", async () => {
    const body = new ReadableStream<Uint8Array>({ start(controller) { controller.error(new Error(canary)); } });
    fetchReply(wire(body));
    await safeError(getSession(), "invalid-response");
  });
});

describe("logoutSession", () => {
  test.each([204, 401])("only HTTP %i acknowledges closed local authority", async status => {
    const transport = fetchReply(new Response(null, { status }));
    await expect(logoutSession(validSession())).resolves.toBeUndefined();
    expect(transport).toHaveBeenCalledOnce();
    expect(transport.mock.calls[0][0]).toBe("/auth/logout");
    const init = options(transport);
    expect(init).toMatchObject({ method: "POST", credentials: "same-origin", mode: "same-origin",
      cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
    expect(init.body).toBeUndefined();
    const headers = new Headers(init.headers);
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("x-apex-csrf")).toBe(csrfToken);
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("cookie")).toBeNull();
  });

  test("uses the supplied in-memory proof rather than a previously fetched session", async () => {
    const transport = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(json(validSession())).mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", transport);
    await getSession();
    await logoutSession({ ...validSession(), csrfToken: "A".repeat(43) });
    expect(new Headers(transport.mock.calls[1][1]?.headers).get("x-apex-csrf")).toBe("A".repeat(43));
  });

  test.each(["", `${csrfToken}=`, `${"A".repeat(42)}B`, `${csrfToken}\r\nx-injected: value`])(
    "rejects a malformed supplied CSRF proof before dispatch (%#)", async token => {
      const transport = fetchReply(new Response(null, { status: 204 }));
      await safeError(logoutSession({ ...validSession(), csrfToken: token }), "invalid-request");
      expect(transport).not.toHaveBeenCalled();
    },
  );
});

const requests = [
  { name: "session read", run: (signal?: AbortSignal) => getSession(signal), statuses: [201, 202, 204, 205, 302] },
  { name: "logout", run: (signal?: AbortSignal) => logoutSession(validSession(), signal), statuses: [200, 201, 202, 205, 302] },
];
for (const { name, run, statuses } of requests) {
  describe(`${name} transport`, () => {
    test.each(statuses)("does not treat unexpected HTTP %i as success", async status => {
      fetchReply(new Response(null, { status }));
      await safeError(run(), "unavailable");
    });

    test.each([[400, "invalid-request"], [403, "forbidden"], [409, "conflict"], [413, "invalid-request"],
      [429, "rate-limited"], [500, "unavailable"], [503, "unavailable"]] as const)(
      "maps HTTP %i to a safe error without reading body or retrying", async (status, code) => {
        let reads = 0;
        const body = new ReadableStream<Uint8Array>({ pull() { reads++; } }, { highWaterMark: 0 });
        const transport = fetchReply(new Response(body, { status, headers: { "x-provider-detail": canary } }));
        await safeError(run(), code);
        expect(reads).toBe(0);
        expect(transport).toHaveBeenCalledOnce();
      },
    );

    test("sanitizes fetch failure without retrying", async () => {
      const transport = vi.fn<typeof globalThis.fetch>().mockRejectedValue(new TypeError(canary));
      vi.stubGlobal("fetch", transport);
      await safeError(run(), "unavailable");
      expect(transport).toHaveBeenCalledOnce();
    });

    test("rejects an already aborted caller before dispatch", async () => {
      const transport = fetchReply(json(validSession()));
      const caller = new AbortController();
      caller.abort(canary);
      await safeError(run(caller.signal), "cancelled");
      expect(transport).not.toHaveBeenCalled();
    });

    test("caller cancellation settles a stalled fetch and aborts its transport", async () => {
      const transport = fetchReply(new Promise<Response>(() => {}));
      const caller = new AbortController();
      const outcome = run(caller.signal).catch((error: unknown) => error);
      caller.abort(canary);
      await safeError(outcome, "cancelled");
      expect(options(transport).signal?.aborted).toBe(true);
      expect(transport).toHaveBeenCalledOnce();
    });

    test("45 seconds bounds a stalled fetch, releases timers and never retries", async () => {
      vi.useFakeTimers();
      const transport = fetchReply(new Promise<Response>(() => {}));
      const outcome = run().catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(45_000);
      await safeError(outcome, "unavailable");
      expect(options(transport).signal?.aborted).toBe(true);
      expect(transport).toHaveBeenCalledOnce();
      expect(vi.getTimerCount()).toBe(0);
    });
  });
}

test("caller cancellation also settles and cancels a stalled session body", async () => {
  const body = stalledBody();
  const transport = fetchReply(body.response);
  const caller = new AbortController();
  const outcome = getSession(caller.signal).catch((error: unknown) => error);
  await Promise.race([body.reading, outcome]);
  caller.abort(canary);
  await safeError(outcome, "cancelled");
  expect(body.wasCancelled()).toBe(true);
  expect(options(transport).signal?.aborted).toBe(true);
});

test("the whole-request deadline includes a stalled session body", async () => {
  vi.useFakeTimers();
  const body = stalledBody();
  const transport = fetchReply(body.response);
  const outcome = getSession().catch((error: unknown) => error);
  await Promise.race([body.reading, outcome]);
  await vi.advanceTimersByTimeAsync(45_000);
  await safeError(outcome, "unavailable");
  expect(body.wasCancelled()).toBe(true);
  expect(options(transport).signal?.aborted).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});

test("reading the body does not restart a deadline already spent awaiting headers", async () => {
  vi.useFakeTimers();
  let deliver!: (response: Response) => void;
  const body = stalledBody();
  fetchReply(new Promise<Response>(resolve => { deliver = resolve; }));
  const outcome = getSession().catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(44_000);
  deliver(body.response);
  await vi.advanceTimersByTimeAsync(1_000);
  await safeError(outcome, "unavailable");
  expect(body.wasCancelled()).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
});

test.each(["read", "logout"])("successful %s releases its deadline timer", async kind => {
  vi.useFakeTimers();
  fetchReply(kind === "read" ? json(validSession()) : new Response(null, { status: 204 }));
  if (kind === "read") await getSession();
  else await logoutSession(validSession());
  expect(vi.getTimerCount()).toBe(0);
});

const lateResponses = [
  { name: "session success", run: getSession, status: 200 },
  { name: "session 401", run: getSession, status: 401 },
  { name: "logout success", run: (signal?: AbortSignal) => logoutSession(validSession(), signal), status: 204 },
  { name: "logout 401", run: (signal?: AbortSignal) => logoutSession(validSession(), signal), status: 401 },
];
for (const { name, run, status } of lateResponses) {
  test.each(["cancelled", "unavailable"] as const)(`late response: ${name} cannot override %s`, async code => {
    vi.useFakeTimers();
    const caller = new AbortController();
    let deliver!: (response: Response) => void;
    const transport = fetchReply(new Promise<Response>(resolve => { deliver = resolve; }));
    const outcome = run(caller.signal).catch((error: unknown) => error);
    if (code === "cancelled") caller.abort(canary);
    else await vi.advanceTimersByTimeAsync(45_000);
    let reads = 0;
    let cancelled = false;
    const body = status === 204 ? null : new ReadableStream<Uint8Array>({
      pull() { reads++; },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    deliver(new Response(body, { status, headers: { "content-type": "application/json" } }));
    await safeError(outcome, code);
    expect(reads).toBe(0);
    if (body) expect(cancelled).toBe(true);
    expect(options(transport).signal?.aborted).toBe(true);
    expect(transport).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  test(`late response: ${name} cannot win an elapsed deadline before its timer fires`, async () => {
    // Advance only the monotonic clock: the real timeout callback has not run.
    vi.useFakeTimers({ toFake: ["performance"] });
    let deliver!: (response: Response) => void;
    const transport = fetchReply(new Promise<Response>(resolve => { deliver = resolve; }));
    const outcome = run().catch((error: unknown) => error);
    vi.advanceTimersByTime(45_000);
    deliver(new Response(status === 200 ? JSON.stringify(validSession()) : null, {
      status, headers: { "content-type": "application/json" },
    }));
    await safeError(outcome, "unavailable");
    expect(options(transport).signal?.aborted).toBe(true);
  });
}
