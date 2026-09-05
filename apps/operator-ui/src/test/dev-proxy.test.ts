// @vitest-environment node
import { Console } from "node:console";
import { createServer, request, type Server } from "node:http";
import { Writable } from "node:stream";
import { inspect } from "node:util";
import { createLogger, createServer as createViteServer, type Logger } from "vite";
import { expect, test, vi } from "vitest";
import { browserEdgeProxy } from "../../dev-proxy";
import viteConfig from "../../vite.config";

test("development proxy is absent unless an explicit local Rust edge is configured", () => {
  expect(browserEdgeProxy(undefined)).toBeUndefined();
});

test("development forwards only API/auth routes unchanged to a fixed loopback Rust edge", () => {
  const rules = browserEdgeProxy("http://127.0.0.1:18081")!;
  expect(Object.keys(rules)).toEqual(["^/(api|auth)(/|$)"]);
  const [pattern] = Object.keys(rules);
  for (const path of ["/api/session", "/auth/login", "/auth/callback", "/api/apex/v1/McpProxyService/GetProxy"])
    expect(new RegExp(pattern).test(path)).toBe(true);
  for (const path of ["/api-remote", "/authentication", "/assets/app.js", "//api/session"])
    expect(new RegExp(pattern).test(path)).toBe(false);
  expect(rules[pattern]).toEqual({ target: "http://127.0.0.1:18081", changeOrigin: false,
    followRedirects: false, ws: false, timeout: 65000, proxyTimeout: 65000 });
});

test.each(["", " ", "http://localhost:8081", "http://127.0.0.2:8081", "http://0.0.0.0:8081",
  "http://example.test:8081", "http://user@127.0.0.1:8081", "http://127.0.0.1:8081/",
  "http://127.0.0.1:8081/path", "http://127.0.0.1:8081?x=1", "https://127.0.0.1:8081",
  "http://127.0.0.1:0", "http://127.0.0.1:08081", "http://127.0.0.1:65536", "http://127.0.0.1:8081\n"])(
  "development refuses nonliteral/ambiguous destination %s", target => {
    expect(() => browserEdgeProxy(target)).toThrow("APEX_UI_BROWSER_EDGE must be an explicit http://127.0.0.1:port origin");
  });

const codeSentinel = "CALLBACK_CODE_MUST_NOT_BE_LOGGED";
const stateSentinel = "CALLBACK_STATE_MUST_NOT_BE_LOGGED";
const callback = `/auth/callback?code=${codeSentinel}%2B%2f&state=${stateSentinel}&extra=a+b&extra=%20`;

function captureLogs() {
  const payloads: unknown[][] = [];
  const terminal: string[] = [];
  const stream = new Writable({ write(chunk, _encoding, done) { terminal.push(chunk.toString()); done(); } });
  const base = createLogger("info", { allowClearScreen: false, console: new Console(stream, stream) });
  // Capture arguments before the real terminal logger, including non-enumerable
  // Error fields: hiding just the displayed string must not pass this boundary.
  const logger: Logger = {
    ...base,
    info(...args) { payloads.push(["info", ...args]); base.info(...args); },
    warn(...args) { payloads.push(["warn", ...args]); base.warn(...args); },
    warnOnce(...args) { payloads.push(["warnOnce", ...args]); base.warnOnce(...args); },
    error(...args) { payloads.push(["error", ...args]); base.error(...args); },
  };
  for (const method of ["log", "info", "warn", "error", "debug", "trace", "dir", "table"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => { payloads.push([method, ...args]); });
  }
  return { logger, payloads, terminal };
}

async function listen(server: Server) {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected loopback TCP listener");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server) {
  await new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

async function startProxy(target: string) {
  vi.stubEnv("APEX_UI_BROWSER_EDGE", target);
  const logs = captureLogs();
  const config = await viteConfig({ command: "serve", mode: "test" });
  // Use the actual application config/plugins and Vite's installed proxy/error
  // listener. Only the log sink, ephemeral listener and file-watching are test-owned.
  const vite = await createViteServer({ ...config, configFile: false, customLogger: logs.logger,
    appType: "custom", optimizeDeps: { noDiscovery: true, include: [] },
    server: { ...config.server, middlewareMode: true, hmr: false, watch: null } });
  const server = createServer(vite.middlewares);
  try {
    const origin = await listen(server);
    return { ...logs, vite, origin, async stop() { await close(server); await vite.close(); } };
  } catch (error) {
    await vite.close();
    throw error;
  }
}

function get(origin: string, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number | undefined; headers: import("node:http").IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const req = request(origin, { path, headers, agent: false }, res => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", chunk => { body += chunk; });
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.setTimeout(3000, () => req.destroy(new Error("Proxy component request timed out")));
    req.on("error", reject);
    req.end();
  });
}

function expectNoCallbackSecrets(value: unknown) {
  const captured = inspect(value, { depth: null, showHidden: true, customInspect: false, getters: false });
  expect(captured).not.toContain(codeSentinel);
  expect(captured).not.toContain(stateSentinel);
}

test("actual Vite HTTP proxy failure never logs callback code/state or exposes them in the error response", async () => {
  const backend = createServer();
  const closedOrigin = await listen(backend);
  await close(backend);
  const proxy = await startProxy(closedOrigin);
  try {
    const response = await get(proxy.origin, callback);
    expect(response.status).toBe(500);
    expect(response.headers["content-type"]).toBe("text/plain");
    expect(response.body).toBe("");
    // The failure remains observable; blanket silence cannot satisfy the test.
    expect(proxy.payloads.some(([level]) => level === "error")).toBe(true);
    expect(proxy.terminal.length).toBeGreaterThan(0);
    expectNoCallbackSecrets([proxy.payloads, proxy.terminal, response]);
  } finally { await proxy.stop(); }
});

test("actual Vite callback success forwards the exact query and preserves Origin/cookie/redirect policy", async () => {
  const received: { url: string | undefined; headers: import("node:http").IncomingHttpHeaders }[] = [];
  const cookie = "__Host-apex=test-session; Secure; HttpOnly; SameSite=Lax; Path=/";
  const location = "https://127.0.0.1:4173/proxies";
  const backend = createServer((req, res) => {
    received.push({ url: req.url, headers: req.headers });
    res.writeHead(302, { Location: location, "Set-Cookie": cookie }).end();
  });
  const target = await listen(backend);
  const proxy = await startProxy(target);
  try {
    const response = await get(proxy.origin, callback, { Origin: "https://127.0.0.1:4173",
      Host: "127.0.0.1:4173", Cookie: "__Host-apex-binding=test-binding" });
    expect(received).toHaveLength(1);
    expect(received[0].url).toBe(callback);
    expect(received[0].headers.origin).toBe("https://127.0.0.1:4173");
    expect(received[0].headers.host).toBe("127.0.0.1:4173");
    expect(received[0].headers.cookie).toBe("__Host-apex-binding=test-binding");
    expect(response.status).toBe(302);
    expect(response.headers.location).toBe(location);
    expect(response.headers["set-cookie"]).toEqual([cookie]);
    expectNoCallbackSecrets([proxy.payloads, proxy.terminal, response]);
  } finally { await proxy.stop(); await close(backend); }
});

test("configured Vite proxy logger discards colored messages and attached errors without muting unrelated errors", async () => {
  const proxy = await startProxy("http://127.0.0.1:1");
  try {
    for (const message of [`http proxy error: ${callback}`, `\u001b[31mhttp proxy error: ${callback}\u001b[39m`]) {
      const error = new Error(codeSentinel, { cause: { query: stateSentinel } });
      proxy.vite.config.logger.error(message, { error, environment: stateSentinel, timestamp: true });
    }
    expect(proxy.payloads.filter(([level]) => level === "error")).toHaveLength(2);
    expectNoCallbackSecrets([proxy.payloads, proxy.terminal]);
    const unrelated = new Error("Unrelated transform failure");
    proxy.vite.config.logger.error("Unrelated transform failure", { error: unrelated });
    expect(proxy.payloads.at(-1)).toEqual(["error", "Unrelated transform failure", { error: unrelated }]);
  } finally { await proxy.stop(); }
});
