// Test-only OS port seam. Production and legacy/native fixed-port proof stay unchanged.
import assert from "node:assert/strict";
import http, { type RequestOptions } from "node:http";
import { Server } from "node:net";
import { syncBuiltinESMExports } from "node:module";
import type { TestContext } from "node:test";

export function isolateHealthTransport(t: TestContext) {
  const listen = Server.prototype.listen, request = http.request;
  let port: number | undefined;
  const bound = t.mock.method(Server.prototype, "listen", function (this: Server, ...args: unknown[]) {
    assert.equal(args[0], 8081); assert.equal(args[1], "127.0.0.1");
    this.once("listening", () => {
      const address = this.address(); assert.ok(address && typeof address !== "string"); port = address.port;
    });
    return Reflect.apply(listen, this, [0, ...args.slice(1)]);
  });
  const redirected = t.mock.method(http, "request", (options: RequestOptions, callback: Parameters<typeof http.request>[2]) => {
    assert.equal(options.host, "127.0.0.1"); assert.equal(options.port, 8081);
    assert.equal(options.path, "/readyz"); assert.equal(options.method, "GET");
    assert.equal((options.headers as Record<string, string>).Host, "127.0.0.1:8081");
    assert.ok(port && port > 0);
    return request({ ...options, port }, callback);
  });
  syncBuiltinESMExports();
  t.after(() => { redirected.mock.restore(); bound.mock.restore(); syncBuiltinESMExports(); });
  return { port: () => { assert.ok(port); return port; } };
}
