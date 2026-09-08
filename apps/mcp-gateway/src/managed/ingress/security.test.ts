import test from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:tls";
import { ingressFixture, send, initialize, pki } from "./fixture.js";

test("exact path, Host and Origin validation also protects metadata", async t => {
  const f = await ingressFixture(t);
  for (const path of ["/other", "/mcp?extra=1", "/a/../mcp", "/%6dcp", "//proxy.apex.test/mcp"]) {
    assert.equal((await send(f.address.port, { path, body: initialize })).status, 400, path);
  }
  for (const path of ["/mcp", "/.well-known/oauth-protected-resource"]) {
    for (const headers of [{ host: "attacker.test" }, { origin: "https://attacker.test" }, { origin: "" }] as Record<string, string>[]) {
      assert.equal((await send(f.address.port, { method: "GET", path, headers })).status, 400);
    }
  }
});

test("header-count truncation cannot hide a second sensitive header", async t => {
  const f = await ingressFixture(t);
  const status = await new Promise<string>((resolve, reject) => {
    const socket = connect({ host: "127.0.0.1", port: f.address.port, servername: "gateway.test", ca: pki.ca,
      ...pki.governance }, () => socket.write("GET /.well-known/oauth-protected-resource HTTP/1.1\r\n" +
        "Host: proxy.apex.test\r\nOrigin: https://console.apex.test\r\n" + "x:y\r\n".repeat(2100) +
        "Origin: https://attacker.test\r\nConnection: close\r\n\r\n"));
    socket.once("data", data => { resolve(String(data).split("\r\n")[0]); socket.destroy(); });
    socket.once("error", reject);
  });
  assert.match(status, /^HTTP\/1.1 400 /);
});

test("duplicate and malformed sensitive headers cannot be collapsed into an authenticated request", async t => {
  const f = await ingressFixture(t);
  for (const [name, value] of Object.entries({ authorization: "Bearer alice", origin: "https://console.apex.test",
    "mcp-session-id": "session", "mcp-protocol-version": "2025-11-25", "content-type": "application/json" })) {
    assert.equal((await send(f.address.port, { body: initialize, headers: { [name]: [value, value] } })).status, 400, name);
  }
  for (const name of ["mcp-session-id", "mcp-protocol-version"]) {
    assert.equal((await send(f.address.port, { body: initialize, headers: { [name]: "" } })).status, 400, name);
  }
});
