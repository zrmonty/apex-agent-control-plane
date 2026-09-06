import assert from "node:assert/strict";
import { test } from "node:test";
import { numericAddress, parseConnect } from "./relay-protocol.js";
import { GuardEgressRelay, GuardIngressRelay } from "./relay-server.js";
import { handshake, testPolicy } from "./relay-testing.js";

const canonical = handshake("allowed.example.test", 443);
test("incremental bounded parser waits for the complete exact handshake", () => {
  for (let length = 0; length < canonical.length; length++) assert.equal(parseConnect(Buffer.from(canonical.slice(0, length))), undefined);
  assert.deepEqual(parseConnect(Buffer.from(canonical)), { host: "allowed.example.test", port: 443 });
  assert.deepEqual(parseConnect(Buffer.from(handshake("[2606:4700:4700::1111]", 443))), { host: "[2606:4700:4700::1111]", port: 443 });
});
for (const [name, value] of [
  ["TE", canonical.replace("\r\n\r\n", "\r\nTE: trailers\r\n\r\n")],
  ["Transfer-Encoding", canonical.replace("\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n")],
  ["Content-Length", canonical.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\n")],
  ["Upgrade", canonical.replace("\r\n\r\n", "\r\nUpgrade: TLS/1.0\r\n\r\n")],
  ["unknown header", canonical.replace("\r\n\r\n", "\r\nX-Ambient: value\r\n\r\n")],
  ["authorization", canonical.replace("\r\n\r\n", "\r\nAuthorization: secret\r\n\r\n")],
  ["userinfo", handshake("user:password@allowed.example.test", 443)],
  ["URL", handshake("https://allowed.example.test", 443)],
  ["noncanonical IP", handshake("127.1", 443)],
  ["zone", handshake("[fe80::1%eth0]", 443)],
  ["path", handshake("allowed.example.test/path", 443)],
  ["mismatched Host", canonical.replace("Host: allowed.example.test", "Host: other.example.test")],
  ["missing Host", canonical.replace("Host: allowed.example.test:443\r\n", "")],
  ["duplicate Host", canonical.replace("\r\n\r\n", "\r\nHost: allowed.example.test:443\r\n\r\n")],
  ["folding", canonical.replace("Host:", " Host:")],
  ["tab", canonical.replace("Host: ", "Host:\t")],
  ["extra space", canonical.replace("CONNECT ", "CONNECT  ")],
  ["HTTP/1.0", canonical.replace("HTTP/1.1", "HTTP/1.0")],
  ["HTTP/2", canonical.replace("HTTP/1.1", "HTTP/2")],
  ["alternate method", canonical.replace("CONNECT", "GET")],
  ["lowercase method", canonical.replace("CONNECT", "connect")],
  ["early TLS", canonical + "\x16\x03\x01"],
  ["second request", canonical + canonical],
  ["extra CRLF", canonical + "\r\n"],
  ["port zero", handshake("allowed.example.test", 0)],
  ["leading port zero", canonical.replaceAll(":443", ":0443")],
  ["invalid port", handshake("allowed.example.test", 65536)],
  ["negative port", handshake("allowed.example.test", -1)],
  ["high byte", canonical.replace("allowed", "allöwed")],
  ["2048 incomplete", "X".repeat(2048)],
  ["2049 bytes", "X".repeat(2049)],
] as const) test(`parser refuses ${name} statically`, () => {
  assert.throws(() => parseConnect(Buffer.from(value)), { message: "guard relay refused safely" });
});

test("only explicit numeric non-wildcard constructor addresses can reach listen", async () => {
  const options = { bindAddress: "127.0.0.1", port: 0, outboundAddress: "127.0.0.1",
    gatewayAddress: "127.0.0.21", edgeAddress: "127.0.0.1", policy: testPolicy(443) };
  for (const value of ["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "localhost", "example.test", "::ffff:0.0.0.0", "fe80::1%eth0", "127.0.0.1:80", ""]) {
    for (const field of ["bindAddress", "gatewayAddress", "outboundAddress"]) {
      assert.throws(() => new GuardEgressRelay({ ...options, [field]: value }), { message: "guard relay refused safely" });
      assert.throws(() => new GuardIngressRelay({ ...options, [field]: value }), { message: "guard relay refused safely" });
    }
    assert.throws(() => new GuardIngressRelay({ ...options, edgeAddress: value }));
  }
  for (const port of [-1, 65536, NaN, 0.5, "80" as unknown as number]) assert.throws(() => new GuardEgressRelay({ ...options, port }));
  assert.equal(numericAddress("2001:db8:0:0:0:0:0:1"), "2001:db8::1");
  assert.equal(numericAddress("10.88.0.2"), "10.88.0.2");
  const dormant = new GuardEgressRelay(options); await dormant.close();
});
