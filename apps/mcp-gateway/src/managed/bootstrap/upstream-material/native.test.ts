// Native component acceptance, not protected-stage/root/network confinement.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:tls";
import type { AddressInfo, Socket } from "node:net";
import { fixture } from "../tls-role-fixture.js";
import { serverFixture } from "./server-fixture.js";
import { parseManagedUpstreamCredential, upstreamCredentialMaterial, disposeUpstreamCredential,
  type UpstreamAuthentication } from "../upstream-material.js";
import { GuardEgressRelay } from "../../guard/relay-server.js";
import { GuardedTlsConnector } from "../../guard/tls-connector.js";
import { testPolicy } from "../../guard/relay-testing.js";

async function native(t: TestContext, authentication: UpstreamAuthentication,
  defect?: "server-name" | "server-ca" | "client-ca") {
  const mutual = authentication.includes("mtls"), bearer = authentication.includes("bearer");
  const owner = parseManagedUpstreamCredential(Buffer.from(JSON.stringify({ schema_version: 1, authentication,
    server_ca: defect === "server-ca" ? fixture.ca : serverFixture.ca,
    ...(bearer ? { token: "synthetic-only-upstream-token" } : {}),
    ...(mutual ? { client: { ca: fixture.ca, ...fixture.governance } } : {}) })), 1783123456123456n);
  const material = upstreamCredentialMaterial(owner), sockets = new Set<Socket>();
  let accepted = 0;
  const upstream = createServer({ ca: defect === "client-ca" ? serverFixture.ca : fixture.ca,
    cert: serverFixture.cert, key: serverFixture.key, requestCert: mutual, rejectUnauthorized: true,
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["h2"] }, socket => {
    accepted++; assert.equal(socket.authorized, mutual);
    socket.on("error", () => {});
    socket.once("data", chunk => {
      assert.equal(chunk.toString(), bearer ? "Bearer synthetic-only-upstream-token" : "tls-only-fixture");
      socket.write("accepted");
    });
  });
  upstream.on("connection", socket => { sockets.add(socket); socket.on("error", () => {});
    socket.once("close", () => sockets.delete(socket)); });
  upstream.on("tlsClientError", () => {});
  let relay: GuardEgressRelay | undefined, connector: GuardedTlsConnector | undefined;
  t.after(async () => {
    await connector?.close(); await relay?.close(); for (const socket of sockets) socket.destroy();
    await new Promise<void>(done => upstream.close(() => done()));
    disposeUpstreamCredential(owner); for (const value of Object.values(material)) value.fill(0);
  });
  upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
  const port = (upstream.address() as AddressInfo).port, host = defect === "server-name" ? "wrong.test" : "gateway.test";
  relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", policy: testPolicy(port, host),
    lookup(_host, callback) { callback(null, [{ address: "127.0.0.1", family: 4 }]); } });
  const address = await relay.listen();
  connector = new GuardedTlsConnector(address, [{ id: "upstream", host, port, ca: material.serverCa,
    authentication: mutual ? "mutual_tls" : "server_tls", alpn: "h2", cert: material.clientCert, key: material.clientKey }]);
  return { exchange: connector.open("upstream", process.hrtime.bigint()), material, accepted: () => accepted };
}
for (const mode of ["server_tls", "bearer", "mtls", "mtls_bearer"] as const) {
  test(`${mode} material works through real guard and TLS with independent client/server PKIs`, { timeout: 5000 }, async t => {
    const f = await native(t, mode), socket = await f.exchange.result;
    assert.equal(socket.authorized, true); assert.equal(socket.getProtocol(), "TLSv1.3");
    assert.equal(socket.servername, "gateway.test"); assert.equal(socket.alpnProtocol, "h2");
    const reply = once(socket, "data");
    socket.write(f.material.token ? Buffer.concat([Buffer.from("Bearer "), f.material.token]) : "tls-only-fixture");
    assert.equal((await reply)[0].toString(), "accepted"); assert.equal(f.accepted(), 1);
    f.exchange.cancel(); await f.exchange.closed;
  });
}
for (const defect of ["server-name", "server-ca", "client-ca"] as const) {
  test(`actual TLS refuses ${defect} despite successful material parsing`, { timeout: 5000 }, async t => {
    const f = await native(t, "mtls_bearer", defect);
    if (defect === "client-ca") {
      // TLS1.3 client secureConnect can precede the server's client-auth alert.
      // No peer acceptance is inferred from client secureConnect alone.
      await f.exchange.result.catch(() => undefined); await f.exchange.closed;
    } else { await assert.rejects(f.exchange.result, /guarded TLS refused safely/); await f.exchange.closed; }
    assert.equal(f.accepted(), 0);
  });
}
