import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, connect, type TLSSocket } from "node:tls";
import type { AddressInfo } from "node:net";
import { materialFixture, now } from "./fixture.js";
import { createManagedRuntimeMaterials, runtimeTlsMaterial, disposeRuntimeMaterials } from "../runtime-materials.js";
import { disposeStageOwner } from "../stage-owner.js";

test("composed stage roles complete real TLS after source stage disposal", { timeout: 5000 }, async t => {
  // Internal stage-loader fixture plus actual material composition/native TLS;
  // not actual FD staging or protected runtime/edge acceptance.
  const f = await materialFixture(), owner = createManagedRuntimeMaterials(f.stageOwner, now);
  const serverMaterial = runtimeTlsMaterial(owner, "ingress"), clientMaterial = runtimeTlsMaterial(owner, "governance");
  disposeStageOwner(f.stageOwner); await f.bootstrap.closed;
  disposeRuntimeMaterials(owner); // Transport's independent copies remain valid.
  const sockets = new Set<TLSSocket>();
  const server = createServer({ ...serverMaterial, requestCert: true, rejectUnauthorized: true,
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["h2"] }, socket => {
    sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket));
    assert.equal(socket.authorized, true); socket.end("composed-role-fixture");
  });
  server.on("tlsClientError", () => {});
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(done => server.close(() => done()));
    for (const bytes of [...Object.values(serverMaterial), ...Object.values(clientMaterial)]) bytes.fill(0);
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const socket = connect({ ...clientMaterial, host: "127.0.0.1", port: (server.address() as AddressInfo).port,
    servername: "gateway.test", rejectUnauthorized: true, minVersion: "TLSv1.3", ALPNProtocols: ["h2"] });
  sockets.add(socket); socket.on("error", () => {});
  const closed = new Promise<void>(done => socket.once("close", () => { sockets.delete(socket); done(); }));
  await once(socket, "secureConnect"); assert.equal(socket.authorized, true); assert.equal(socket.alpnProtocol, "h2");
  const chunks: Buffer[] = []; for await (const chunk of socket) chunks.push(Buffer.from(chunk));
  assert.equal(Buffer.concat(chunks).toString(), "composed-role-fixture"); socket.destroy(); await closed;
});
