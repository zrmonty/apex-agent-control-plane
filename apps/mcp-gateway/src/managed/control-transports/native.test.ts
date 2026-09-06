import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createHash, X509Certificate } from "node:crypto";
import { createSecureServer, type ServerHttp2Session } from "node:http2";
import type { AddressInfo, Socket } from "node:net";
import type { TLSSocket } from "node:tls";
import { fixture as pki } from "../bootstrap/tls-role-fixture.js";
import { materialFixture } from "../bootstrap/runtime-materials/fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { GuardEgressRelay } from "../guard/relay-server.js";
import { startManagedControlTransports, type ManagedControlTransports } from "../control-transports.js";
test("public stage-bound pair uses actual guarded H2 and separate credentials", {
    timeout: 15000, skip: process.env.APEX_TEST_CONTROL_TRANSPORTS !== "owned-native-fixture-v1",
}, async (t) => {
    assert.equal(process.platform, "linux");
    const sessions = new Set<ServerHttp2Session>(), sockets = new Set<Socket>(), seen = new Set<string>();
    const servers = ["governance", "evidence"].map(purpose => {
        const server = createSecureServer({ key: pki.ingress.key, cert: pki.ingress.cert, ca: pki.ca, requestCert: true, rejectUnauthorized: true });
        server.on("connection", socket => { sockets.add(socket); socket.on("error", () => { }); socket.once("close", () => sockets.delete(socket)); });
        server.on("session", session => { sessions.add(session); session.on("error", () => { }); session.once("close", () => sessions.delete(session)); });
        server.on("tlsClientError", () => { });
        server.on("stream", (stream, headers) => {
            stream.on("error", () => { });
            seen.add(purpose);
            assert.equal(headers[":path"], purpose === "governance" ? "/apex.v1.ManagedRuntimeAuthority/RenewDeployment" : "/apex.v1.EventIngest/Ingest");
            assert.equal(headers.authorization, `Bearer synthetic-dedicated-${purpose}-token`);
            assert.equal(headers[":authority"], `gateway.test:${(server.address() as AddressInfo).port}`);
            assert.equal(headers["apex-instance-proof-bin"], purpose === "governance" ? Buffer.alloc(32, 7).toString("base64") : undefined);
            const socket = stream.session!.socket as TLSSocket;
            assert.equal(socket.authorized, true);
            assert.equal(createHash("sha256").update(socket.getPeerCertificate().raw).digest("hex"), new X509Certificate(pki[purpose as "governance" | "evidence"].cert).fingerprint256.replaceAll(":", "").toLowerCase());
            stream.resume();
            stream.on("end", () => {
                stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
                stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
                stream.end(Buffer.alloc(5));
            });
        });
        return server;
    });
    let relay: GuardEgressRelay | undefined, owner: ManagedControlTransports | undefined;
    t.after(async () => {
        owner?.cancel();
        for (const session of sessions)
            session.destroy();
        for (const socket of sockets)
            socket.destroy();
        await owner?.closed;
        await relay?.close();
        await Promise.all(servers.map(server => new Promise<void>(done => server.close(() => done()))));
    });
    for (const server of servers) {
        server.listen(0, "127.0.0.1");
        await once(server, "listening");
    }
    const ports = servers.map(server => (server.address() as AddressInfo).port);
    const f = await materialFixture(f => {
        Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
            APEX_MCP_GUARD_ADDRESS: "10.248.246.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
        for (const [index, purpose] of ["governance", "evidence"].entries()) {
            f.value.profile[purpose as "governance" | "evidence"] = { endpoint: `https://gateway.test:${ports[index]}`, tls_server_name: "gateway.test" };
        }
        f.stage.files["authority-profile.json"] = f.bytes();
    });
    const materials = createManagedRuntimeMaterials(f.stageOwner, BigInt(Date.now()) * 1000n);
    t.after(async () => { disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
    // Fixture-only same-namespace loopback policy. Public pair gets no injected destination/session.
    relay = new GuardEgressRelay({ bindAddress: "10.248.246.3", port: 18080, gatewayAddress: "10.248.246.3", outboundAddress: "127.0.0.1",
        lookup(_host, done) { done(null, [{ address: "127.0.0.1", family: 4 }]); },
        policy: { select(host, port) {
                assert.equal(host, "gateway.test");
                assert.ok(ports.includes(port));
                return { host, port, pin() { return { host, port, address: "127.0.0.1", family: 4 }; } };
            } } });
    await relay.listen();
    let fatals = 0;
    owner = startManagedControlTransports({ stage: f.stageOwner, materials, onFatal() { fatals++; } });
    const pair = await owner.result;
    const authority = pair.authority.start("/apex.v1.ManagedRuntimeAuthority/RenewDeployment", Buffer.alloc(0));
    const now = process.hrtime.bigint(), evidence = pair.evidence.start(Buffer.alloc(0), now, now + 5000000000n);
    assert.deepEqual(await authority.result, Buffer.alloc(0));
    assert.deepEqual(await evidence.result, Buffer.alloc(0));
    await Promise.all([authority.closed, evidence.closed]);
    assert.deepEqual([...seen].sort(), ["evidence", "governance"]);
    assert.equal(f.counts.disposals, 0);
    owner.cancel();
    await owner.closed;
    assert.equal(fatals, 0);
    // A fresh pair is possible only after actual prior closure; real peer loss
    // revokes both new channels without disposing the caller's stage/materials.
    owner = startManagedControlTransports({ stage: f.stageOwner, materials, onFatal() { fatals++; } });
    await owner.result;
    const active = [...sessions];
    assert.ok(active.length >= 2);
    active[0].destroy();
    await owner.revoked;
    await owner.closed;
    assert.equal(fatals, 0);
    assert.equal(f.counts.disposals, 0);
});
