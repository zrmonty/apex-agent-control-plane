import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createHash, X509Certificate } from "node:crypto";
import { createSecureServer, type ServerHttp2Session, type ServerHttp2Stream } from "node:http2";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { decodeStrict, encodeJson, RuntimeConfigurationSchema, RuntimeLaunchContextSchema,
  ManagedDeploymentRenewalSchema, ManagedDeploymentGrantSchema, ManagedGrantMode, GovernanceOutcome,
  ManagedCallAuthorizationRequestSchema, ManagedCallAuthorizationDecisionSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema, ManagedPolicyRequestSchema, ManagedPolicySnapshotSchema,
  RuntimeNetworkInspectionRequestSchema, RuntimeNetworkInspectionResponseSchema } from "@apex/contracts";
import { EventEnvelopeSchema, EvidenceAdmissionProbeRequestSchema, EvidenceAdmissionProbeResponseSchema } from "@apex/contracts/event";
import { materialFixture } from "../bootstrap/runtime-materials/fixture.js";
import { fixture as pki } from "../bootstrap/tls-role-fixture.js";
import { jwks } from "../bootstrap/inbound-verifier/fixture.js";
import { createManagedRuntimeMaterials, disposeRuntimeMaterials } from "../bootstrap/runtime-materials.js";
import { disposeStageOwner } from "../bootstrap/stage-owner.js";
import { runtimeManifestHash } from "../runtime-config.js";
import { launchContextHash } from "../launch-context.js";
import { GuardEgressRelay } from "../guard/relay-server.js";
import { createClock } from "../../telemetry/clock.js";
import { deferred } from "../stage-reader/fixture.js";
import { startManagedRuntimeCore, type RuntimeCoreHandle } from "../runtime-core.js";

test("actual core uses separated guarded mTLS, prepares without admission, and waits for evidence before filtered success", {
  timeout: 15000, skip: process.env.APEX_TEST_RUNTIME_CORE !== "owned-native-fixture-v1",
}, async t => {
  assert.equal(process.platform, "linux");
  const sockets = new Set<Duplex>(), sessions = new Set<ServerHttp2Session>(), methods: string[] = [];
  const evidenceSeen = deferred<void>(); let event: ReturnType<typeof fromBinary<typeof EventEnvelopeSchema>> | undefined;
  const heldCallSeen = deferred<void>(); let holdCall = false;
  const firstCompletionSeen = deferred<void>();
  let admit: (() => void) | undefined, serving = false, renewal = 0, toolCalls = 0, completion = 0, fatals = 0;
  const pin = (cert: string) => new X509Certificate(cert).fingerprint256.replaceAll(":", "").toLowerCase();
  const reply = (stream: ServerHttp2Stream, bytes: Uint8Array) => {
    const frame = Buffer.alloc(5 + bytes.length); frame.writeUInt32BE(bytes.length, 1); frame.set(bytes, 5);
    stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
    stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" })); stream.end(frame);
  };
  const tls = { key: pki.ingress.key, cert: pki.ingress.cert, ca: pki.ca, requestCert: true, rejectUnauthorized: true };
  const controls = ["governance", "evidence"].map(purpose => {
    const server = createSecureServer(tls);
    server.on("session", session => { sessions.add(session); session.on("error", () => {}); session.once("close", () => sessions.delete(session)); });
    server.on("stream", (stream, headers) => {
      stream.on("error", () => {});
      const socket = stream.session!.socket as TLSSocket;
      assert.equal(socket.authorized, true);
      assert.equal(createHash("sha256").update(socket.getPeerCertificate().raw).digest("hex"), pin(pki[purpose as "governance" | "evidence"].cert));
      assert.equal(headers.authorization, `Bearer synthetic-dedicated-${purpose}-token`);
      assert.equal(headers["apex-instance-proof-bin"], purpose === "governance" ? Buffer.alloc(32, 7).toString("base64") : undefined);
      const chunks: Buffer[] = []; stream.on("data", b => chunks.push(Buffer.from(b))); stream.on("end", () => {
        const frame = Buffer.concat(chunks); assert.equal(frame[0], 0); assert.equal(frame.readUInt32BE(1), frame.length - 5);
        const bytes = frame.subarray(5), method = String(headers[":path"]); methods.push(method);
        if (purpose === "evidence") {
          if (method === "/apex.v1.EvidenceAdmissionReadiness/Check") {
            const request = fromBinary(EvidenceAdmissionProbeRequestSchema, bytes);
            reply(stream, toBinary(EvidenceAdmissionProbeResponseSchema, create(EvidenceAdmissionProbeResponseSchema, {
              schemaVersion: request.schemaVersion, requestNonce: request.requestNonce, workspaceId: request.workspaceId,
              namespaceId: request.namespaceId, agentId: request.agentId, ready: true, validForUs: 10_000_000n,
            }))); return;
          }
          assert.equal(method, "/apex.v1.EventIngest/Ingest"); event = fromBinary(EventEnvelopeSchema, bytes);
          assert.equal(event.agentId, "managed-evidence"); admit = () => reply(stream, Buffer.alloc(0)); evidenceSeen.resolve(); return;
        }
        if (method === "/apex.v1.ManagedNetworkReadiness/Check") {
          // Synthetic confinement observation over actual guarded mTLS. This
          // fixture does not run the production CP/agent or claim real topology.
          const request = fromBinary(RuntimeNetworkInspectionRequestSchema, bytes);
          reply(stream, toBinary(RuntimeNetworkInspectionResponseSchema, create(RuntimeNetworkInspectionResponseSchema, {
            schemaVersion: request.schemaVersion, binding: request.binding, nonce: request.nonce, confined: true,
            networkBindingSha256: "b".repeat(64), gatewayProcessSha256: "d".repeat(64), guardProcessSha256: "e".repeat(64),
            validForUs: 10_000_000n,
          }))); return;
        }
        if (method.endsWith("GetManagedPolicy")) {
          const request = fromBinary(ManagedPolicyRequestSchema, bytes);
          reply(stream, toBinary(ManagedPolicySnapshotSchema, create(ManagedPolicySnapshotSchema, {
            binding: request.binding, nonce: request.nonce, policyId: "ria-read-v1", revision: 9007199254740993n,
          }))); return;
        }
        if (method.endsWith("RenewDeployment")) {
          const request = fromBinary(ManagedDeploymentRenewalSchema, bytes); renewal++;
          reply(stream, toBinary(ManagedDeploymentGrantSchema, create(ManagedDeploymentGrantSchema, {
            binding: request.binding, nonce: request.nonce, renewalSequence: request.renewalSequence,
            decisionId: `018f3d4a-8b9c-7000-8000-${String(renewal).padStart(12, "0")}`, epoch: serving ? 2n : 1n,
            mode: serving ? ManagedGrantMode.SERVE : ManagedGrantMode.PREPARE, validForUs: 10_000_000n,
          }))); return;
        }
        if (method.endsWith("AuthorizeManagedCall")) {
          const request = fromBinary(ManagedCallAuthorizationRequestSchema, bytes);
          assert.equal(request.generation, 9007199254740993n); assert.equal(request.caller!.principal, "operator:alice");
          reply(stream, toBinary(ManagedCallAuthorizationDecisionSchema, create(ManagedCallAuthorizationDecisionSchema, {
            decision: { outcome: GovernanceOutcome.ALLOWED, policyId: "ria-read-v1", reasonCode: "policy.allowed", fieldRestrictions: [] },
            admissionId: "018f3d4a-8b9c-7000-8000-000000000999", epoch: 2n, policyRevision: 9007199254740993n,
            validForUs: 10_000_000n, expiresAtUnixUs: BigInt(Date.now()) * 1000n + 10_000_000n,
          }))); return;
        }
        assert.ok(method.endsWith("CompleteManagedCall")); completion++;
        const request = fromBinary(ManagedCallCompletionSchema, bytes);
        if (completion === 1) {
          firstCompletionSeen.resolve();
          // Deterministic transient completion failure: the core must expose
          // this exact reservation for explicit retry during normal operation.
          stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
          stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "14" })); stream.end(); return;
        }
        reply(stream, toBinary(ManagedCallCompletionReceiptSchema, create(ManagedCallCompletionReceiptSchema, {
          binding: request.binding, admissionId: request.admissionId, callId: request.callId, released: true })));
      });
    }); return server;
  });
  const upstream = createServer({ ...tls, requestCert: false, ALPNProtocols: ["http/1.1"] }, (req, res) => {
    assert.equal(req.url, "/mcp"); assert.equal(req.headers.authorization, "Bearer synthetic-dedicated-upstream-token");
    assert.equal(req.headers["apex-instance-proof-bin"], undefined);
    const chunks: Buffer[] = []; req.on("data", b => chunks.push(b)); req.on("end", () => {
      const rpc = JSON.parse(Buffer.concat(chunks).toString()) as { id: string; method: string };
      methods.push(rpc.method);
      if (rpc.method === "notifications/initialized") { res.writeHead(202); res.end(); return; }
      const result = rpc.method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "native", version: "1" } } :
        rpc.method === "tools/list" ? { tools: [{ name: "portfolio.read", inputSchema: { type: "object", properties: { portfolioId: { type: "string" } },
          required: ["portfolioId"], additionalProperties: false }, outputSchema: { type: "object" } }] } :
          { content: [], structuredContent: { portfolio_id: "p-1", as_of: "2026-09-08", base_currency: "USD", total_value: 123,
            client: { display_name: "Client", account_number: "RAW-MUST-NOT-ESCAPE", tax_id: "RAW-MUST-NOT-ESCAPE" }, positions: [] } };
      if (rpc.method === "tools/call") { toolCalls++; if (holdCall) { heldCallSeen.resolve(); return; } }
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
    });
  });
  let owner: RuntimeCoreHandle | undefined, relay: GuardEgressRelay | undefined;
  t.after(async () => {
    owner?.cancel(); for (const s of sessions) s.destroy(); for (const s of sockets) s.destroy();
    await owner?.closed; await relay?.close();
    await Promise.all([...controls, upstream].map(s => new Promise<void>(done => s.close(() => done()))));
  });
  for (const server of [...controls, upstream]) {
    server.on("connection", s => { sockets.add(s); s.on("error", () => {}); s.once("close", () => sockets.delete(s)); });
    server.on("tlsClientError", () => {}); server.listen(0, "127.0.0.1"); await once(server, "listening");
  }
  const ports = [...controls, upstream].map(s => (s.address() as AddressInfo).port);
  const f = await materialFixture(f => {
    Object.assign(f.env, { APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
      APEX_MCP_GUARD_ADDRESS: "10.248.246.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
    const files = f.stage.files;
    const config = decodeStrict(RuntimeConfigurationSchema, files["runtime-revision.json"].toString());
    config.spec!.upstreams[0].endpointOrCommandRef = `https://gateway.test:${ports[2]}/mcp`;
    config.spec!.upstreams[0].serverIdentity = "gateway.test";
    config.networkGrants.forEach(g => { g.host = "gateway.test"; g.port = ports[2]; });
    config.spec!.runtimeProfile!.egressDestinations.forEach(g => { g.host = "gateway.test"; g.port = ports[2]; });
    config.runtimeManifestHash = runtimeManifestHash(config);
    const launch = decodeStrict(RuntimeLaunchContextSchema, files["launch-context.json"].toString());
    launch.runtimeManifestHash = config.runtimeManifestHash; launch.launchContextHash = launchContextHash(launch);
    files["runtime-revision.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeConfigurationSchema, config)));
    files["launch-context.json"] = Buffer.from(JSON.stringify(encodeJson(RuntimeLaunchContextSchema, launch)));
    ["governance", "evidence"].forEach((p, i) => { f.value.profile[p as "governance" | "evidence"] = {
      endpoint: `https://gateway.test:${ports[i]}`, tls_server_name: "gateway.test" }; });
    files["authority-profile.json"] = f.bytes(); files["inbound-jwks"] = jwks();
  });
  const materials = createManagedRuntimeMaterials(f.stageOwner, BigInt(Date.now()) * 1000n);
  t.after(async () => { disposeRuntimeMaterials(materials); disposeStageOwner(f.stageOwner); await f.bootstrap.closed; });
  // Explicit disposable native fixture policy; not deployment confinement proof.
  relay = new GuardEgressRelay({ bindAddress: "10.248.246.3", port: 18080, gatewayAddress: "10.248.246.3", outboundAddress: "127.0.0.1",
    lookup(_host, done) { done(null, [{ address: "127.0.0.1", family: 4 }]); },
    policy: { select(host, port) { assert.equal(host, "gateway.test"); assert.ok(ports.includes(port));
      return { host, port, pin() { return { host, port, address: "127.0.0.1", family: 4 }; } }; } } });
  await relay.listen(); const clock = createClock();
  owner = startManagedRuntimeCore({ stage: f.stageOwner, materials, clock, onFatal() { fatals++; } });
  const core = await owner.result; assert.equal(core.isAdmitting(), false);
  assert.equal((await core.readiness.checkStartup()).ready, true);
  assert.equal(methods.filter(method => method === "/apex.v1.ManagedNetworkReadiness/Check").length, 1);
  assert.equal(methods.filter(method => method === "/apex.v1.EvidenceAdmissionReadiness/Check").length, 1);
  assert.equal(methods.filter(method => method.endsWith("GetManagedPolicy")).length, 1);
  assert.equal(toolCalls, 0); assert.equal(event, undefined); assert.equal(core.isAdmitting(), false);
  serving = true; assert.equal(await core.grants.renew(), true); assert.equal(core.isAdmitting(), true);
  const at = clock.now(), call = core.executor.start({ subject: "operator:alice", proxyId: f.stageOwner.documents.config.proxyId, scopes: ["mcp:tools"] },
    "portfolio.read", { portfolioId: "p-1" }, at, at.monotonicNs + 10_000_000_000n);
  let delivered = false; void call.result.then(() => { delivered = true; }, () => {});
  await evidenceSeen.promise; assert.equal(delivered, false); assert.equal(toolCalls, 1);
  assert.equal(event!.data!.generation, "9007199254740993"); assert.match(event!.timestamp, /\.\d{6}Z$/);
  assert.equal(JSON.stringify(event).includes("RAW-MUST-NOT-ESCAPE"), false);
  await firstCompletionSeen.promise; admit!(); const result = await call.result; await call.closed;
  assert.equal(result.structuredContent.portfolioId, "p-1"); assert.equal(JSON.stringify(result).includes("RAW-MUST-NOT-ESCAPE"), false);
  assert.deepEqual(core.pendingCompletions(), [{ callId: call.observation().callId,
    admissionId: "018f3d4a-8b9c-7000-8000-000000000999", state: "completion_pending" }]);
  assert.equal(completion, 1);
  const retry = core.retryCompletion(call.observation().callId!);
  assert.equal(await retry.result, true); await retry.closed;
  assert.equal(completion, 2); assert.deepEqual(core.pendingCompletions(), []);
  holdCall = true;
  const secondAt = clock.now(), second = core.executor.start({ subject: "operator:alice", proxyId: f.stageOwner.documents.config.proxyId, scopes: ["mcp:tools"] },
    "portfolio.read", { portfolioId: "p-1" }, secondAt, secondAt.monotonicNs + 10_000_000_000n);
  await heldCallSeen.promise;
  const probeAt = clock.now(), sweep = core.prepareUpstream({ startedAtMonotonicNs: probeAt.monotonicNs,
    deadlineMonotonicNs: probeAt.monotonicNs + 5_000_000_000n });
  assert.equal(core.isAdmitting(), true); await sweep;
  assert.equal(core.isAdmitting(), true); assert.equal(toolCalls, 2); assert.equal(completion, 2);
  assert.equal(methods.filter(method => method === "initialize").length, 2);
  assert.equal(methods.filter(method => method === "tools/list").length, 2);
  owner.cancel(); await assert.rejects(second.result); await second.closed; await owner.closed;
  assert.equal(completion, 3); assert.deepEqual(await owner.completionHandoff, []);
  assert.equal(fatals, 0); assert.equal(core.isAdmitting(), false);
});
