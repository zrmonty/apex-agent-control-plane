// Real guarded TLS/RPC sockets with synthetic authority/durability responses.
// Does not impersonate the real CP, agent or durable event-ingest acceptance.
import assert from "node:assert/strict";
import { once } from "node:events";
import { createHash, X509Certificate } from "node:crypto";
import { createSecureServer, type ServerHttp2Session, type ServerHttp2Stream } from "node:http2";
import { createServer } from "node:https";
import type { Duplex } from "node:stream";
import type { TLSSocket } from "node:tls";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedDeploymentRenewalSchema, ManagedDeploymentGrantSchema, ManagedGrantMode, GovernanceOutcome,
  ManagedCallAuthorizationRequestSchema, ManagedCallAuthorizationDecisionSchema,
  ManagedCallCompletionSchema, ManagedCallCompletionReceiptSchema, ManagedPolicyRequestSchema, ManagedPolicySnapshotSchema,
  RuntimeNetworkInspectionRequestSchema, RuntimeNetworkInspectionResponseSchema } from "@apex/contracts";
import { EventEnvelopeSchema, EvidenceAdmissionProbeRequestSchema, EvidenceAdmissionProbeResponseSchema } from "@apex/contracts/event";
import { fixture as pki } from "../bootstrap/tls-role-fixture.js";
import { deferred } from "../stage-reader/fixture.js";

export async function nativeServices() {
  const sockets = new Set<Duplex>(), sessions = new Set<ServerHttp2Session>(), methods: string[] = [];
  const applied = deferred<void>(), evidenceSeen = deferred<void>(), refreshed = deferred<void>(), completionSeen = deferred<void>();
  let serving = false, renewal = 0, toolCalls = 0, completion = 0, networkChecks = 0;
  let admit: (() => void) | undefined, complete: (() => void) | undefined;
  let event: ReturnType<typeof fromBinary<typeof EventEnvelopeSchema>> | undefined;
  const destinations = new Set<string>(), networkAt: bigint[] = [];
  const held = new Map<string, ServerHttp2Stream>(), premature = new Set<string>();
  function hold(name: string, stream: ServerHttp2Stream) {
    held.set(name, stream);
    for (const signal of ["close", "aborted", "error"] as const) stream.on(signal, () => {
      if (held.has(name)) premature.add(`${name}:${signal}`);
    });
  }
  function assertHeld(name: string) {
    const stream = held.get(name); assert.ok(stream, `${name} remains held`);
    assert.deepEqual([...premature], [], "no premature receipt stream progress");
    assert.equal(stream.destroyed || stream.closed || stream.writableEnded, false);
  }
  function guarded(socket: { remoteAddress?: string }, purpose: string) {
    assert.equal(socket.remoteAddress, "10.248.245.3", `${purpose} must traverse actual guard`);
    destinations.add(purpose);
  }
  const pin = (cert: string) => new X509Certificate(cert).fingerprint256.replaceAll(":", "").toLowerCase();
  const reply = (stream: ServerHttp2Stream, bytes: Uint8Array) => {
    const frame = Buffer.alloc(5 + bytes.length); frame.writeUInt32BE(bytes.length, 1); frame.set(bytes, 5);
    stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
    stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" })); stream.end(frame);
  };
  const tls = { key: pki.ingress.key, cert: pki.ingress.cert, ca: pki.ca, requestCert: true, rejectUnauthorized: true };
  const controls = (["governance", "evidence"] as const).map(purpose => {
    const server = createSecureServer(tls);
    server.on("session", session => { sessions.add(session); session.on("error", () => {}); session.once("close", () => sessions.delete(session)); });
    server.on("stream", (stream, headers) => {
      stream.on("error", () => {}); const socket = stream.session!.socket as TLSSocket;
      guarded(socket, purpose);
      assert.equal(socket.authorized, true);
      assert.equal(createHash("sha256").update(socket.getPeerCertificate().raw).digest("hex"), pin(pki[purpose].cert));
      assert.equal(headers.authorization, `Bearer synthetic-dedicated-${purpose}-token`);
      assert.equal(headers["apex-instance-proof-bin"], purpose === "governance" ? Buffer.alloc(32, 7).toString("base64") : undefined);
      const chunks: Buffer[] = []; stream.on("data", b => chunks.push(Buffer.from(b))); stream.on("end", () => {
        const frame = Buffer.concat(chunks); assert.equal(frame[0], 0); assert.equal(frame.readUInt32BE(1), frame.length - 5);
        const bytes = frame.subarray(5), method = String(headers[":path"]); methods.push(method);
        if (purpose === "evidence") {
          if (method === "/apex.v1.EvidenceAdmissionReadiness/Check") {
            const request = fromBinary(EvidenceAdmissionProbeRequestSchema, bytes);
            reply(stream, toBinary(EvidenceAdmissionProbeResponseSchema, create(EvidenceAdmissionProbeResponseSchema, {
              schemaVersion: request.schemaVersion, workspaceId: request.workspaceId, namespaceId: request.namespaceId,
              agentId: request.agentId, requestNonce: request.requestNonce, ready: true, validForUs: 10_000_000n,
            }))); return;
          }
          assert.equal(method, "/apex.v1.EventIngest/Ingest"); event = fromBinary(EventEnvelopeSchema, bytes);
          assert.equal(event.agentId, "managed-evidence"); hold("evidence", stream);
          admit = () => { assertHeld("evidence"); held.delete("evidence"); reply(stream, Buffer.alloc(0)); };
          evidenceSeen.resolve(); return;
        }
        if (method === "/apex.v1.ManagedNetworkReadiness/Check") {
          networkAt.push(process.hrtime.bigint());
          const request = fromBinary(RuntimeNetworkInspectionRequestSchema, bytes);
          reply(stream, toBinary(RuntimeNetworkInspectionResponseSchema, create(RuntimeNetworkInspectionResponseSchema, {
            schemaVersion: request.schemaVersion, binding: request.binding, nonce: request.nonce, confined: true,
            networkBindingSha256: "b".repeat(64), gatewayProcessSha256: "d".repeat(64), guardProcessSha256: "e".repeat(64), validForUs: 10_000_000n,
          }))); if (++networkChecks === 2) refreshed.resolve(); return;
        }
        if (method.endsWith("GetManagedPolicy")) {
          const request = fromBinary(ManagedPolicyRequestSchema, bytes);
          reply(stream, toBinary(ManagedPolicySnapshotSchema, create(ManagedPolicySnapshotSchema, {
            binding: request.binding, nonce: request.nonce, policyId: "ria-read-v1", revision: 9007199254740993n,
          }))); return;
        }
        if (method.endsWith("RenewDeployment")) {
          const request = fromBinary(ManagedDeploymentRenewalSchema, bytes); renewal++;
          if (request.applied?.admitting) { assert.equal(serving, true); applied.resolve(); }
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
        hold("completion", stream);
        complete = () => {
          assertHeld("completion"); held.delete("completion");
          assert.equal(stream.destroyed, false, "completion transport must survive normal output and local shutdown");
          reply(stream, toBinary(ManagedCallCompletionReceiptSchema, create(ManagedCallCompletionReceiptSchema, {
            binding: request.binding, admissionId: request.admissionId, callId: request.callId, released: true })));
        };
        completionSeen.resolve();
      });
    }); return server;
  });
  const upstream = createServer({ ...tls, requestCert: false, ALPNProtocols: ["http/1.1"] }, (req, res) => {
    guarded(req.socket, "upstream");
    assert.equal(req.url, "/mcp"); assert.equal(req.headers.authorization, "Bearer synthetic-dedicated-upstream-token");
    assert.equal(req.headers["apex-instance-proof-bin"], undefined);
    const chunks: Buffer[] = []; req.on("data", b => chunks.push(b)); req.on("end", () => {
      const rpc = JSON.parse(Buffer.concat(chunks).toString()) as { id: string; method: string }; methods.push(rpc.method);
      if (rpc.method === "notifications/initialized") { res.writeHead(202); res.end(); return; }
      const result = rpc.method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "native", version: "1" } } :
        rpc.method === "tools/list" ? { tools: [{ name: "portfolio.read", inputSchema: { type: "object", properties: { portfolioId: { type: "string" } },
          required: ["portfolioId"], additionalProperties: false }, outputSchema: { type: "object" } }] } :
          { content: [], structuredContent: { portfolio_id: "p-1", as_of: "2026-09-08", base_currency: "USD", total_value: 123,
            client: { display_name: "Client", account_number: "RAW-MUST-NOT-ESCAPE", tax_id: "RAW-MUST-NOT-ESCAPE" }, positions: [] } };
      if (rpc.method === "tools/call") toolCalls++;
      res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result }));
    });
  });
  const servers = [...controls, upstream];
  async function close() {
    for (const session of sessions) session.destroy(); for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map(server => new Promise<void>(done => server.close(() => done()))));
  }
  try {
    for (const [index, server] of servers.entries()) {
      server.on("connection", socket => { sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket)); });
      server.on("tlsClientError", () => {}); server.listen(41001 + index, "10.248.245.2"); await once(server, "listening");
    }
    return { close, methods, applied: applied.promise, evidenceSeen: evidenceSeen.promise,
      refreshed: refreshed.promise, completionSeen: completionSeen.promise,
      serve() { serving = true; }, admit() { assert.ok(admit); admit(); }, complete() { assert.ok(complete); complete(); },
      assertHeld, stats: () => ({ toolCalls, completion, event, destinations: [...destinations].sort(), networkAt: [...networkAt] }) };
  } catch (error) { await close(); throw error; }
}
