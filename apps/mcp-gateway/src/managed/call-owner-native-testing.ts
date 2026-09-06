// Actual mTLS authority + guard/TLS/MCP component fixture. NOT CP/PG/Serving.
import assert from "node:assert/strict";
import { once } from "node:events";
import { connect, createSecureServer, type ServerHttp2Session } from "node:http2";
import { connect as tlsConnect } from "node:tls";
import type { AddressInfo } from "node:net";
import type { TestContext } from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ManagedDeploymentGrantSchema, ManagedDeploymentRenewalSchema, ManagedGrantMode,
  ManagedCallAuthorizationRequestSchema, ManagedCallAuthorizationDecisionSchema, ManagedCallCompletionSchema,
  ManagedCallCompletionReceiptSchema } from "@apex/contracts";
import { certificate, key } from "./authority/testing-tls.js";
import { OwnedAuthorityChannel } from "./authority/unary.js";
import { AuthenticatedGrantTransport } from "./authority/grant-transport.js";
import { AuthenticatedBusinessTransport } from "./authority/business-transport.js";
import { DeploymentGrantOwner } from "./authority/grant-owner.js";
import { metadata, allowed, receipt, paths, request } from "./authority/business-testing.js";
import { wireFixture, context } from "./upstream-wire/testing.js";
import { OwnedMcpSession } from "./upstream-wire/session.js";
import { OwnedCallCoordinator } from "./call-owner.js";
import { sha256CanonicalJson } from "../live/canonical.js";
import { createUuidV7 } from "../live/uuid.js";

export async function nativeCallFixture(t: TestContext, validForUs = 10_000_000n, holdFirstCall = false) {
  let now = process.hrtime.bigint(); const started = now;
  const effects: string[] = [], sessions = new Set<ServerHttp2Session>();
  const server = createSecureServer({ key, cert: certificate, ca: certificate, requestCert: true, rejectUnauthorized: true });
  server.on("session", session => { sessions.add(session); session.on("error", () => {}); session.once("close", () => sessions.delete(session)); });
  server.on("stream", (stream, headers) => {
    stream.on("error", () => {}); const chunks: Buffer[] = [];
    stream.on("data", chunk => chunks.push(Buffer.from(chunk)));
    stream.on("end", () => {
      assert.equal(headers.authorization, "Bearer public-test-call-owner-token");
      assert.equal(headers["apex-instance-proof-bin"], Buffer.alloc(32, 7).toString("base64"));
      const bytes = Buffer.concat(chunks); assert.equal(bytes[0], 0); assert.equal(bytes.readUInt32BE(1), bytes.length - 5);
      const payload = bytes.subarray(5); let output: Uint8Array;
      if (headers[":path"] === "/apex.v1.ManagedRuntimeAuthority/RenewDeployment") {
        effects.push("renew"); const input = fromBinary(ManagedDeploymentRenewalSchema, payload);
        output = toBinary(ManagedDeploymentGrantSchema, create(ManagedDeploymentGrantSchema, {
          binding: input.binding, nonce: input.nonce, renewalSequence: input.renewalSequence, epoch: 23n,
          decisionId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e08", mode: ManagedGrantMode.SERVE, validForUs: 10_000_000n,
        }));
      } else if (headers[":path"] === paths.authorize) {
        effects.push("authorize"); fromBinary(ManagedCallAuthorizationRequestSchema, payload);
        output = toBinary(ManagedCallAuthorizationDecisionSchema, { ...allowed(), admissionId: createUuidV7(), validForUs });
      } else {
        assert.equal(headers[":path"], paths.complete); effects.push("complete");
        const input = fromBinary(ManagedCallCompletionSchema, payload);
        output = toBinary(ManagedCallCompletionReceiptSchema, { ...receipt(), binding: input.binding,
          admissionId: input.admissionId, callId: input.callId });
      }
      const framed = Buffer.alloc(output.length + 5); framed.writeUInt32BE(output.length, 1); framed.set(output, 5);
      stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => { if (!stream.destroyed) stream.sendTrailers({ "grpc-status": "0" }); }); stream.end(framed);
    });
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  const authoritySession = connect(`https://grpc-contract-test:${port}`, { createConnection: () => tlsConnect({
    host: "127.0.0.1", port, servername: "grpc-contract-test", ca: certificate, cert: certificate, key,
    ALPNProtocols: ["h2"], rejectUnauthorized: true,
  }) });
  await once(authoritySession, "connect");
  const channel = new OwnedAuthorityChannel(authoritySession, { token: "public-test-call-owner-token", instanceProof: Buffer.alloc(32, 7) });
  const business = new AuthenticatedBusinessTransport({ ...metadata, channel, monotonicNowNs: () => now });
  const grants = new DeploymentGrantOwner({ binding: metadata.binding, transport: new AuthenticatedGrantTransport(channel), monotonicNowNs: () => now });
  assert.equal(await grants.renew(), true);
  const tool = { name: "portfolio.read", inputSchema: { type: "object" } };
  let calls = 0, firstSeen!: () => void;
  const firstReceived = new Promise<void>(done => { firstSeen = done; });
  const f = await wireFixture(t, (value, _req, res) => {
    const message = value as { method: string; id: string }; effects.push(message.method);
    if (message.method === "tools/call" && ++calls === 1 && holdFirstCall) {
      res.writeHead(200, { "content-type": "text/event-stream" }); res.write(": held\n\n"); firstSeen(); return;
    }
    if (message.method === "notifications/initialized") { res.writeHead(204); res.end(); return; }
    const result = message.method === "initialize" ? { protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "fixture", version: "1" } }
      : message.method === "tools/list" ? { tools: [tool] } : { content: [{ type: "text", text: "native result" }] };
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
  });
  const session = new OwnedMcpSession(f.http, [tool]);
  await session.initialize(context()); await session.discover(context());
  const owner = new OwnedCallCoordinator({ ...metadata, business, grants, monotonicNowNs: () => now,
    routes: new Map([[tool.name, { session, toolName: tool.name }]]) });
  t.after(async () => {
    await owner.close(); await session.close(); await grants.close(); await channel.close();
    for (const connection of sessions) connection.destroy();
    await new Promise<void>(done => server.close(() => done()));
  });
  const body = { portfolioId: "p-1" }, submitted = request(); submitted.argumentsHash = sha256CanonicalJson(body);
  submitted.trace!.traceId = "1".repeat(32); submitted.trace!.spanId = "2".repeat(16);
  return { ...f, owner, grants, effects, started, firstReceived, authoritySession,
    start: (callId = submitted.callId) => owner.start({ request: { ...submitted, callId }, input: body, startedAtMonotonicNs: started, deadlineMonotonicNs: started + 30_000_000_000n }),
    time(value: bigint) { now = value; } };
}
