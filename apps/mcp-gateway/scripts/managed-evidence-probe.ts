// Opt-in cross-language test probe, never a production bootstrap/factory.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { once } from "node:events";
import { connect } from "node:http2";
import { connect as tlsConnect } from "node:tls";
import { ManagedEvidenceBuilder } from "../src/managed/evidence/builder.js";
import { ManagedEvidenceClient } from "../src/managed/evidence/client.js";
import { OwnedEvidenceChannel } from "../src/managed/evidence-channel.js";
import { metadata } from "../src/managed/authority/business-testing.js";
import { example } from "../src/managed/evidence/testing.js";

const [portText, pkiRoot] = process.argv.slice(2), port = Number(portText);
if (!Number.isInteger(port) || port < 1 || port > 65535 || !pkiRoot) throw new Error("invalid test fixture");
const pki = (name: string) => readFileSync(join(pkiRoot, "trusted-host", name));
const socket = tlsConnect({ host: "127.0.0.1", port, servername: "localhost", ca: pki("ca.pem"),
  cert: pki("agent-workload-client.pem"), key: pki("agent-workload-client.key"),
  ALPNProtocols: ["h2"], rejectUnauthorized: true });
socket.on("error", () => {});
await once(socket, "secureConnect");
const session = connect(`https://localhost:${port}`, { settings: { enablePush: false }, createConnection: () => socket });
session.on("error", () => {});
await once(session, "connect");
// Test-only status observation; no payload, headers, or credential diagnostics.
const request = session.request.bind(session);
session.request = (...args: Parameters<typeof request>) => {
  const stream = request(...args);
  for (const event of ["response", "trailers"]) stream.on(event, headers => {
    if (headers["grpc-status"] !== undefined) process.stderr.write(`ingest status ${headers["grpc-status"]}\n`);
    const code = headers["grpc-message"];
    for (const known of ["SECRET_EXPOSURE", "INVALID_STRUCTURE", "INVALID_INTEGRITY", "INVALID_TIMESTAMP", "INVALID_EVENT_ID"])
      if (typeof code === "string" && code.includes(known)) process.stderr.write(`ingest code ${known}\n`);
  });
  return stream;
};
const channel = new OwnedEvidenceChannel(session, "public-test-evidence-token"), client = new ManagedEvidenceClient(channel);
try {
  const builder = new ManagedEvidenceBuilder(metadata);
  for (const [index, us] of [1n, 7n, 999n].entries()) {
    const source = example(us);
    const prepared = builder.prepare({ ...source,
      eventId: `018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e${20 + index}`,
      linkedEventId: `018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e${30 + index}` });
    for (const duplicate of [false, true]) {
      const now = process.hrtime.bigint(), exchange = client.start(prepared, now, now + 5_000_000_000n);
      assert.deepEqual(await exchange.result, { ...prepared, duplicate }); await exchange.closed;
    }
    process.stdout.write(`${us}|${prepared.eventId}|${prepared.eventHash}\n`);
  }
} finally { await client.close(); await channel.close(); }
