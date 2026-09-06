import { once } from "node:events";
import { createServer } from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import type { TestContext } from "node:test";
import { certificate, key } from "../authority/testing-tls.js";
import { GuardEgressRelay } from "../guard/relay-server.js";
import { GuardedTlsConnector } from "../guard/tls-connector.js";
import { OwnedHttpClient } from "../guard/http-owner.js";
import { OwnedMcpWire, type WireContext } from "./client.js";

/** Real native guard + TLS + HTTP + MCP component chain. TEST ONLY loopback
 * policy isn't protected deployment or Docker/kernel-confinement evidence. */
export async function wireFixture(t: TestContext, handle: (value: unknown, req: IncomingMessage, res: ServerResponse) => void,
  now?: () => bigint) {
  const sockets = new Set<Duplex>();
  const server = createServer({ key, cert: certificate, ca: certificate, requestCert: true,
    rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", chunk => chunks.push(chunk));
    req.on("end", () => { const body = Buffer.concat(chunks).toString(); handle(body ? JSON.parse(body) : undefined, req, res); });
  });
  server.on("connection", s => { sockets.add(s); s.on("error", () => {}); s.once("close", () => sockets.delete(s)); });
  server.on("tlsClientError", () => {});
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as AddressInfo).port;
  const relay = new GuardEgressRelay({ bindAddress: "127.0.0.1", port: 0, gatewayAddress: "127.0.0.1",
    outboundAddress: "127.0.0.1", lookup: (_host, done) => done(null, [{ address: "127.0.0.1", family: 4 }]),
    policy: { select(host, selectedPort) {
      if (host !== "grpc-contract-test" || selectedPort !== port) throw new Error("test selector refused");
      return { host, port, pin(answers) {
        if (answers.length !== 1 || answers[0] !== "127.0.0.1") throw new Error("test address refused");
        return { host, port, address: "127.0.0.1", family: 4 };
      } };
    } },
  });
  const address = await relay.listen();
  const connector = new GuardedTlsConnector(address, [{ id: "upstream", host: "grpc-contract-test", port,
    authentication: "mutual_tls", ca: certificate, cert: certificate, key, alpn: "http/1.1" }]);
  const http = new OwnedHttpClient(connector, { destinationId: "upstream", url: `https://grpc-contract-test:${port}/mcp` });
  const wire = new OwnedMcpWire(http, now);
  t.after(async () => {
    await wire.close(); await http.close(); await connector.close(); await relay.close();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(done => server.close(() => done()));
  });
  return { wire, http, connector, relay };
}
export function context(beforeWrite: () => void = () => {}): WireContext {
  const startedAtMonotonicNs = process.hrtime.bigint();
  return { startedAtMonotonicNs, deadlineMonotonicNs: startedAtMonotonicNs + 30_000_000_000n, beforeWrite };
}
