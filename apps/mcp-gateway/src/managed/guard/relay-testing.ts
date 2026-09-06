// TEST ONLY loopback networking; never a production policy or resolver fallback.
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer, createConnection, type Socket } from "node:net";
import type { TestContext } from "node:test";
import type { GuardEgressPolicy } from "./egress-policy.js";
import type { RelayAddress } from "./relay-types.js";

export const ack = Buffer.from("HTTP/1.1 200 Connection Established\r\n\r\n");
export const handshake = (host: string, port: number) => `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`;
export function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve };
}
export async function peer(t: TestContext, handle: (socket: Socket) => void = socket => socket.pipe(socket),
  address = "127.0.0.1", port = 0) {
  const sockets = new Set<Socket>(); let connections = 0;
  const server = createServer(socket => {
    connections++; sockets.add(socket); socket.on("error", () => {});
    socket.on("close", () => sockets.delete(socket)); handle(socket);
  });
  await new Promise<void>((yes, no) => { server.once("error", no); server.listen(port, address, yes); });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(done => server.close(() => done()));
  });
  return { port: (server.address() as { port: number }).port, address, sockets, get connections() { return connections; } };
}
export async function client(t: TestContext, endpoint: RelayAddress, source = "127.0.0.1") {
  const socket = createConnection({ host: endpoint.address, port: endpoint.port, localAddress: source,
    family: endpoint.family, autoSelectFamily: false });
  socket.on("error", () => {});
  const closed = new Promise<void>(done => socket.once("close", () => done()));
  t.after(async () => { socket.destroy(); await closed; });
  await once(socket, "connect");
  return { socket, closed };
}
export function read(socket: Socket, size: number): Promise<Buffer> {
  return new Promise((yes, no) => {
    let value = Buffer.alloc(0);
    const close = () => { cleanup(); no(new Error("peer closed before expected bytes")); };
    const data = (bytes: Buffer) => {
      value = Buffer.concat([value, bytes]);
      if (value.length >= size) { cleanup(); assert.equal(value.length, size); yes(value); }
    };
    const cleanup = () => { socket.off("data", data); socket.off("close", close); };
    socket.on("data", data); socket.once("close", close);
  });
}
export function testPolicy(port: number, host = "allowed.example.test"): GuardEgressPolicy {
  return { select(selectedHost, selectedPort) {
    if (selectedHost !== host || selectedPort !== port) throw new Error("POLICY_CANARY");
    return Object.freeze({ host, port, pin(answers: readonly string[]) {
      if (!answers.length || answers.some(address => address !== "127.0.0.1")) throw new Error("PIN_CANARY");
      return Object.freeze({ host, port, address: "127.0.0.1", family: 4 as const });
    } });
  } };
}
