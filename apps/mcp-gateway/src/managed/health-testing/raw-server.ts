import { createServer, type Socket } from "node:net";
import type { TestContext } from "node:test";
import { bounded } from "./http.js";

export async function rawServer(t: TestContext, reply: (socket: Socket, original: string) => void) {
  const sockets = new Set<Socket>();
  const stats = { connections: 0, requests: 0, request: "" };
  const server = createServer(socket => {
    stats.connections++; sockets.add(socket);
    socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket));
    const bytes = Buffer.alloc(4097); let length = 0, replied = false;
    socket.on("data", chunk => {
      if (replied) return;
      if (length + chunk.length > bytes.length) { socket.destroy(); return; }
      chunk.copy(bytes, length); length += chunk.length;
      if (bytes.subarray(0, length).includes("\r\n\r\n")) {
        replied = true; stats.requests++; stats.request = bytes.subarray(0, length).toString("latin1");
        reply(socket, stats.request);
      }
    });
  });
  let closing: Promise<void> | undefined;
  const close = () => closing ??= bounded(new Promise<void>(resolve => {
    const ended = [...sockets].map(socket => new Promise<void>(done => { socket.once("close", done); socket.destroy(); }));
    server.close(() => { void Promise.all(ended).then(() => resolve()); });
  }));
  t.after(close);
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(8081, "127.0.0.1", resolve); });
  return { close, sockets, stats };
}

export function response(body: string | Buffer, extra: readonly string[] = [], status = "200 OK"): Buffer {
  const bytes = Buffer.from(body);
  return Buffer.concat([Buffer.from(`HTTP/1.1 ${status}\r\nContent-Type: application/json\r\nContent-Length: ${bytes.length}\r\nCache-Control: no-store\r\nConnection: close\r\n${extra.length ? `${extra.join("\r\n")}\r\n` : ""}\r\n`), bytes]);
}
