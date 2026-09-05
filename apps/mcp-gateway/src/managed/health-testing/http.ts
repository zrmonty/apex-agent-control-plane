// Test-only actual fixed-loopback peers, never imported by production.
import { createConnection, type Socket } from "node:net";
import type { TestContext } from "node:test";

export function token(): Buffer { return Buffer.alloc(32, 0x5a); }
export function wire(path = "/readyz", headers = `Host: 127.0.0.1:8081\r\nAuthorization: Bearer ${token().toString("base64url")}`): string {
  return `GET ${path} HTTP/1.1\r\n${headers}\r\nConnection: close\r\n\r\n`;
}
export function requestText(request: string): Promise<{ status: number; headers: Record<string, string>; body: string; raw: string }> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port: 8081 });
    const storage = Buffer.alloc(16384);
    let length = 0, failure: Error | undefined;
    const fuse = setTimeout(() => { failure = new Error("test peer fuse expired"); socket.destroy(); }, 4000);
    socket.once("connect", () => socket.write(request));
    socket.on("data", chunk => {
      if (length + chunk.length > storage.length) { failure = new Error("test peer overflow"); socket.destroy(); return; }
      chunk.copy(storage, length); length += chunk.length;
    });
    socket.on("error", error => { if ((error as NodeJS.ErrnoException).code !== "ECONNRESET") failure = error; });
    socket.once("close", () => {
      clearTimeout(fuse);
      if (failure) { reject(failure); return; }
      const raw = storage.subarray(0, length).toString("utf8"), boundary = raw.indexOf("\r\n\r\n");
      const lines = raw.slice(0, boundary).split("\r\n");
      const headers: Record<string, string> = {};
      for (const line of lines.slice(1)) { const colon = line.indexOf(":"); headers[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim(); }
      resolve({ status: Number(lines[0]?.split(" ")[1] ?? 0), headers, body: boundary < 0 ? "" : raw.slice(boundary + 4), raw });
    });
  });
}
export async function closeSocket(socket: Socket): Promise<void> {
  if (socket.closed) return;
  const closed = new Promise<void>(resolve => socket.once("close", () => resolve()));
  socket.destroy(); await closed;
}
export async function peer(t: TestContext) {
  const socket = createConnection({ host: "127.0.0.1", port: 8081 });
  socket.on("error", () => {});
  const closed = new Promise<void>(resolve => socket.once("close", () => resolve()));
  t.after(() => closeSocket(socket));
  await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
  return { socket, closed };
}
export async function bounded<T>(result: Promise<T>, ms = 3000): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try { return await Promise.race([result, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error("test safety fuse, not component success")), ms); })]); }
  finally { clearTimeout(timer); }
}
