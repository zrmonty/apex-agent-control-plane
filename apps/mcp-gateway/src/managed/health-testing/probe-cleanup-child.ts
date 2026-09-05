// Real fixed-loopback I/O with a deliberately unresponsive client destroy hook.
import { createServer, Socket } from "node:net";
import { probeHealth } from "../../health-probe.js";
import { createClock } from "../../telemetry/clock.js";
import { completed } from "../readiness/report-codec/test-support.js";
import { response } from "./raw-server.js";
import { token } from "./http.js";

const fuse = setTimeout(() => process.exit(74), 2500);
const f = await completed(), body = response(f.codec.encode(f.report));
const serverSockets = new Set<Socket>();
const server = createServer(socket => {
  serverSockets.add(socket); socket.on("error", () => {});
  socket.once("close", () => serverSockets.delete(socket));
  socket.once("data", () => socket.end(body));
});
await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(8081, "127.0.0.1", resolve); });
const originalEmit = Socket.prototype.emit;
let owned: Socket | undefined, restore: (() => void) | undefined, attempts = 0;
Socket.prototype.emit = function (event: string | symbol, ...args: unknown[]): boolean {
  if (event === "connect" && this.remotePort === 8081) {
    owned = this;
    const destroy = this.destroy.bind(this);
    this.destroy = () => { attempts++; return this; };
    restore = () => { this.destroy = destroy; destroy(); };
  }
  return Reflect.apply(originalEmit, this, [event, ...args]);
};
const start = performance.now();
const result = await probeHealth({ codec: f.codec, tokenBytes: token(), clock: createClock() });
const elapsedMs = Math.floor(performance.now() - start), beforeRestoreClosed = owned?.closed === true;
const closed = new Promise<void>(resolve => owned!.once("close", () => resolve()));
restore?.(); await closed;
await new Promise<void>(resolve => server.close(() => resolve())); await f.monitor.close();
process.stdout.write(JSON.stringify({ result, elapsedMs, beforeRestoreClosed, attempted: attempts > 0,
  closed: owned?.closed === true, serverSockets: serverSockets.size }), () => { clearTimeout(fuse); process.exit(73); });
