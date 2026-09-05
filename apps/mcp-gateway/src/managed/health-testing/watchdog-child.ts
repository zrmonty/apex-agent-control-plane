// Test-only fault at the actual socket boundary; no production test mode/port.
import { Server, createConnection, type Socket } from "node:net";
import { createClock } from "../../telemetry/clock.js";
import { startHealthServer } from "../health-server.js";
import { fixture } from "../readiness/report-codec/test-support.js";
import { token } from "./http.js";

const actualGrace = process.argv[2] === "actual-grace";
// Distinct failing outcome. Neither this fuse nor a runner timeout is a PASS.
const fuse = setTimeout(() => process.exit(74), actualGrace ? 8000 : 3800);
const originalEmit = Server.prototype.emit;
let owned: Socket | undefined, restoreDestroy: (() => void) | undefined, attempts = 0, connected = false;
Server.prototype.emit = function (event: string | symbol, ...args: unknown[]): boolean {
  if (event === "connection") {
    const address = this.address();
    if (address && typeof address !== "string" && address.port === 8081) {
      owned = args[0] as Socket;
      const destroy = owned.destroy.bind(owned);
      owned.destroy = () => { attempts++; return owned!; };
      restoreDestroy = () => { owned!.destroy = destroy; destroy(); };
    }
  }
  return Reflect.apply(originalEmit, this, [event, ...args]);
};
const f = fixture(), realClock = createClock(); let offset = 0n;
const clock = { now() { const sample = realClock.now(); return { ...sample, monotonicNs: sample.monotonicNs + offset }; } };
const start = performance.now();
const health = await startHealthServer({ codec: f.codec, state: f.monitor, clock, tokenBytes: token(), onFatal() {
  process.stdout.write(JSON.stringify({ fatal: true, connected, attempted: attempts > 0,
    actualGrace, elapsedMs: Math.floor(performance.now() - start), closed: owned?.closed === true }), () => {
    clearTimeout(fuse); process.exit(73);
  });
} });
const client = createConnection({ host: "127.0.0.1", port: 8081 }); client.on("error", () => {});
client.once("connect", () => { connected = true; client.write("G"); });
if (actualGrace) {
  setTimeout(() => { void health.close().catch(() => {}); }, 100);
} else {
  // Keep the real 2s socket deadline. Then simulate a delayed close notification
  // beyond its cleanup grace, without claiming five real elapsed cleanup seconds.
  setTimeout(() => { offset = 5000000000n; restoreDestroy?.(); }, 2150);
}
