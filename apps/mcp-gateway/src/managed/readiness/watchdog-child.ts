// Test-only single-process fixture, never a production root or readiness owner.
import { createServer, createConnection } from "node:net";
import { ReadinessCheckId } from "@apex/contracts";
import { createClock } from "../../telemetry/clock.js";
import { ReadinessMonitor, type ProbeOwner, type ProbeResult } from "../readiness.js";
import { CHECK_IDS } from "./types.js";
import { setup, pass } from "./test-support.js";

// Independent broken-component fuse; exit 74 must fail the parent's assertion.
setTimeout(() => process.exit(74), 1500).unref();
const server = createServer(socket => socket.on("error", () => {}));
await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
if (!address || typeof address === "string") throw new Error("fixture listener failed");
const f = setup(), clock = createClock();
let connected = false, cancellations = 0;
const owners: ProbeOwner[] = CHECK_IDS.map(id => ({ id, start: () => {
  if (id !== ReadinessCheckId.NETWORK) return { completion: Promise.resolve(pass(id, clock.now().monotonicNs + 10000000000n)), cancel: () => {} };
  const socket = createConnection({ host: "127.0.0.1", port: address.port });
  socket.on("error", () => {}); socket.once("connect", () => { connected = true; });
  // Deliberately uncooperative actual open I/O, not just a logical promise race.
  const completion = new Promise<ProbeResult>(() => {});
  return { completion, cancel: () => { cancellations++; } };
} }));
const monitor = new ReadinessMonitor({ ...f.options, clock, scheduler: undefined, owners,
  // Explicit shortened COMPONENT limits only; no env/config/profile override.
  limits: { deadlineMs: 30, cleanupMs: 70 }, onFatal: () => {
    process.stdout.write(JSON.stringify({ fatal: true, ready: monitor.snapshot().ready, cancellations, connected }), () => process.exit(73));
  } });
await monitor.checkStartup();
