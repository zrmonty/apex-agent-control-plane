import { createHash } from "node:crypto";
import { create, type JsonValue } from "@bufbuild/protobuf";
import { RuntimeLaunchContextSchema, RuntimeMaterialRole, ReadinessCheckSchema,
  ReadinessCheckStatus, ReadinessReason, encodeJson } from "@apex/contracts";
import { createClock } from "../../telemetry/clock.js";
import { rustConfig } from "../testing/runtime-fixture.js";
import { CHECK_IDS, type ProbeOwner, type ProbeResult, type ReadinessOptions, type ReadinessScheduler } from "./types.js";

export { rustConfig };
// Synthetic COMPONENT metadata over the real Rust config, never Task7 authority.
export function syntheticLaunch() {
  const launch = create(RuntimeLaunchContextSchema, { schemaVersion: 1, target: {
    workspaceId: rustConfig.workspaceId, namespaceId: rustConfig.namespaceId,
    proxyId: rustConfig.proxyId, revisionId: rustConfig.revisionId, generation: rustConfig.generation,
    fencingToken: 9007199254740993n }, configHash: rustConfig.configHash,
    runtimeManifestHash: rustConfig.runtimeManifestHash, imageRef: rustConfig.imageRef,
    processInstanceId: "01992000-0000-7000-8000-000000000001",
    authorityProfileRef: "component-profile", authorityProfileVersion: "v1",
    health: { port: 8081, credentialRef: "secret://deployment/health" },
    materials: [{ role: RuntimeMaterialRole.HEALTH_TOKEN, reference: "secret://deployment/health", version: "v1" }] });
  const json = encodeJson(RuntimeLaunchContextSchema, launch) as Record<string, JsonValue>;
  delete json.launchContextHash;
  function sorted(value: JsonValue): string {
    if (Array.isArray(value)) return `[${value.map(sorted).join(",")}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${sorted(value[k])}`).join(",")}}`;
    return JSON.stringify(value);
  }
  launch.launchContextHash = createHash("sha256").update(sorted(json)).digest("hex");
  return launch;
}

export class ControlledTime {
  ns = 900719925474099300n;
  wall = 9007199254740993n;
  readonly clock = createClock({ monotonicNowNs: () => this.ns,
    wallNow: () => ({ unixUs: this.wall, resolutionNs: 1000n, uncertaintyUs: 7n }), source: "component-clock" });
  private jobs = new Set<{ at: bigint; callback: () => void }>();
  readonly scheduler: ReadinessScheduler = { after: (ms, callback) => {
    const job = { at: this.ns + BigInt(ms) * 1000000n, callback }; this.jobs.add(job);
    return () => { this.jobs.delete(job); };
  } };
  advance(ns: bigint, poll = true): void {
    this.ns += ns;
    if (poll) for (const job of [...this.jobs]) if (job.at <= this.ns && this.jobs.delete(job)) job.callback();
  }
  get scheduled(): number { return this.jobs.size; }
}
export function pass(id: ProbeOwner["id"], expiry: bigint): ProbeResult {
  return { check: create(ReadinessCheckSchema, { id, status: ReadinessCheckStatus.PASS, reason: ReadinessReason.OK }),
    validUntilMonotonicNs: expiry };
}
export function setup() {
  const time = new ControlledTime();
  const launch = syntheticLaunch();
  const stats = { starts: 0, cancels: 0, fatal: 0, current: true };
  const owners: ProbeOwner[] = CHECK_IDS.map(id => ({ id, start: () => {
    stats.starts++;
    return { completion: Promise.resolve(pass(id, time.ns + 20000000000n)), cancel: () => { stats.cancels++; } };
  } }));
  const options: ReadinessOptions = { configuration: rustConfig,
    launchContext: encodeJson(RuntimeLaunchContextSchema, launch), owners, clock: time.clock,
    scheduler: time.scheduler, isCurrent: () => stats.current, onFatal: () => { stats.fatal++; } };
  return { time, launch, stats, owners, options };
}
export async function flush(): Promise<void> { for (let i = 0; i < 16; i++) await Promise.resolve(); }

export function controlled() {
  const f = setup();
  const pending = new Map<number, { resolve(value: ProbeResult): void; reject(error: Error): void }>();
  let active = 0, maximum = 0;
  const owners: ProbeOwner[] = CHECK_IDS.map(id => ({ id, start: () => {
    f.stats.starts++; active++; maximum = Math.max(maximum, active);
    const completion = new Promise<ProbeResult>((resolve, reject) => pending.set(id, { resolve, reject }));
    return { completion, cancel: () => { f.stats.cancels++; } };
  } }));
  function release(id: number, outcome?: ProbeResult): void {
    const operation = pending.get(id);
    if (!operation) throw new Error("controlled operation not active");
    pending.delete(id); active--;
    operation.resolve(outcome ?? pass(id as ProbeOwner["id"], f.time.ns + 20000000000n));
  }
  return { ...f, options: { ...f.options, owners }, pending, release,
    get active() { return active; }, get maximum() { return maximum; } };
}
