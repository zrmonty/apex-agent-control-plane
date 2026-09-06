import type { Dependencies, Gate, Relay } from "./types.js";
import { FakeTime, fixtureHash } from "../../stage-reader/fixture.js";
import { deferred } from "../relay-testing.js";
import { fixture, expected, now } from "../configuration/fixture.js";
import type { RelayAddress, EgressRelayOptions, IngressRelayOptions } from "../relay-types.js";
export function setup(durationUs = 60_000_000n) {
  const time = new FakeTime(), gate: Gate = {}, value = fixture();
  const unixMs = Number(now / 1000n), wall = BigInt(unixMs) * 1000n;
  value.not_before_unix_us = (wall - 1n).toString(); value.not_after_unix_us = (wall + durationUs).toString();
  const files = { "guard-config.json": Buffer.from(JSON.stringify(value)) }, manifest = fixtureHash(files);
  let fatals = 0, disposed = 0, loads = 0, cancels = 0;
  const env = { NODE_ENV: "production", HOME: "/tmp/apex", APEX_MCP_PROFILE: "guard", APEX_MCP_GUARD_BOOTSTRAP: "sealed-stage-v1",
    APEX_INSTALLATION_ID: expected.installationId, APEX_PROCESS_INSTANCE_ID: expected.processInstanceId,
    APEX_STAGE_MANIFEST_SHA256: manifest, APEX_NETWORK_BINDING_SHA256: expected.networkBindingSha256,
    APEX_NETWORK_TOPOLOGY_SHA256: expected.networkTopologySha256 };
  const relays: FakeRelay[] = [];
  const deps: Dependencies = { timers: time, unixMs: () => unixMs,
    load(options) {
      loads++; if (options.expectedManifestSha256 !== manifest) throw new Error("fixture digest mismatch");
      return { result: Promise.resolve({ files, manifestSha256: manifest, dispose() { disposed++; } }),
        closed: Promise.resolve(), cancel() { cancels++; } };
    }, ingress(options) { const relay = new FakeRelay(options); relays.push(relay); return relay; },
    egress(options) { const relay = new FakeRelay(options); relays.push(relay); return relay; } };
  return { deps, time, gate, env, value, files, manifest, relays, wall,
    options: { env, onFatal() { fatals++; } }, state: () => ({ fatals, disposed, loads, cancels }) };
}
export class FakeRelay implements Relay {
  private readonly stop = deferred<void>();
  readonly revoked = this.stop.promise;
  bound = false; closes = 0;
  listenHook?: () => Promise<RelayAddress>;
  closeHook?: () => Promise<void>;
  constructor(readonly options: EgressRelayOptions | IngressRelayOptions) {}
  listen(): Promise<RelayAddress> {
    this.bound = true; return this.listenHook?.() ?? Promise.resolve({ address: this.options.bindAddress, port: this.options.port, family: 4 });
  }
  close(): Promise<void> { this.closes++; this.stop.resolve(); return this.closeHook?.() ?? Promise.resolve(); }
  revoke(): void { this.stop.resolve(); }
}
