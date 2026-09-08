import { randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { create } from "@bufbuild/protobuf";
import { ReadinessCheckId as Check, ReadinessCheckSchema, ReadinessCheckStatus as Status, ReadinessReason as Reason,
  RuntimeLaunchContextSchema, encodeJson, type RuntimeLaunchContext } from "@apex/contracts";
import { ReadinessMonitor, type ProbeHandle, type ReadinessBinding, type ProbeOwner } from "../readiness.js";
import type { BusinessExchange } from "../authority/business-types.js";
import type { RuntimeCoreOptions } from "../runtime-core.js";
import type { RuntimeCore } from "./types.js";
import type { RuntimeGrants } from "./grants.js";
import type { Timers } from "../stage-reader/types.js";
import { refused } from "./types.js";
import { isDependencyUnavailable } from "../authority/dependency-failure.js";

type Dependencies = Pick<RuntimeCore, "verifier" | "business" | "startNetworkReadiness" | "startEvidenceReadiness"> & {
  grants: RuntimeGrants;
  /** Checks genuine stage/material ownership, both clocks and raw grant continuity. */
  current(): bigint;
  credentialExpiry: bigint;
  upstream(started: bigint, deadline: bigint): BusinessExchange<void>;
  timers: Timers;
};
const LIFETIME = 10_000_000_000n, DEADLINE = 2_000_000_000n;

/** Internal composition only: CoreJob supplies its actual owned dependencies.
 * No public factory accepts caller-created probes as production evidence. */
export function createCoreReadiness(options: RuntimeCoreOptions, deps: Dependencies): ReadinessMonitor {
  const { config, launch } = options.stage.documents;
  const compared = new WeakSet<ReadinessBinding>();
  // Before the first completed all-nine PASS, ordinary exchange failure may
  // converge after exact closure. Continuity loss remains independently latched
  // by current()/the monitor; a serving generation never recovers dependency loss.
  let failed = false;
  let monitor: ReadinessMonitor;
  const current = (binding: ReadinessBinding) => {
    if (failed) return false;
    try { if (deps.verifier.isReady() !== true) return false; } catch { return false; }
    deps.current();
    if (!compared.has(binding)) {
      if (!isDeepStrictEqual(binding.config, config) || !isDeepStrictEqual(binding.launch, launch)) return false;
      // The monitor owns a recursively frozen complete copy, not a hash-only join.
      compared.add(binding);
    }
    return true;
  };
  const owner = (id: ProbeOwner["id"], start?: (at: bigint, deadline: bigint) => BusinessExchange<unknown>,
    expiry?: (value: unknown, at: bigint) => bigint): ProbeOwner => Object.freeze({ id, start(binding: ReadinessBinding): ProbeHandle {
    if (!current(binding)) throw refused();
    const at = deps.current(), ceiling = at + LIFETIME < deps.credentialExpiry ? at + LIFETIME : deps.credentialExpiry;
    if (ceiling <= at) throw refused();
    if (id === Check.INBOUND_AUTH && !deps.verifier.isReady()) throw refused();
    // Reserve immutable original expiry before I/O or a concurrent grant renewal.
    const grantExpiry = id === Check.ADMISSION ? deps.grants.authoritySnapshot().validUntilMonotonicNs : undefined;
    if (id === Check.ADMISSION && (grantExpiry === undefined || grantExpiry <= at)) throw refused();
    let exchange: BusinessExchange<unknown> | undefined;
    try { exchange = start?.(at, at + DEADLINE); }
    catch (error) {
      if (monitor.hasBeenReady || !isDependencyUnavailable(error)) failed = true;
      throw refused();
    }
    let cancelled = false;
    const cancel = () => {
      if (cancelled) return;
      cancelled = true;
      try { exchange?.cancel(); } catch { /* Physical completion remains owned. */ }
    };
    const completion = (async () => {
      let value: unknown;
      try { value = await exchange?.result; }
      catch (error) {
        // Invalidate synchronously before joining physical closure. Completion
        // still owns the monitor permit until the exact exchange terminates.
        if (monitor.hasBeenReady || !isDependencyUnavailable(error)) failed = true;
        throw refused();
      }
      finally {
        // A decoded result is not physical termination. Close exact stream and
        // retain the monitor permit if transport cleanup rejects or never ends.
        if (exchange) {
          try { exchange.cancel(); } catch { /* Retain exact closure below. */ }
          await exchange.closed.then(() => {}, () => new Promise<void>(() => {}));
        }
      }
      if (cancelled || !current(binding)) throw refused();
      const observedExpiry = expiry ? expiry(value, at) : grantExpiry ?? ceiling;
      const validUntilMonotonicNs = observedExpiry < ceiling ? observedExpiry : ceiling;
      if (typeof observedExpiry !== "bigint" || validUntilMonotonicNs <= deps.current()) throw refused();
      return Object.freeze({ check: Object.freeze(create(ReadinessCheckSchema, { id, status: Status.PASS, reason: Reason.OK })),
        validUntilMonotonicNs });
    })();
    void completion.catch(() => {});
    return Object.freeze({ completion, cancel });
  } });
  const observationExpiry = (value: unknown) => (value as { validUntilMonotonicNs: bigint }).validUntilMonotonicNs;
  monitor = new ReadinessMonitor({ configuration: config,
    launchContext: encodeJson(RuntimeLaunchContextSchema, launch as RuntimeLaunchContext), clock: options.clock,
    isCurrent: current, onFatal: options.onFatal, scheduler: deps.timers, owners: [
      owner(Check.CONFIG), owner(Check.LAUNCH), owner(Check.MATERIAL), owner(Check.INBOUND_AUTH),
      owner(Check.UPSTREAM_CATALOG, deps.upstream),
      owner(Check.GOVERNANCE, () => deps.business.startPolicy(randomBytes(32).toString("hex"))),
      owner(Check.EVIDENCE_ADMISSION, deps.startEvidenceReadiness, observationExpiry),
      owner(Check.NETWORK, deps.startNetworkReadiness, observationExpiry), owner(Check.ADMISSION),
    ] });
  return monitor;
}
