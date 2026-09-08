import type { Clock } from "../telemetry/clock.js";
import type { InboundTokenVerifier } from "./auth.js";
import type { StageOwner } from "./bootstrap/stage-owner.js";
import type { RuntimeMaterials } from "./bootstrap/runtime-materials.js";
import type { CompiledManagedExecutor } from "./compiled-executor.js";
import { startIngress } from "./ingress/owner.js";

export interface ManagedIngressOptions {
  readonly stage: StageOwner;
  readonly materials: RuntimeMaterials;
  readonly verifier: InboundTokenVerifier;
  readonly executor: CompiledManagedExecutor;
  readonly clock: Clock;
  readonly isAdmitting: () => boolean;
  readonly onFatal: () => void;
}
export interface ManagedIngress {
  readonly result: Promise<{ host: string; port: number }>;
  /** Resolves after listener/session/execution closure and actual verifier settlement. */
  readonly closed: Promise<void>;
  cancel(): void;
}

/** Protected stage inputs only. The loopback test listener is a separate private boundary. */
export function startManagedIngress(options: ManagedIngressOptions): ManagedIngress {
  return startIngress(options, { address(stage) {
    if (!stage.network) throw new Error("managed ingress refused safely");
    return { host: stage.network.gatewayAddress, port: 8080 };
  } });
}
