import { GatewayError } from "../contracts.js";
import { parseAuthenticatedContext } from "../context.js";
import type { ReadonlyRuntimeConfiguration } from "../managed/runtime-config.js";
import { assertRuntimeScope } from "../managed/runtime-types.js";
import { assertExecutableRuntimeConfiguration } from "../managed/executable-capabilities.js";
import type { ManagedExecutor } from "../managed/managed-executor.js";
import type { InboundTokenVerifier } from "../managed/auth.js";

export type ManagedRuntime = Readonly<{
  config: ReadonlyRuntimeConfiguration;
  executor: ManagedExecutor;
  verifier: InboundTokenVerifier;
}>;

/** Metadata validity is not runtime authority. Tasks 8/13 must wire concrete
 * admission and egress enforcement before this factory can construct anything.
 * No secrets, clients, discovery, listener or permissive callbacks are created. */
export async function buildManagedRuntime(
  config: ReadonlyRuntimeConfiguration,
  env: NodeJS.ProcessEnv = process.env,
): Promise<ManagedRuntime> {
  assertExecutableRuntimeConfiguration(config);
  const caller = parseAuthenticatedContext(env);
  assertRuntimeScope(config, caller);
  throw new GatewayError("GOVERNANCE_UNAVAILABLE", "managed runtime enforcement is unavailable safely");
}

export async function discoverUpstreams(
  sessions: ReadonlyMap<string, { discover(): Promise<unknown> }>,
  maxConcurrency: number,
): Promise<void> {
  if (!Number.isSafeInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new GatewayError("INVALID_INPUT", "upstream discovery concurrency rejected safely");
  }
  const pending = [...sessions.values()];
  let next = 0;
  const failures: Array<{ index: number; error: unknown }> = [];
  const workerCount = Math.min(maxConcurrency, pending.length);
  const worker = async (): Promise<void> => {
    while (true) {
      const index = next;
      next += 1;
      const session = pending[index];
      if (session === undefined) {
        return;
      }
      try {
        await session.discover();
      } catch (error: unknown) {
        failures.push({ index, error });
      }
    }
  };
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  if (failures.length > 0) {
    failures.sort((left, right) => left.index - right.index);
    throw failures[0].error;
  }
}
