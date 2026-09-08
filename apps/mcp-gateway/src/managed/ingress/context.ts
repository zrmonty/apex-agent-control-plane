import { AsyncLocalStorage } from "node:async_hooks";
import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { HeaderValues } from "../auth.js";
import type { CompiledExecution } from "../compiled-executor.js";
import { refused } from "./request.js";

export interface RequestContext {
  control: boolean;
  readonly original: ClockSnapshot;
  readonly deadline: bigint;
  readonly headers: HeaderValues;
  readonly controller: AbortController;
  readonly executions: Set<CompiledExecution>;
}
export const requestContext = new AsyncLocalStorage<RequestContext>();
/** Abort only ends this wait; execution.closed remains independently owned. */
export function abortable<T>(result: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(refused());
    signal.addEventListener("abort", abort, { once: true });
    void result.then(value => { signal.removeEventListener("abort", abort); resolve(value); },
      () => { signal.removeEventListener("abort", abort); reject(refused()); });
    if (signal.aborted) { signal.removeEventListener("abort", abort); abort(); }
  });
}
