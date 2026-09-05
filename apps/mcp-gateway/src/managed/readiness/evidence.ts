import { create, clone } from "@bufbuild/protobuf";
import { ReadinessCheckSchema, ReadinessCheckStatus as Status, ReadinessReason as Reason, type ReadinessCheck } from "@apex/contracts";
import { assertDataTree, assertMessage } from "../runtime-config/boundary.js";
import type { CheckId, ProbeResult } from "./types.js";

export function failed(id: CheckId, reason: Reason): ReadinessCheck {
  return create(ReadinessCheckSchema, { id, status: Status.FAIL, reason });
}

export function evidence(value: unknown, id: CheckId, now: bigint): { check: ReadinessCheck; expiry?: bigint } {
  try {
    assertDataTree(value, true); // No getter, Proxy, hidden property or toJSON execution.
    if (!value || typeof value !== "object" || Object.keys(value).sort().join(",") !== "check,validUntilMonotonicNs") throw new Error();
    const result = value as ProbeResult;
    assertMessage(ReadinessCheckSchema, result.check);
    if (result.check.id !== id || typeof result.validUntilMonotonicNs !== "bigint") throw new Error();
    const { status, reason } = result.check;
    if (status === Status.PENDING) return { check: failed(id, Reason.UNAVAILABLE) };
    if (status === Status.FAIL && reason >= Reason.INVALID && reason <= Reason.SHUTTING_DOWN) return { check: failed(id, reason) };
    if (status !== Status.PASS || reason !== Reason.OK) throw new Error();
    if (result.validUntilMonotonicNs <= now) return { check: failed(id, Reason.STALE) };
    return { check: clone(ReadinessCheckSchema, result.check as ReadinessCheck), expiry: result.validUntilMonotonicNs };
  } catch { return { check: failed(id, Reason.INVALID) }; }
}
