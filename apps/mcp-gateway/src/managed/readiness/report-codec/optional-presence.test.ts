import assert from "node:assert/strict";
import test from "node:test";
import { create, clone } from "@bufbuild/protobuf";
import { ProxyStageTimingSchema, ReadinessCheckSchema, RuntimeConfigurationSchema } from "@apex/contracts";
import { assertDataTree, assertMessage } from "../../runtime-config/boundary.js";
import { rustConfig } from "../test-support.js";

test("generated explicit optional uint64 absence differs from exact zero without requiring a wire default", () => {
  const stage = create(ProxyStageTimingSchema);
  assert.equal(stage.durationNs, undefined); assert.equal(stage.clockUncertaintyUs, undefined);
  assertDataTree(stage, true);
  assert.doesNotThrow(() => assertMessage(ProxyStageTimingSchema, stage));
  stage.durationNs = 0n; stage.clockUncertaintyUs = 0n;
  assert.doesNotThrow(() => assertMessage(ProxyStageTimingSchema, stage));
  assert.equal(stage.durationNs, 0n); assert.equal(stage.clockUncertaintyUs, 0n);
});

test("optional scalar support never permits absent implicit fields or invalid present uint64 values", () => {
  const stage = create(ProxyStageTimingSchema, { durationNs: 0n, clockUncertaintyUs: 0n });
  for (const field of ["durationNs", "clockUncertaintyUs"] as const) {
    for (const value of [null, 0, "0", -1n, 1n << 64n]) {
      const mutant = clone(ProxyStageTimingSchema, stage); Object.assign(mutant, { [field]: value });
      assert.throws(() => assertMessage(ProxyStageTimingSchema, mutant));
    }
  }
  for (const field of ["name", "startedAtUnixUs", "durationUs", "otelTraceId", "clockResolutionNs"] as const) {
    const mutant = clone(ProxyStageTimingSchema, stage); Object.assign(mutant, { [field]: undefined });
    assert.throws(() => assertMessage(ProxyStageTimingSchema, mutant));
  }
  const config = clone(RuntimeConfigurationSchema, rustConfig as never);
  for (const field of ["schemaVersion", "approvalMode", "secretRefs", "memoryBytes"] as const) {
    const mutant = clone(RuntimeConfigurationSchema, config); Object.assign(mutant, { [field]: undefined });
    assert.throws(() => assertMessage(RuntimeConfigurationSchema, mutant));
  }
  assert.throws(() => assertMessage(ReadinessCheckSchema, { ...create(ReadinessCheckSchema), status: undefined }));
});
