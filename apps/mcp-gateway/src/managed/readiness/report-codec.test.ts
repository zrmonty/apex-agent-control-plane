import assert from "node:assert/strict";
import test from "node:test";
import { clone } from "@bufbuild/protobuf";
import { ReadinessReportSchema, type ReadinessReport } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { ReadinessReportCodec } from "./report-codec.js";
import { setup } from "./test-support.js";

test("bound codec round-trips a cold generated report into an independent frozen copy", async () => {
  const f = setup(), monitor = new ReadinessMonitor(f.options);
  const codec = new ReadinessReportCodec({ config: f.options.configuration, launch: f.launch });
  const source = clone(ReadinessReportSchema, monitor.snapshot() as ReadinessReport);
  const original = structuredClone(source), text = codec.encode(source), decoded = codec.decode(text);
  assert.deepEqual(decoded, original); assert.notEqual(decoded, source);
  assert.equal(decoded.target!.fencingToken, 9007199254740993n);
  assert.equal(decoded.observedAtUnixUs, 0n); assert.equal(decoded.ready, false);
  assert.ok(Object.isFrozen(decoded) && Object.isFrozen(decoded.target) && Object.isFrozen(decoded.checks[0]));
  assert.equal(Object.isFrozen(source), false); assert.equal(Object.isFrozen(source.target), false);
  source.target!.workspaceId = "CALLER_MUTATION";
  assert.equal(decoded.target!.workspaceId, original.target!.workspaceId);
  assert.equal(codec.encode(decoded), text);
  await monitor.close();
});
