import assert from "node:assert/strict";
import { test } from "node:test";
import { fixture, paths, wiped } from "./health-material/test-fixture.js";
import "./health-material/boundary-cases.js";
import "./health-material/lifetime-cases.js";
import "./health-material/ownership-cases.js";

test("valid fixed-slot component load returns the full generated binding and owned token after exact closure", async () => {
  const f = fixture();
  const job = f.start();
  const loaded = await job.completion;
  assert.deepEqual(loaded.binding, f.expected);
  assert.notEqual(loaded.binding, f.expected);
  assert.ok(Object.isFrozen(loaded.binding.config) && Object.isFrozen(loaded.binding.launch));
  assert.equal(loaded.binding.launch.target!.fencingToken, 9007199254740993n);
  assert.ok(loaded.tokenBytes.length === 32 && loaded.tokenBytes.equals(f.token), "exact owned token");
  assert.notEqual(loaded.tokenBytes, f.token);
  assert.equal(f.counts.active, 0); assert.equal(f.counts.closed, 3);
  assert.deepEqual(f.calls.filter(call => call.startsWith("open:")), paths.map(path => `open:${path}`));
  assert.ok(wiped(f.buffers));
  loaded.dispose(); loaded.dispose(); job.cancel();
  assert.ok(wiped([loaded.tokenBytes]));
  assert.ok(f.token.every(value => value === 0xa5), "fixture-owned token unchanged");
  assert.equal(f.time.scheduled, 0); assert.equal(f.counts.fatal, 0);
});
