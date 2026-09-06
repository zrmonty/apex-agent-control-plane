import assert from "node:assert/strict";
import test from "node:test";
import { startOwnedStage } from "./job.js";
import { ownerFixture, tick, isStatic } from "./fixture.js";
import { startLoad } from "../../stage-reader/job.js";
import { FakeFiles, deferred } from "../../stage-reader/fixture.js";
import { copyStageRole, disposeStageOwner } from "../stage-owner.js";

// Real reader/job/parser composition, deterministic fake OS only. Native OS
// evidence is separately recorded by the scoped read-only Linux recipe.
test("real reader closes OS handles but owner retains original allocations until dispose", async () => {
  const f = ownerFixture(), fs = new FakeFiles(); fs.files = f.stage.files;
  const h = startOwnedStage(f, options => startLoad(options, fs, f.time, {}), f.time, f.gate);
  const owner = await h.result;
  assert.equal(fs.paths.size, 0); assert.equal(fs.closed.length, fs.opened.length); assert.equal(fs.directoryClosed, 1);
  const original = fs.readBuffers.get("/apex/runtime/governance-key")!;
  assert(original.some(b => b !== 0)); const copy = copyStageRole(owner, "governance-key");
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  disposeStageOwner(owner); await h.closed;
  for (const bytes of fs.readBuffers.values()) assert(bytes.every(b => b === 0));
  assert(copy.some(b => b !== 0)); copy.fill(0);
});
test("real reader held open stays physically owned through cancellation and fatal deadline", async () => {
  const f = ownerFixture(), fs = new FakeFiles(), held = deferred<void>(); fs.files = f.stage.files;
  fs.hook = (kind, path) => kind === "open" && path === "/apex/runtime/governance-key" ? held.promise : undefined;
  const h = startOwnedStage(f, options => startLoad(options, fs, f.time, {}), f.time, f.gate);
  await tick(); h.cancel(); await assert.rejects(h.result, isStatic);
  let closed = false; void h.closed.then(() => { closed = true; }); f.time.advance(5000); await tick();
  assert.equal(f.counts.fatals, 1); assert.equal(closed, false);
  await assert.rejects(startOwnedStage(f, f.load, f.time, f.gate).result, isStatic);
  held.resolve(); await h.closed; assert.equal(fs.paths.size, 0);
  for (const bytes of fs.readBuffers.values()) assert(bytes.every(b => b === 0));
});
test("real reader failed native-close analogue never releases owner slot", async () => {
  const f = ownerFixture(), fs = new FakeFiles(); fs.files = f.stage.files;
  fs.hook = (kind, path) => { if (kind === "close" && path === "/apex/runtime/governance-key") throw new Error("CLOSE-CANARY"); };
  const h = startOwnedStage(f, options => startLoad(options, fs, f.time, {}), f.time, f.gate);
  await assert.rejects(h.result, isStatic); await tick(); f.time.advance(5000); await tick();
  assert.equal(f.counts.fatals, 1); assert.equal(fs.paths.size, 1);
  let closed = false; void h.closed.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  await assert.rejects(startOwnedStage(f, f.load, f.time, f.gate).result, isStatic);
});
test("reader clock uses bootstrap entry after setup time, not a fresh five seconds", async () => {
  const f = ownerFixture(), fs = new FakeFiles(); fs.files = f.stage.files;
  let samples = 0;
  f.time.now = () => { if (++samples === 2) f.time.time = 4999000000n; return f.time.time; };
  fs.hook = (kind, path) => {
    if (kind === "read" && path === "/apex/runtime/runtime-revision.json") f.time.time = 5000000000n;
  };
  const h = startOwnedStage(f, options => startLoad(options, fs, f.time, {}), f.time, f.gate);
  await assert.rejects(h.result, isStatic); await h.closed;
  assert.equal(fs.paths.size, 0); assert.equal(f.counts.fatals, 0);
});
