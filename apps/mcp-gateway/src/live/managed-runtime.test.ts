import assert from "node:assert/strict";
import test from "node:test";

import type { UpstreamSession } from "../managed/upstream.js";
import { discoverUpstreams } from "./managed-runtime.js";

test("discovers upstream sessions with bounded concurrency", async () => {
  let active = 0;
  let peak = 0;
  const discovered: string[] = [];
  const sessions = new Map<string, UpstreamSession>();

  for (const id of ["one", "two", "three", "four", "five"]) {
    sessions.set(id, {
      async discover() {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        discovered.push(id);
        active -= 1;
        return { upstreamId: id, schemaHash: id, tools: [] };
      },
      async call() { return {}; },
      async close() {},
    });
  }

  await discoverUpstreams(sessions, 2);

  assert.equal(peak, 2);
  assert.deepEqual([...discovered].sort(), ["five", "four", "one", "three", "two"]);
});
