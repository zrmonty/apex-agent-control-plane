import test from "node:test";
import assert from "node:assert/strict";
import { ReadinessCheckId as Check } from "@apex/contracts";
import { ReadinessMonitor } from "../readiness.js";
import { setup } from "./test-support.js";

for (const loss of ["dependency", "expiry"] as const) {
  test(`first published readiness makes subsequent ${loss} loss irreversible`, async () => {
    const f = setup();
    let fail = false;
    const monitor = new ReadinessMonitor({ ...f.options, owners: f.owners.map(owner => ({ ...owner, start(binding) {
      if (fail && owner.id === Check.NETWORK) throw Error("unavailable fixture");
      return owner.start(binding);
    } })) });
    try {
      assert.equal((await monitor.checkStartup()).ready, true);
      f.time.advance(loss === "expiry" ? 10000000000n : 5000000000n);
      if (loss === "dependency") {
        fail = true;
        assert.equal((await monitor.checkStartup()).ready, false);
        fail = false;
      } else assert.equal(monitor.snapshot().ready, false);
      f.time.advance(5000000000n);
      const starts = f.stats.starts;
      assert.equal((await monitor.checkStartup()).ready, false);
      assert.equal(f.stats.starts, starts, "lost serving generation must never dispatch replacement probes");
    } finally { await monitor.close(); }
  });
}
