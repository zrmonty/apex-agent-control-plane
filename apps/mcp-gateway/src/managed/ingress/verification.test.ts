import test from "node:test";
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { ingressFixture, initialize, send, until } from "./fixture.js";

for (const ending of ["disconnect", "watchdog"] as const) {
  test(`verification capacity survives ${ending} until the verifier actually settles`, async t => {
    const f = await ingressFixture(t, { requests: 1, bodyMs: 80 });
    const verify = f.options.verifier.verify;
    let release!: () => void, started = 0;
    const held = new Promise<void>(resolve => { release = resolve; });
    f.options.verifier.verify = async token => { started++; await held; return verify(token); };
    const abort = new AbortController();
    const pending = send(f.address.port, { body: initialize, signal: abort.signal });
    void pending.catch(() => {});
    try {
      await until(() => started === 1);
      if (ending === "disconnect") abort.abort();
      await pending.catch(() => {}); await delay(20);
      const next = await send(f.address.port, { body: initialize }).catch(() => undefined);
      assert.equal(started, 1, "abandoned verification must still consume its permit");
      assert.equal(next?.status, 503);
      release(); await delay(20);
      assert.equal((await send(f.address.port, { body: initialize })).status, 200);
    } finally { release(); }
  });
}

for (const cause of ["external", "verifier callback"] as const) {
test(`${cause} ingress closure retains unresolved verification and reports fatal cleanup without claiming drain`, async t => {
  const f = await ingressFixture(t, { cleanupMs: 40 });
  const verify = f.options.verifier.verify;
  let release!: () => void, started = false, closed = false;
  const held = new Promise<void>(resolve => { release = resolve; });
  f.options.verifier.verify = async token => {
    started = true;
    if (cause === "verifier callback") f.ingress.cancel();
    await held; return verify(token);
  };
  void f.ingress.closed.then(() => { closed = true; });
  const pending = send(f.address.port, { body: initialize }); void pending.catch(() => {});
  try {
    await until(() => started);
    f.ingress.cancel();
    await pending.catch(() => {}); await delay(100);
    assert.equal(closed, false, "closed cannot certify an unresolved verifier");
    assert.equal(f.fatals, 1);
    release(); await f.ingress.closed; assert.equal(closed, true);
  } finally { release(); }
});
}
