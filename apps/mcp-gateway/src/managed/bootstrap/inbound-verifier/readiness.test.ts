import assert from "node:assert/strict";
import test from "node:test";
import { jwtVerify } from "jose";
import { createVerifier } from "./owner.js";
import { config, jwks, token, deferred, tick } from "./fixture.js";

test("readiness observes the actual validated key owner without authenticating a synthetic token", async () => {
  let verifications = 0;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: ((...args: Parameters<typeof jwtVerify>) => { verifications++; return jwtVerify(...args); }) as typeof jwtVerify });
  assert.equal(verifier.isReady(), true); assert.equal(verifier.isReady(), true); assert.equal(verifications, 0);
  await verifier.close(); assert.equal(verifier.isReady(), false); assert.equal(verifications, 0);
});

for (const invalid of ["backwards", "wall", "throw", "reentrant-close"]) {
  test(`readiness fails closed permanently for ${invalid}`, async () => {
    let broken = false;
    const verifier = createVerifier(jwks(), config, { monoNs() {
      if (broken && invalid === "throw") throw Error("private clock canary");
      if (broken && invalid === "reentrant-close") void verifier.close();
      return broken && invalid === "backwards" ? 9n : 10n;
    }, wallMs: () => broken && invalid === "wall" ? NaN : Date.now(), verify: jwtVerify });
    assert.equal(verifier.isReady(), true); broken = true; assert.equal(verifier.isReady(), false);
    broken = false; assert.equal(verifier.isReady(), false); await verifier.close();
  });
}

test("readiness observes shutdown without releasing an outstanding signature operation", async () => {
  const hold = deferred<void>();
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: (async (...args: Parameters<typeof jwtVerify>) => { const result = await jwtVerify(...args); await hold.promise; return result; }) as typeof jwtVerify });
  const rejected = assert.rejects(verifier.verify(await token()), /managed inbound verifier refused safely/);
  await tick(); assert.equal(verifier.isReady(), true);
  let drained = false; const closing = verifier.close().then(() => { drained = true; });
  assert.equal(verifier.isReady(), false); await tick(); assert.equal(drained, false);
  hold.resolve(); await rejected; await closing; assert.equal(verifier.isReady(), false);
});
