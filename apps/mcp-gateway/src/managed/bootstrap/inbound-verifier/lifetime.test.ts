import assert from "node:assert/strict";
import test from "node:test";
import { jwtVerify } from "jose";
import { createVerifier } from "./owner.js";
import { config, jwks, token, deferred, tick, claims, rawToken } from "./fixture.js";
const refused = (e: unknown) => e instanceof Error && e.message === "managed inbound verifier refused safely" && e.cause === undefined;

for (const clock of ["monoNs", "wallMs"] as const) {
  test(`throwing ${clock} permanently closes verifier before further crypto`, async () => {
    let broken = true, jobs = 0;
    const dependencies = { monoNs() { if (clock === "monoNs" && broken) throw Error("CLOCK-CANARY"); return 0n; },
      wallMs() { if (clock === "wallMs" && broken) throw Error("CLOCK-CANARY"); return Date.now(); },
      verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify };
    const verifier = createVerifier(jwks(), config, dependencies), signed = await token();
    await assert.rejects(verifier.verify(signed), refused); broken = false;
    try { await assert.rejects(verifier.verify(signed), refused); assert.equal(jobs, 0); }
    finally { await verifier.close(); }
  });
}
test("clock close reentry at precrypto fence cannot start native work", async () => {
  let samples = 0, jobs = 0;
  const verifier = createVerifier(jwks(), config, { monoNs() { if (++samples === 2) void verifier.close(); return 0n; },
    wallMs: Date.now, verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify });
  await assert.rejects(verifier.verify(await token()), refused); await verifier.close(); assert.equal(jobs, 0);
});

test("128 actual held cryptographic jobs saturate capacity; close waits for all settlements and forbids late authentication", async () => {
  const holds = Array.from({ length: 128 }, () => deferred<void>()); let jobs = 0;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: (async (...args: Parameters<typeof jwtVerify>) => {
      const hold = holds[jobs++], result = await jwtVerify(...args); await hold.promise; return result;
    }) as typeof jwtVerify });
  const signed = await token();
  const pending = Array.from({ length: 128 }, () => assert.rejects(verifier.verify(signed), refused));
  assert.equal(jobs, 128); await assert.rejects(verifier.verify(signed), refused); assert.equal(jobs, 128);
  const closed = verifier.close(); assert.equal(verifier.close(), closed);
  let done = false; void closed.then(() => { done = true; });
  for (let i = 0; i < 127; i++) holds[i].resolve();
  await Promise.all(pending.slice(0, 127)); await tick(); assert.equal(done, false);
  await assert.rejects(verifier.verify(signed), refused); assert.equal(jobs, 128);
  holds[127].resolve(); await Promise.all(pending); await closed; assert.equal(done, true);
});
test("only an actual settled job frees a concurrency slot while still open", async () => {
  const holds = Array.from({ length: 129 }, () => deferred<void>()); let jobs = 0;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: (async (...args: Parameters<typeof jwtVerify>) => {
      const hold = holds[jobs++], result = await jwtVerify(...args); await hold.promise; return result;
    }) as typeof jwtVerify });
  const signed = await token();
  const pending = Array.from({ length: 128 }, () => verifier.verify(signed));
  await assert.rejects(verifier.verify(signed), refused); holds[0].resolve(); assert.equal((await pending[0]).subject, "operator:alice");
  const next = verifier.verify(signed); assert.equal(jobs, 129);
  for (const hold of holds) hold.resolve(); await Promise.all([...pending, next]); await verifier.close();
});
for (const phase of ["pre", "post"] as const) for (const excess of [0n, 1000n, 7000n, 999000n]) {
  test(`${phase} crypto exact original5s +${excess}ns rejects`, async () => {
    let samples = 0, jobs = 0;
    const verifier = createVerifier(jwks(), config, { monoNs: () => ++samples >= (phase === "pre" ? 2 : 3) ? 5000000000n + excess : 0n,
      wallMs: Date.now, verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify });
    await assert.rejects(verifier.verify(await token()), refused); await verifier.close(); assert.equal(jobs, phase === "pre" ? 0 : 1);
  });
}
test("one nanosecond inside deadline succeeds, while expiry does not release held native work", async () => {
  let mono = 0n;
  const hold = deferred<void>();
  const verifier = createVerifier(jwks(), config, { monoNs: () => mono, wallMs: Date.now,
    verify: (async (...args: Parameters<typeof jwtVerify>) => { const result = await jwtVerify(...args); await hold.promise; return result; }) as typeof jwtVerify });
  const result = verifier.verify(await token()); mono = 4999999999n; hold.resolve();
  assert.equal((await result).subject, "operator:alice"); await verifier.close();
  const held = deferred<void>(); mono = 0n;
  const second = createVerifier(jwks(), config, { monoNs: () => mono, wallMs: Date.now,
    verify: (async (...args: Parameters<typeof jwtVerify>) => { const output = await jwtVerify(...args); await held.promise; return output; }) as typeof jwtVerify });
  const late = assert.rejects(second.verify(await token()), refused); mono = 5000000000n;
  let finished = false; const closed = second.close(); void closed.then(() => { finished = true; });
  await tick(); assert.equal(finished, false); held.resolve(); await late; await closed;
});
test("postcrypto expiry and iat/nbf are checked against the new wall sample without leeway", async () => {
  for (const field of ["exp", "nbf", "iat"]) {
    let wall = 1000000;
    const payload = { ...claims(), exp: field === "exp" ? 1001 : 2000, [field]: field === "exp" ? 1001 : 1000 };
    const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: () => wall,
      verify: (async (...args: Parameters<typeof jwtVerify>) => { const result = await jwtVerify(...args); wall = field === "exp" ? 1001000 : 999999; return result; }) as typeof jwtVerify });
    await assert.rejects(verifier.verify(rawToken('{"alg":"ES256","kid":"fixture-ec"}', JSON.stringify(payload))), refused);
    await verifier.close();
  }
});
for (const phase of [1, 2, 3]) for (const clock of ["monoNs", "wallMs"] as const) {
  test(`clock exception at sample${phase}/${clock} permanently closes and contains crypto`, async () => {
    let calls = 0;
    const dependencies = { monoNs() { if (clock === "monoNs" && ++calls === phase) throw Error("SECRET-CLOCK"); return 0n; },
      wallMs() { if (clock === "wallMs" && ++calls === phase) throw Error("SECRET-CLOCK"); return Date.now(); }, verify: jwtVerify };
    const verifier = createVerifier(jwks(), config, dependencies), signed = await token();
    await assert.rejects(verifier.verify(signed), refused); await verifier.close(); await assert.rejects(verifier.verify(signed), refused);
  });
}
test("crypto rejection after close remains static and physical settlement releases closure", async () => {
  const hold = deferred<void>(), verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: (async () => { await hold.promise; throw Error("CRYPTO-CANARY"); }) as typeof jwtVerify });
  const result = assert.rejects(verifier.verify(await token()), refused), closed = verifier.close();
  let finished = false; void closed.then(() => { finished = true; }); await tick(); assert.equal(finished, false);
  hold.resolve(); await result; await closed;
});
test("synchronous crypto throw frees only that job and does not poison valid future tokens", async () => {
  let fail = true;
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: ((...args: Parameters<typeof jwtVerify>) => { if (fail) throw Error("CANARY"); return jwtVerify(...args); }) as typeof jwtVerify });
  const signed = await token(); await assert.rejects(verifier.verify(signed), refused); fail = false;
  assert.equal((await verifier.verify(signed)).subject, "operator:alice"); await verifier.close();
});
for (const [clock, value] of [["monoNs", -1n], ["monoNs", 0], ["monoNs", undefined], ["wallMs", -1],
  ["wallMs", NaN], ["wallMs", Infinity], ["wallMs", 0.1], ["wallMs", 253402300800000]] as const) {
  test(`invalid ${clock} sample ${String(value)} permanently closes`, async () => {
    let invalid = true, jobs = 0;
    const verifier = createVerifier(jwks(), config, {
      monoNs: () => invalid && clock === "monoNs" ? value as bigint : 0n,
      wallMs: () => invalid && clock === "wallMs" ? value as number : Date.now(),
      verify: ((...args: Parameters<typeof jwtVerify>) => { jobs++; return jwtVerify(...args); }) as typeof jwtVerify });
    const signed = await token(); await assert.rejects(verifier.verify(signed), refused); invalid = false;
    await assert.rejects(verifier.verify(signed), refused); await verifier.close(); assert.equal(jobs, 0);
  });
}
test("regressing monotonic clock closes verifier across jobs", async () => {
  let mono = 10n;
  const verifier = createVerifier(jwks(), config, { monoNs: () => mono, wallMs: Date.now, verify: jwtVerify });
  const signed = await token(); await verifier.verify(signed); mono = 9n;
  await assert.rejects(verifier.verify(signed), refused); mono = 11n;
  await assert.rejects(verifier.verify(signed), refused); await verifier.close();
});
test("close reentry inside native dispatch owns the returned job until settlement", async () => {
  const hold = deferred<void>();
  const verifier = createVerifier(jwks(), config, { monoNs: () => 0n, wallMs: Date.now,
    verify: (async (...args: Parameters<typeof jwtVerify>) => {
      void verifier.close(); const result = await jwtVerify(...args); await hold.promise; return result;
    }) as typeof jwtVerify });
  const result = assert.rejects(verifier.verify(await token()), refused); let closed = false;
  const closing = verifier.close(); void closing.then(() => { closed = true; }); await tick(); assert.equal(closed, false);
  hold.resolve(); await result; await closing;
});
