import assert from "node:assert/strict";
import crypto from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { test } from "node:test";
import { CompiledCallPreparer } from "./call-preparation.js";
import { fixture } from "./call-preparation/fixture.js";
const refused = /^Error: managed call preparation refused safely$/;

test("OS random boundary supplies independent UUID, 16-byte trace and 8-byte span draws", t => {
  const f = fixture(), p = new CompiledCallPreparer(f.options), sizes: number[] = [];
  const random = t.mock.method(crypto, "randomBytes", (size: number) => {
    sizes.push(size); return Buffer.alloc(size, sizes.length);
  });
  syncBuiltinESMExports();
  try {
    const prepared = p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline);
    assert.deepEqual(sizes, [16, 16, 8]);
    assert.equal(prepared.trace.traceId, "02".repeat(16));
    assert.equal(prepared.trace.spanId, "03".repeat(8));
    assert.match(prepared.request.callId, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  } finally { random.mock.restore(); syncBuiltinESMExports(); }
});
for (const zeroDraw of [2, 3]) test(`zero OTel draw${zeroDraw} refuses, no fabricated fallback identity`, t => {
  const f = fixture(), p = new CompiledCallPreparer(f.options); let draws = 0;
  const random = t.mock.method(crypto, "randomBytes", (size: number) => Buffer.alloc(size, ++draws === zeroDraw ? 0 : 1));
  syncBuiltinESMExports();
  try {
    assert.throws(() => p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline), refused);
    assert.equal(draws, zeroDraw);
  } finally { random.mock.restore(); syncBuiltinESMExports(); }
});
test("OS entropy failure exposes no diagnostics and invalid input draws no entropy", t => {
  const f = fixture(), p = new CompiledCallPreparer(f.options); let draws = 0;
  const random = t.mock.method(crypto, "randomBytes", (_size: number): Buffer => { draws++; throw Error("SENSITIVE entropy error"); });
  syncBuiltinESMExports();
  try {
    assert.throws(() => p.prepare(f.identity, "portfolio.read", { portfolioId: "p", asOf: "2026-09-06" }, f.original, f.deadline), refused);
    assert.equal(draws, 0);
    assert.throws(() => p.prepare(f.identity, "portfolio.read", { portfolioId: "p" }, f.original, f.deadline), refused);
    assert.equal(draws, 1);
  } finally { random.mock.restore(); syncBuiltinESMExports(); }
});
