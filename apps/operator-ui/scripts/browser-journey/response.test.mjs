import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDiagnostics } from './diagnostics.mjs';
import { jsonResponse } from './response.mjs';

const CANARY = 'private-response-canary';
const operations = ['initial_inventory', 'create', 'detail_reload', 'inventory_reload', 'restored_inventory'];
const stages = ['wait', 'status', 'cache', 'body', 'size', 'utf8', 'json'];
const goodBytes = Buffer.from('{"ok":true}');
const oversized = Buffer.alloc(1024 * 1024 + 1, 32);
function reply(overrides = {}) {
  return {
    status: () => 200,
    headers: () => ({ 'cache-control': 'no-store', 'x-private': CANARY }),
    body: async () => goodBytes,
    url: () => `https://private.invalid/?code=${CANARY}`,
    ...overrides,
  };
}
function dependencyFailure() {
  const error = new Error(`https://private.invalid/?code=${CANARY}`);
  error.stack = CANARY;
  throw error;
}
const failures = [
  ['wait', dependencyFailure],
  ['status', () => reply({ status: () => 502 })],
  ['cache', () => reply({ headers: () => ({ 'cache-control': CANARY }) })],
  ['body', () => reply({ body: async () => dependencyFailure() })],
  ['size', () => reply({ body: async () => oversized })],
  ['utf8', () => reply({ body: async () => Buffer.from([0xc3, 0x28]) })],
  ['json', () => reply({ body: async () => Buffer.from(`{"${CANARY}":`) })],
];

// The external Playwright Response is controlled here; the checker and final
// diagnostic classifier are real. Synthetic component evidence, not Chromium/BFF.
for (const operation of operations) {
  for (const [stage, obtain] of failures) {
    test(`${operation} identifies ${stage} failure without reflecting input`, async () => {
      const diagnostics = createDiagnostics();
      const phases = [];
      await assert.rejects(jsonResponse(operation, obtain, value => {
        phases.push(value); diagnostics.phase(value);
      }), error => {
        assert.equal(diagnostics.category(error), `response_${operation}_${stage}`);
        assert.equal(error.message, `response_${operation}_${stage}`);
        assert.equal(error.cause, undefined);
        assert.ok(!String(error.stack).includes(CANARY));
        assert.ok(!JSON.stringify(phases).includes(CANARY));
        assert.equal(phases.at(-1), `response_${operation}_${stage}`);
        return true;
      });
    });
  }
  test(`${operation} preserves valid JSON and the original response without changing checks`, async () => {
    const original = reply(); const phases = []; let calls = 0;
    const result = await jsonResponse(operation, async () => { calls++; return original; }, value => phases.push(value));
    assert.deepEqual(result.value, { ok: true });
    assert.equal(result.response, original);
    assert.equal(calls, 1);
    assert.deepEqual(phases, stages.map(stage => `response_${operation}_${stage}`));
  });
}

test('wait covers a rejected asynchronous response acquisition without retry', async () => {
  let calls = 0;
  await assert.rejects(jsonResponse('detail_reload', async () => { calls++; dependencyFailure(); }, () => {}),
    { message: 'response_detail_reload_wait' });
  assert.equal(calls, 1);
});

test('waiting stays before any response access and does not consume the body early', async () => {
  let release; let reads = 0; const phases = [];
  const pending = new Promise(resolve => { release = resolve; });
  const result = jsonResponse('create', () => pending, value => phases.push(value));
  try {
    assert.deepEqual(phases, ['response_create_wait']);
    assert.equal(reads, 0);
  } finally {
    release(reply({ body: async () => { reads++; return goodBytes; } }));
    await result;
  }
  assert.equal(reads, 1);
});

for (const stage of ['status', 'cache']) {
  test(`${stage} accessor exceptions cannot replace the stage with raw dependency data`, async () => {
    const original = stage === 'status' ? reply({ status: dependencyFailure }) : reply({ headers: dependencyFailure });
    await assert.rejects(jsonResponse('create', () => original, () => {}), error => {
      assert.ok(!String(error.stack).includes(CANARY));
      assert.equal(error.message, `response_create_${stage}`);
      return true;
    });
  });
}

for (const key of ['access_token', 'refresh_token', 'id_token', 'accessToken', 'refreshToken', 'idToken']) {
  test(`the existing ${key} privacy rejection remains privacy, not JSON diagnostics`, async () => {
    const diagnostics = createDiagnostics();
    await assert.rejects(jsonResponse('create', () => reply({
      body: async () => Buffer.from(JSON.stringify({ [key]: CANARY })),
    }), diagnostics.phase), error => {
      assert.equal(error.message, 'privacy');
      assert.equal(diagnostics.category(error), 'privacy');
      assert.ok(!String(error.stack).includes(CANARY));
      return true;
    });
  });
}

test('exactly one MiB of valid JSON remains accepted', async () => {
  const bytes = Buffer.alloc(1024 * 1024, 32); goodBytes.copy(bytes);
  const { value } = await jsonResponse('inventory_reload', () => reply({ body: async () => bytes }), () => {});
  assert.deepEqual(value, { ok: true });
});

test('unlisted operation labels fail statically before invoking the response source', async () => {
  for (const operation of [CANARY, 'detail_reload_body', 'create\n', undefined, { toString: dependencyFailure }]) {
    let calls = 0; const phases = [];
    await assert.rejects(jsonResponse(operation, () => { calls++; return reply(); }, value => phases.push(value)),
      { message: 'internal' });
    assert.equal(calls, 0);
    assert.ok(!JSON.stringify(phases).includes(CANARY));
  }
});
