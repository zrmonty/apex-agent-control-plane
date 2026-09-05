import assert from 'node:assert/strict';
import test from 'node:test';
import { runBounded } from './command.mjs';

// Real controlled children test the process boundary, never fake image acceptance.
test('bounded child returns exact stdout without exposing stderr', async () => {
  const result = await runBounded(process.execPath,
    ['-e', "process.stdout.write('ok'); process.stderr.write('DO_NOT_EMIT_CHILD_VALUE')"]);
  assert.deepEqual(result, { ok: true, code: 'OK', stdout: 'ok' });
});

test('child nonzero exit is sanitized and keeps only bounded stdout', async () => {
  const result = await runBounded(process.execPath,
    ['-e', "process.stderr.write('DO_NOT_EMIT_CHILD_VALUE'); process.exitCode = 3"]);
  assert.deepEqual(result, { ok: false, code: 'COMMAND_FAILED', stdout: '' });
});

test('child deadline terminates a real hanging process', async () => {
  const started = performance.now();
  const result = await runBounded(process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 100, maxBytes: 1024 });
  assert.equal(result.code, 'COMMAND_TIMEOUT');
  assert.equal(result.ok, false);
  assert.ok(performance.now() - started < 2500);
});

for (const stream of ['stdout', 'stderr']) {
  test(`child ${stream} flood is bounded, killed, and discarded`, async () => {
    const result = await runBounded(process.execPath,
      ['-e', `process.${stream}.write('x'.repeat(128 * 1024)); setInterval(() => {}, 1000)`],
      { timeoutMs: 2000, maxBytes: 1024 });
    assert.deepEqual(result, { ok: false, code: 'COMMAND_OUTPUT_LIMIT', stdout: '' });
  });
}

test('invalid runner limits fail without executing a child', async () => {
  for (const options of [{ timeoutMs: 0 }, { timeoutMs: 60_001 }, { maxBytes: 0 },
    { maxBytes: 65_537 }, { timeoutMs: NaN }]) {
    const result = await runBounded(process.execPath, ['-e', "process.stdout.write('ran')"], options);
    assert.deepEqual(result, { ok: false, code: 'COMMAND_FAILED', stdout: '' });
  }
});

test('spawn failure emits no raw process error', async () => {
  const result = await runBounded('nonexistent-packaging-test-executable', []);
  assert.deepEqual(result, { ok: false, code: 'COMMAND_FAILED', stdout: '' });
});
