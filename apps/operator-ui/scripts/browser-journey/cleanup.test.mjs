import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PassThrough } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { createCleanup } from './cleanup.mjs';
import { parentProtocol } from './protocol.mjs';

function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function readyProtocol(t) {
  const input = new PassThrough(); const output = new PassThrough(); let text = '';
  output.on('data', bytes => { text += bytes; });
  const protocol = parentProtocol(input, output, new AbortController(), 500);
  t.after(() => { protocol.dispose(); input.destroy(); output.destroy(); });
  const down = protocol.exchange('D'); input.write('D\n'); await down;
  const up = protocol.exchange('R'); input.write('R\n'); await up;
  return { protocol, text: () => text };
}

for (const first of ['browser', 'frontend']) {
test(`success marker waits for both owned closes when ${first} finishes first`, { timeout: 1000 }, async t => {
  const { protocol, text } = await readyProtocol(t);
  const browser = deferred(); const frontend = deferred(); let nudges = 0; let emergencies = 0; let closes = 0;
  const cleanup = createCleanup({ getLaunching: () => Promise.resolve({ close() { closes++; return browser.promise; } }),
    closeFrontend: () => frontend.promise, notifyBrowser: () => { nudges++; }, emergencyExit: () => { emergencies++; },
    intervalMs: 5, timeoutMs: 100 });
  const closing = cleanup(); assert.equal(cleanup(), closing);
  const completed = closing.then(() => protocol.passed());
  (first === 'browser' ? browser : frontend).resolve(); await delay(10);
  assert.equal(text(), 'UI_READY_FOR_RESTART\nUI_OFFLINE_OBSERVED\n');
  (first === 'browser' ? frontend : browser).resolve(); await completed;
  assert.equal(text(), 'UI_READY_FOR_RESTART\nUI_OFFLINE_OBSERVED\nUI_JOURNEY_PASSED\n');
  const stopped = nudges; await delay(15);
  assert.equal(nudges, stopped); assert.equal(emergencies, 0); assert.equal(closes, 1);
});
}

test('a launched browser close rejection forbids PASS and retains bounded owned-tree escalation', { timeout: 1000 }, async t => {
  const { protocol, text } = await readyProtocol(t);
  const emergency = deferred(); let nudges = 0; let closes = 0;
  const cleanup = createCleanup({ getLaunching: () => Promise.resolve({ close() {
    closes++; return Promise.reject(new Error('close-secret-canary'));
  } }), closeFrontend: () => Promise.resolve(), notifyBrowser: () => { nudges++; },
  emergencyExit: () => emergency.resolve(nudges), intervalMs: 5, timeoutMs: 40 });
  const closing = cleanup(); assert.equal(cleanup(), closing);
  const outcome = await closing.then(() => { protocol.passed(); return 'passed'; }, error => error.message);
  // Wait even on RED so a broken timer policy cannot leave the test hanging.
  const atExit = await Promise.race([emergency.promise, delay(100).then(() => -1)]);
  assert.equal(outcome, 'cleanup');
  assert.equal(text(), 'UI_READY_FOR_RESTART\nUI_OFFLINE_OBSERVED\n');
  assert.ok(atExit >= 2, 'close failure disabled the process-tree watchdog');
  assert.equal(closes, 1);
  const stopped = nudges; await delay(15); assert.equal(nudges, stopped);
});

test('failed launch cleanup completes without replacing the original launch failure', { timeout: 1000 }, async () => {
  const original = new Error('launch-secret-canary'); const launching = Promise.reject(original);
  let frontendClosed = false; let emergencies = 0;
  const cleanup = createCleanup({ getLaunching: () => launching,
    closeFrontend: async () => { frontendClosed = true; }, notifyBrowser: () => {},
    emergencyExit: () => { emergencies++; }, intervalMs: 5, timeoutMs: 40 });
  let observed;
  try { await launching; } catch (error) { await cleanup(); observed = error; }
  assert.equal(observed, original); assert.equal(frontendClosed, true);
  await delay(50); assert.equal(emergencies, 0);
});

test('hanging owned close reaches the emergency bound without resolving cleanup', { timeout: 1000 }, async () => {
  const emergency = deferred(); const close = deferred(); let settled = false; let nudges = 0;
  const cleanup = createCleanup({ getLaunching: () => Promise.resolve({ close: () => close.promise }),
    closeFrontend: () => Promise.resolve(), notifyBrowser: () => { nudges++; },
    emergencyExit: () => emergency.resolve(nudges), intervalMs: 5, timeoutMs: 40 });
  const closing = cleanup().then(() => { settled = true; });
  assert.ok(await emergency.promise >= 2); assert.equal(settled, false);
  close.resolve(); await closing;
});
