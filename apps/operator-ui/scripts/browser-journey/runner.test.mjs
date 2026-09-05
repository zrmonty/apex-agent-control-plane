import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../browser-journey.mjs', import.meta.url));
async function child(t, args, eof = false) {
  const processChild = spawn(process.execPath, [script, ...args], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
    env: { ...process.env, APEX_ROOT_BROWSER_HTTP_ADDR: 'remote-secret-canary.invalid:9999',
      APEX_BROWSER_TEST_PKI_DIR: '', DEBUG: 'pw:*', PWDEBUG: '1' } });
  const closed = once(processChild, 'close');
  t.after(async () => { if (processChild.exitCode === null && processChild.signalCode === null) processChild.kill(); await closed; });
  let out = ''; let err = '';
  processChild.stdout.on('data', bytes => { out += bytes; }); processChild.stderr.on('data', bytes => { err += bytes; });
  if (eof) processChild.stdin.end();
  const timer = setTimeout(() => processChild.kill(), 3000);
  try {
    const [code, signal] = await closed;
    assert.equal(signal, null); assert.equal(code, 1); assert.equal(out, '');
    assert.match(err, /^UI_JOURNEY_FAILED_(?:configuration|protocol)\n$/);
    assert.equal(err.includes('secret-canary'), false);
  } finally { clearTimeout(timer); }
}
test('CLI refuses ambient remote target without raw diagnostics or success markers', t => child(t, []));
test('unexpected argv is rejected without reflecting credential-like input', t => child(t, ['password-secret-canary']));
test('invalid configuration remains bounded when the parent closes input immediately', t => child(t, [], true));
