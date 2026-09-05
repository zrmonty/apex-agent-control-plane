// Execute the actual workflow shell against controlled Docker observations.
// The TCP listener is real; it deliberately accepts before resolver selection.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import test from 'node:test';

const source = readFileSync(new URL('../../.github/workflows/live-mtls-e2e.yml', import.meta.url), 'utf8')
  .replaceAll('\r\n', '\n');
const step = source.split('      - name: Keycloak-backed operator credentials\n')[1]?.split('\n      - name: ')[0];
assert.ok(step, 'expected the Keycloak startup step');
const shell = step.split('        run: |\n')[1].split('\n')
  .filter(line => line.trim()).map(line => {
    assert.ok(line.startsWith('          '));
    return line.slice(10);
  }).join('\n');

async function run(scenario) {
  const listener = createServer(socket => { socket.resume(); socket.end(); });
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  try {
    const command = `
attempts=0
docker() {
  case "$*" in
    *' up '*) return 0 ;;
    *' ps '*)
      if [ "$SCENARIO" = exited ]; then echo 'control-plane-api-oidc exited';
      else echo 'control-plane-api-oidc running'; fi ;;
    *' logs '*)
      if [ "$SCENARIO" = delayed ] && [ "$attempts" -ge 1 ]; then
        echo 'operator credentials: keycloak'
      elif [ "$SCENARIO" = log_error ]; then
        echo 'operator credentials: keycloak'; return 1
      else echo 'operator credentials: static'; fi ;;
    *) return 97 ;;
  esac
}
sleep() { attempts=$((attempts + 1)); }
${shell.replaceAll('/dev/tcp/127.0.0.1/18449', `/dev/tcp/127.0.0.1/${listener.address().port}`)}
echo "READINESS_ATTEMPTS=$attempts"
`;
    return await new Promise((resolve, reject) => {
      const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
      const child = spawn(bash, ['-c', command], { env: { ...process.env, SCENARIO: scenario },
        windowsHide: true, timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'] });
      let output = '';
      child.stdout.on('data', bytes => { output += bytes; });
      child.stderr.on('data', bytes => { output += bytes; });
      child.on('error', reject);
      child.on('close', (code, signal) => resolve({ code, signal, output }));
    });
  } finally {
    await new Promise(resolve => listener.close(resolve));
  }
}

test('an open Docker forwarding port must wait for actual resolver selection', async () => {
  const result = await run('delayed');
  assert.equal(result.code, 0, result.output);
  assert.match(result.output, /READINESS_ATTEMPTS=1\b/);
});

for (const scenario of ['wrong_resolver', 'exited', 'log_error']) {
  test(`Keycloak readiness fails closed for ${scenario}`, async () => {
    const result = await run(scenario);
    assert.equal(result.code, 1, result.output);
    assert.equal(result.signal, null);
    assert.doesNotMatch(result.output, /READINESS_ATTEMPTS=/);
  });
}
