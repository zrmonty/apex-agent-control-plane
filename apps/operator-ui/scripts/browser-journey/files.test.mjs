import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, lstatSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { readBounded, loadAssets, labCredentials } from './files.mjs';

function directory(t) {
  const parent = realpathSync(os.tmpdir()); const dir = mkdtempSync(path.join(parent, 'apex-ui-unit-'));
  t.after(() => {
    assert.equal(path.dirname(dir), parent); assert.ok(path.basename(dir).startsWith('apex-ui-unit-'));
    assert.equal(realpathSync(dir), dir); assert.equal(lstatSync(dir).isSymbolicLink(), false);
    rmSync(dir, { recursive: true });
  });
  return dir;
}
test('fixture file reads reject oversized/empty/non-file paths before materializing contents', t => {
  const dir = directory(t); const file = path.join(dir, 'small'); writeFileSync(file, 'four');
  assert.equal(readBounded(file, 4).toString(), 'four');
  assert.throws(() => readBounded(file, 3)); assert.throws(() => readBounded(dir, 100));
  writeFileSync(file, ''); assert.throws(() => readBounded(file, 4));
});
test('static loader serves only actual bounded built assets, not maps or arbitrary sibling files', t => {
  const dir = directory(t); mkdirSync(path.join(dir, 'assets'));
  writeFileSync(path.join(dir, 'index.html'), '<html>built</html>');
  writeFileSync(path.join(dir, 'assets', 'app.js'), 'actual build bytes');
  writeFileSync(path.join(dir, 'assets', 'app.js.map'), '{"sourcesContent":["private"]}');
  writeFileSync(path.join(dir, 'secret.pem'), 'private');
  const assets = loadAssets(dir);
  assert.equal(assets.has('/index.html'), true, 'built entrypoint was not loaded');
  assert.equal(assets.get('/index.html').body.toString(), '<html>built</html>');
  assert.equal(assets.get('/assets/app.js').body.toString(), 'actual build bytes');
  assert.equal(assets.has('/secret.pem'), false); assert.equal(assets.has('/assets/app.js.map'), false);
});
test('realm selection requires exactly one enabled non-service human and one non-temporary password', () => {
  const human = { username: 'lab-human', enabled: true, credentials: [{ type: 'password', value: 'unit-only', temporary: false }] };
  assert.deepEqual(labCredentials({ users: [human] }), { username: 'lab-human', password: 'unit-only' });
  for (const users of [[], [human, human], [{ ...human, enabled: false }], [{ ...human, username: 'service-account-lab' }],
    [{ ...human, credentials: [{ type: 'password', value: 'unit-only', temporary: true }] }]]) {
    assert.throws(() => labCredentials({ users }));
  }
});
