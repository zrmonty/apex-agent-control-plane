import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { scanDist, loadDescriptors } from './inspector.mjs';
import { scannerFixtures } from './scanner-fixtures.mjs';

// Real small filesystem fixtures are scanner unit inputs only, not image evidence.
// Clean only this process's exact mkdtemp-owned roots, including on test failure.
const fixtures = scannerFixtures();
test.after(() => fixtures.cleanupAll());
const fixture = () => fixtures.create();
test('scanner counts exact clean dist bytes without loading application code', async () => {
  const root = fixture();
  mkdirSync(join(root, 'live'));
  writeFileSync(join(root, 'index.js'), 'throw Error("must not execute")');
  writeFileSync(join(root, 'live', 'grpc.js'), 'export {};');
  assert.deepEqual(await scanDist(root), {
    files: 2, bytes: 41, testArtifacts: 0, privateKeyFiles: 0,
  });
});
test('scanner counts compiled tests and fixture paths including nested names', async () => {
  const root = fixture();
  mkdirSync(join(root, '__fixtures__'));
  writeFileSync(join(root, 'auth.test.js'), 'x');
  writeFileSync(join(root, 'auth.spec.js'), 'x');
  writeFileSync(join(root, '__fixtures__', 'data.js'), 'x');
  writeFileSync(join(root, 'contracts.js'), 'x');
  assert.deepEqual(await scanDist(root), {
    files: 4, bytes: 4, testArtifacts: 4, privateKeyFiles: 0,
  });
});
test('scanner detects embedded private PEM markers without exposing content', async () => {
  const root = fixture();
  for (const [index, kind] of ['', 'RSA ', 'EC ', 'DSA ', 'ENCRYPTED ', 'OPENSSH '].entries()) {
    writeFileSync(join(root, `module-${index}.js`),
      `export const fixture = '-----BEGIN ${kind}PRIVATE KEY-----\\nUNIT_MARKER_ONLY';`);
  }
  const result = await scanDist(root);
  assert.equal(result.privateKeyFiles, 6);
  assert.equal(result.testArtifacts, 0);
  assert.ok(!JSON.stringify(result).includes('UNIT_MARKER_ONLY'));
});
test('scanner rejects even an empty test-fixture directory as an artifact', async () => {
  const root = fixture();
  mkdirSync(join(root, '__fixtures__'));
  assert.deepEqual(await scanDist(root), { files: 0, bytes: 0, testArtifacts: 1, privateKeyFiles: 0 });
});
test('scanner rejects a missing or non-directory root', async () => {
  const root = fixture();
  writeFileSync(join(root, 'file.js'), 'x');
  await assert.rejects(scanDist(join(root, 'missing')));
  await assert.rejects(scanDist(join(root, 'file.js')));
});
test('scanner refuses a junction or symlink without traversing outside', async () => {
  const root = fixture();
  const outside = fixture();
  writeFileSync(join(outside, 'never-read.js'), 'UNIT_OUTSIDE_MARKER');
  symlinkSync(outside, join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(scanDist(root));
  await assert.rejects(scanDist(join(root, 'escape')));
});
test('scanner rejects a file larger than two MiB', async () => {
  const root = fixture();
  writeFileSync(join(root, 'large.js'), Buffer.alloc(2 * 1024 * 1024 + 1));
  await assert.rejects(scanDist(root));
});
test('scanner rejects an aggregate larger than 32 MiB', async () => {
  const root = fixture();
  const bytes = Buffer.alloc(2 * 1024 * 1024);
  for (let index = 0; index < 17; index++) writeFileSync(join(root, `${index}.js`), bytes);
  await assert.rejects(scanDist(root));
});
test('scanner bounds depth and immediate directory scanning', async () => {
  const root = fixture();
  let nested = root;
  for (let depth = 0; depth < 17; depth++) { nested = join(nested, 'a'); mkdirSync(nested); }
  await assert.rejects(scanDist(root));
  const wide = fixture();
  for (let index = 0; index < 4097; index++) writeFileSync(join(wide, `${index}.js`), '');
  await assert.rejects(scanDist(wide));
});

const protoRoot = fileURLToPath(new URL('../../../../contracts/proto/apex/v1/', import.meta.url));
test('actual repository descriptors include approval, WKT, and all four expected RPC methods', async () => {
  assert.deepEqual(await loadDescriptors([
    join(protoRoot, 'governance.proto'), join(protoRoot, 'event.proto'),
  ]), { protoFiles: 2, descriptorServices: 3, rpcMethods: 4 });
});
test('missing real proto and missing imported approval both fail descriptor loading', async () => {
  await assert.rejects(loadDescriptors([join(protoRoot, 'absent.proto'), join(protoRoot, 'event.proto')]));
  const root = fixture();
  writeFileSync(join(root, 'governance.proto'),
    'syntax = "proto3"; package apex.v1; import "apex/v1/missing_approval.proto";');
  await assert.rejects(loadDescriptors([join(root, 'governance.proto'), join(protoRoot, 'event.proto')]));
});
