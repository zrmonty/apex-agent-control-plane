import assert from 'node:assert/strict';
import { existsSync, lstatSync, mkdirSync, readFileSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { scannerFixtures } from './scanner-fixtures.mjs';

test('fixture cleanup removes only the current registry exact root and nested files', (t) => {
  const owned = scannerFixtures();
  t.after(() => owned.cleanupAll());
  const root = owned.create();
  mkdirSync(join(root, 'nested'));
  writeFileSync(join(root, 'nested', 'data.js'), 'component-only');
  owned.cleanup(root);
  assert.equal(existsSync(root), false);
  // A second cleanup must not acquire ownership of a subsequently reused name.
  assert.throws(() => owned.cleanup(root), /SCANNER_FIXTURE_CLEANUP_REFUSED/);
});

test('fixture cleanup refuses other registries, parent paths, children and relative paths', (t) => {
  const owned = scannerFixtures();
  const other = scannerFixtures();
  t.after(() => owned.cleanupAll());
  t.after(() => other.cleanupAll());
  const root = owned.create();
  const foreign = other.create();
  for (const path of [foreign, dirname(root), join(root, 'nested'), './apex-packaging-scanner-invalid']) {
    assert.throws(() => owned.cleanup(path), /SCANNER_FIXTURE_CLEANUP_REFUSED/);
  }
  assert.equal(existsSync(root), true);
  assert.equal(existsSync(foreign), true);
});

test('recursive fixture cleanup unlinks junctions/symlinks without deleting their outside target', (t) => {
  const owned = scannerFixtures();
  const other = scannerFixtures();
  t.after(() => owned.cleanupAll());
  t.after(() => other.cleanupAll());
  const root = owned.create();
  const outside = other.create();
  writeFileSync(join(outside, 'keep.js'), 'OUTSIDE_COMPONENT_MARKER');
  symlinkSync(outside, join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  owned.cleanup(root);
  assert.equal(existsSync(root), false);
  assert.equal(readFileSync(join(outside, 'keep.js'), 'utf8'), 'OUTSIDE_COMPONENT_MARKER');
});

test('after-hook equivalent cleanup removes every owned root without a glob', () => {
  const owned = scannerFixtures();
  const roots = [owned.create(), owned.create()];
  owned.cleanupAll();
  assert.equal(roots.some((root) => existsSync(root)), false);
  owned.cleanupAll();
});

test('fixture root replaced by a junction or symlink is refused, not traversed', (t) => {
  const owned = scannerFixtures();
  const other = scannerFixtures();
  t.after(() => owned.cleanupAll());
  t.after(() => other.cleanupAll());
  const root = owned.create();
  const outside = other.create();
  writeFileSync(join(outside, 'keep.js'), 'OUTSIDE_COMPONENT_MARKER');
  // Remove only this freshly returned, still-empty exact root, non-recursively.
  rmdirSync(root);
  symlinkSync(outside, root, process.platform === 'win32' ? 'junction' : 'dir');
  try {
    assert.throws(() => owned.cleanup(root), /SCANNER_FIXTURE_CLEANUP_REFUSED/);
    assert.equal(readFileSync(join(outside, 'keep.js'), 'utf8'), 'OUTSIDE_COMPONENT_MARKER');
  } finally {
    assert.equal(lstatSync(root).isSymbolicLink(), true);
    // Unlink the exact test-created replacement only; never recursively follow it.
    if (process.platform === 'win32') rmdirSync(root);
    else unlinkSync(root);
  }
});
