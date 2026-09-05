// Test-only fixture ownership. Never enumerate old roots or shared artifacts.
import { lstatSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

export function scannerFixtures() {
  const parent = realpathSync(tmpdir());
  const roots = new Map();
  const refuse = () => { throw new Error('SCANNER_FIXTURE_CLEANUP_REFUSED'); };
  function cleanup(root) {
    // Validate exact current-process ownership and canonical temp confinement
    // before any recursive deletion. Never follow a replaced root/junction.
    if (typeof root !== 'string' || !roots.has(root) || !isAbsolute(root) ||
        root !== resolve(root) || dirname(root) !== parent ||
        !/^apex-packaging-scanner-[A-Za-z0-9]{6}$/.test(basename(root))) refuse();
    let stat;
    try { stat = lstatSync(root, { bigint: true }); }
    catch (error) {
      if (error.code === 'ENOENT') { roots.delete(root); return; }
      refuse();
    }
    const original = roots.get(root);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== original.dev ||
        stat.ino !== original.ino || realpathSync(root) !== root) refuse();
    // Node rm removes child symlinks/junctions themselves, not their targets.
    // This is cleanup of quiescent test fixtures, not a hostile-writer sandbox.
    rmSync(root, { recursive: true, force: false, maxRetries: 2, retryDelay: 20 });
    roots.delete(root);
  }
  return {
    create() {
      const root = mkdtempSync(join(parent, 'apex-packaging-scanner-'));
      roots.set(root, lstatSync(root, { bigint: true }));
      return root;
    },
    cleanup,
    cleanupAll() {
      let failed = false;
      for (const root of [...roots.keys()]) {
        try { cleanup(root); } catch { failed = true; }
      }
      if (failed) refuse();
    },
  };
}
