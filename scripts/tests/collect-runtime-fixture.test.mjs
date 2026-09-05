// Collector component fixtures are deliberately NOT runtime contracts or acceptance evidence.
// Owned temp trees are retained: the collector and this suite never delete artifacts.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, parse, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const runner = fileURLToPath(new URL('../collect-runtime-fixture.mjs', import.meta.url));
const artifactName = 'runtime-revision.json';
const firstDirectory = 'apex-runtime-fixture-0191b7f1-7f2c-7c13-9a61-2f29f2be1001';
const secondDirectory = 'apex-runtime-fixture-0191b7f1-7f2c-7c13-9a61-2f29f2be1002';

function fixture() {
  const base = mkdtempSync(join(tmpdir(), 'apex-collector-component-'));
  const root = join(base, 'cargo temp');
  mkdirSync(root);
  return { base, root, out: join(base, 'collected artifact.json') };
}

function artifact(root, name = firstDirectory, bytes = Buffer.from('abc')) {
  const directory = join(root, name);
  mkdirSync(directory);
  const source = join(directory, artifactName);
  writeFileSync(source, bytes, { flag: 'wx' });
  return { directory, source };
}

function invoke(...args) {
  const result = spawnSync(process.execPath, [runner, ...args], {
    cwd: tmpdir(), encoding: 'utf8', timeout: 5000, maxBuffer: 16 * 1024,
  });
  assert.ifError(result.error);
  return result;
}

function rejectsCollection(root, out) {
  const result = invoke('--root', root, '--out', out);
  assert.equal(result.status, 1, 'invalid artifact tree must not be collected');
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr).code, 'COLLECTION_FAILED');
  assert.equal(existsSync(out), false);
}

test('component: copies exact opaque bytes and emits independently known byte SHA metadata', () => {
  const { root, out } = fixture();
  const { source } = artifact(root);
  const result = invoke('--root', root, '--out', out);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.deepEqual(readFileSync(out), Buffer.from('abc'));
  assert.deepEqual(readFileSync(source), Buffer.from('abc'));
  assert.deepEqual(JSON.parse(result.stdout), {
    type: 'runtime-fixture-collected', artifactCount: 1, bytes: 3,
    sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    outputPath: out,
  });
});

test('component: rejects ambiguous CLI and nonabsolute or empty paths before any output write', () => {
  const { root, out } = fixture();
  artifact(root);
  const cases = [
    ['--unknown', root, '--out', out],
    ['--root', root, '--out', out, '--extra'],
    ['--root', root, '--root', root, '--out', out],
    ['--root', root, '--out', out, '--out', out],
    [], ['--root'], ['--root', root], ['--out', out],
    ['--root', '', '--out', out], ['--root', ' ', '--out', out],
    ['--root', 'relative', '--out', out], ['--root', root, '--out', 'relative'],
    ['--root', root, '--out', ''], ['--root', root, '--out', ' '],
    ['--root', parse(root).root, '--out', out],
    ['--root', root, '--out', `${out}\n`],
  ];
  for (const args of cases) {
    const result = invoke(...args);
    assert.equal(result.status, 2, 'invalid CLI must fail before collection');
    assert.equal(result.stdout, '');
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_ARGUMENTS');
    assert.equal(existsSync(out), false);
  }
});

for (const [name, setup] of [
  ['duplicate exported artifacts', (root) => { artifact(root); artifact(root, secondDirectory); }],
  ['second matching directory even if incomplete', (root) => {
    artifact(root); mkdirSync(join(root, secondDirectory));
  }],
  ['non-v7 directory', (root) => artifact(root, firstDirectory.replace('-7c13-', '-4c13-'))],
  ['non-RFC variant', (root) => artifact(root, firstDirectory.replace('-9a61-', '-7a61-'))],
  ['noncanonical uppercase UUID', (root) => artifact(root, firstDirectory.replace('7c13', '7C13'))],
  ['extra directory suffix', (root) => artifact(root, `${firstDirectory}-extra`)],
  ['missing artifact', () => {}],
  ['nested artifact instead of immediate export', (root) => {
    const nested = join(root, 'unrelated'); mkdirSync(nested); artifact(nested);
  }],
  ['wrong fixed filename', (root) => {
    const directory = join(root, firstDirectory); mkdirSync(directory);
    writeFileSync(join(directory, 'other.json'), 'collector-only bytes', { flag: 'wx' });
  }],
]) {
  test(`component: rejects ${name} without writing output`, () => {
    const { root, out } = fixture();
    setup(root);
    rejectsCollection(root, out);
  });
}

test('component: caps scanning at 1024 immediate entries including unrelated files', () => {
  const { base, root, out } = fixture();
  artifact(root);
  for (let index = 0; index < 1023; index += 1) {
    writeFileSync(join(root, `cargo-noise-${index}`), '', { flag: 'wx' });
  }
  const atLimit = invoke('--out', out, '--root', root);
  assert.equal(atLimit.status, 0, atLimit.stderr);
  assert.deepEqual(readFileSync(out), Buffer.from('abc'));
  writeFileSync(join(root, 'one-too-many'), '', { flag: 'wx' });
  rejectsCollection(root, join(base, 'must-not-exist.json'));
});

function directoryLink(target, link) {
  // Junctions exercise Windows link rejection without requiring symlink privileges.
  symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
}

test('component: rejects linked artifact directory instead of collecting outside root', () => {
  const { base, root, out } = fixture();
  const elsewhere = join(base, 'outside');
  mkdirSync(elsewhere);
  const { directory, source } = artifact(elsewhere);
  directoryLink(directory, join(root, firstDirectory));
  rejectsCollection(root, out);
  assert.deepEqual(readFileSync(source), Buffer.from('abc'));
});

test('component: requires a real nonsymlink root directory', () => {
  const { base, root, out } = fixture();
  artifact(root);
  const alias = join(base, 'linked-root');
  directoryLink(root, alias);
  rejectsCollection(alias, out);
});

for (const [name, setup] of [
  ['file in place of artifact directory', (root) => writeFileSync(join(root, firstDirectory), 'abc')],
  ['directory in place of artifact file', (root) => {
    const directory = join(root, firstDirectory); mkdirSync(directory);
    mkdirSync(join(directory, artifactName));
  }],
]) {
  test(`component: rejects ${name}`, () => {
    const { root, out } = fixture(); setup(root); rejectsCollection(root, out);
  });
}

// Unix CI is required for file-symlink coverage; Windows executes junction tests above.
if (process.platform !== 'win32') {
  test('component POSIX: rejects a file symlink without reading its target', () => {
    const { base, root, out } = fixture();
    const target = join(base, 'outside-file');
    writeFileSync(target, 'collector-only bytes', { flag: 'wx' });
    const directory = join(root, firstDirectory); mkdirSync(directory);
    symlinkSync(target, join(directory, artifactName), 'file');
    rejectsCollection(root, out);
    assert.equal(readFileSync(target, 'utf8'), 'collector-only bytes');
  });
}

test('component: preserves arbitrary bytes at 256 KiB and refuses a larger artifact before copy', () => {
  const accepted = fixture();
  const bytes = Buffer.alloc(256 * 1024, 0xff); // Opaque collector payload, intentionally not JSON.
  artifact(accepted.root, firstDirectory, bytes);
  const result = invoke('--root', accepted.root, '--out', accepted.out);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(accepted.out), bytes);
  assert.equal(JSON.parse(result.stdout).bytes, 262144);
  const rejected = fixture();
  const { source } = artifact(rejected.root, firstDirectory, Buffer.alloc(256 * 1024 + 1, 0xfe));
  rejectsCollection(rejected.root, rejected.out);
  assert.equal(readFileSync(source).length, 262145);
});

test('component: never overwrites an existing exact output path', () => {
  const { root, out } = fixture();
  const { source } = artifact(root);
  writeFileSync(out, 'existing collector-only artifact', { flag: 'wx' });
  const result = invoke('--root', root, '--out', out);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr).code, 'COLLECTION_FAILED');
  assert.equal(readFileSync(out, 'utf8'), 'existing collector-only artifact');
  assert.equal(readFileSync(source, 'utf8'), 'abc');
});

test('component: rejects a new output inside the matched artifact directory', () => {
  const { root } = fixture();
  const { directory, source } = artifact(root);
  rejectsCollection(root, join(directory, 'must-not-exist.json'));
  assert.equal(readFileSync(source, 'utf8'), 'abc');
});

test('component: rejects output parent aliases into the matched artifact directory', () => {
  const { base, root } = fixture();
  const { directory, source } = artifact(root);
  const alias = join(base, 'output-parent-alias');
  directoryLink(directory, alias);
  rejectsCollection(root, join(alias, 'must-not-exist.json'));
  assert.equal(readFileSync(source, 'utf8'), 'abc');
});

test('component: permits a sibling output directory sharing the artifact directory prefix', () => {
  const { root } = fixture();
  const { directory } = artifact(root);
  const sibling = `${directory}-collection`;
  mkdirSync(sibling);
  const out = join(sibling, artifactName);
  const result = invoke('--root', root, '--out', out);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(readFileSync(out), Buffer.from('abc'));
});

test('component: missing output parent fails without creating directories', () => {
  const { base, root } = fixture();
  artifact(root);
  const parent = join(base, 'not-created');
  rejectsCollection(root, join(parent, artifactName));
  assert.equal(existsSync(parent), false);
});

test('component: accepts an absolute dedicated root with its trailing directory separator', () => {
  const { root, out } = fixture();
  artifact(root);
  const result = invoke('--root', `${root}${sep}`, '--out', out);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(out, 'utf8'), 'abc');
});
