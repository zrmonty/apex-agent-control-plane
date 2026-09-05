#!/usr/bin/env node
// CI/LAB byte collector, not a runtime-contract validator or acceptance proof.
// Run only after Cargo exits, against its dedicated trusted temp root. The root,
// source and output parent must not be concurrently mutated: COPYFILE_EXCL is
// path-based and does not provide a hostile-writer filesystem sandbox.
// Usage: node scripts/collect-runtime-fixture.mjs --root <absolute-dir> --out <absolute-new-file>
// No mkdir, overwrite, cleanup or deletion; output parents must already exist.
import { createHash } from 'node:crypto';
import {
  closeSync, constants, copyFileSync, fstatSync, lstatSync, openSync, opendirSync,
  readSync, realpathSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize, parse, relative, resolve, sep } from 'node:path';

const artifactDirectory = /^apex-runtime-fixture-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const maxEntries = 1024;
const maxBytes = 256 * 1024;

function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

function argumentsFor(args) {
  requireCondition(args.length === 4, 'INVALID_ARGUMENTS');
  const options = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    requireCondition(['--root', '--out'].includes(flag) && !options.has(flag), 'INVALID_ARGUMENTS');
    requireCondition(typeof value === 'string' && value.trim().length > 0 &&
      !/[\x00-\x1f\x7f]/.test(value) && isAbsolute(value) &&
      resolve(parse(value).root) === normalize(parse(value).root) &&
      (flag === '--root' || resolve(value) === normalize(value)), 'INVALID_ARGUMENTS');
    options.set(flag, resolve(value));
  }
  const root = options.get('--root');
  requireCondition(root !== parse(root).root, 'INVALID_ARGUMENTS');
  return { root, out: options.get('--out') };
}

function findDirectory(root) {
  const directory = opendirSync(root, { bufferSize: 32 });
  let match;
  let count = 0;
  try {
    for (let entry = directory.readSync(); entry !== null; entry = directory.readSync()) {
      count += 1;
      requireCondition(count <= maxEntries, 'COLLECTION_FAILED');
      if (!artifactDirectory.test(entry.name)) continue;
      requireCondition(match === undefined, 'COLLECTION_FAILED');
      match = entry.name;
    }
  } finally {
    directory.closeSync();
  }
  requireCondition(match !== undefined, 'COLLECTION_FAILED');
  return join(root, match);
}

function realDirectory(path) {
  const metadata = lstatSync(path);
  requireCondition(!metadata.isSymbolicLink() && metadata.isDirectory(), 'COLLECTION_FAILED');
  return realpathSync(path);
}

function readArtifact(path) {
  const metadata = lstatSync(path);
  requireCondition(!metadata.isSymbolicLink() && metadata.isFile() &&
    metadata.size <= maxBytes, 'COLLECTION_FAILED');
  const file = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fstatSync(file);
    requireCondition(opened.isFile() && opened.size <= maxBytes &&
      opened.dev === metadata.dev && opened.ino === metadata.ino, 'COLLECTION_FAILED');
    // Explicit reads stay bounded even on growth; path-based copy requires a stopped producer.
    const bytes = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = readSync(file, bytes, length, bytes.length - length, null);
      if (read === 0) break;
      length += read;
    }
    requireCondition(length <= maxBytes && length === opened.size &&
      fstatSync(file).size === opened.size, 'COLLECTION_FAILED');
    return bytes.subarray(0, length);
  } finally {
    closeSync(file);
  }
}

function outputOutsideArtifact(directory, out) {
  const canonical = join(realpathSync(dirname(out)), basename(out));
  const fromArtifact = relative(directory, canonical);
  requireCondition(isAbsolute(fromArtifact) || fromArtifact === '..' ||
    fromArtifact.startsWith(`..${sep}`), 'COLLECTION_FAILED');
}

try {
  const { root, out } = argumentsFor(process.argv.slice(2));
  const directory = realDirectory(findDirectory(realDirectory(root)));
  outputOutsideArtifact(directory, out);
  const source = join(directory, 'runtime-revision.json');
  const original = readArtifact(source);
  copyFileSync(source, out, constants.COPYFILE_EXCL);
  const bytes = readArtifact(out);
  requireCondition(bytes.equals(original), 'COLLECTION_FAILED');
  process.stdout.write(`${JSON.stringify({
    type: 'runtime-fixture-collected', artifactCount: 1, bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'), outputPath: out,
  })}\n`);
} catch (error) {
  const usage = error.message === 'INVALID_ARGUMENTS';
  process.stderr.write(`${JSON.stringify({
    type: 'runtime-fixture-error', code: usage ? 'INVALID_ARGUMENTS' : 'COLLECTION_FAILED',
  })}\n`);
  process.exitCode = usage ? 2 : 1;
}
