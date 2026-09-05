import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('../verify-working-mcp-gateway.mjs', import.meta.url));
// Independent expectations from task 21's required acceptance matrix.
const requiredIds = [
  'fresh-ui-create-deploy', 'allowed-denied-call', 'two-proxies', 'cli-stdio',
  'approval-limits', 'pause-retire', 'rotate-rollback', 'controller-runtime-crash',
  'governance-identity-outage', 'evidence-outage', 'projection-outage',
  'microsecond-precision', 'wall-clock-jump-skew', 'trace-exporter-loss', 'backup-restore',
];
const suiteIds = {
  smoke: ['fresh-ui-create-deploy', 'allowed-denied-call', 'pause-retire'],
  isolation: ['two-proxies', 'cli-stdio', 'approval-limits', 'rotate-rollback'],
  failure: [
    'approval-limits', 'pause-retire', 'rotate-rollback', 'controller-runtime-crash',
    'governance-identity-outage', 'evidence-outage', 'projection-outage', 'trace-exporter-loss', 'backup-restore',
  ],
  tracing: ['microsecond-precision', 'wall-clock-jump-skew', 'trace-exporter-loss'],
  all: requiredIds,
};

function invoke(...args) {
  return spawnSync(process.execPath, [runner, ...args], {
    cwd: tmpdir(), env: { ...process.env, PATH: '' }, encoding: 'utf8', timeout: 5000,
  });
}

test('component: --list immediately inventories every required live case without services', () => {
  const result = invoke('--list');
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.type, 'acceptance-inventory');
  assert.equal(report.releaseGate, 'not-run');
  assert.deepEqual(report.cases.map(({ id }) => id), requiredIds);
  for (const entry of report.cases) {
    assert.equal(entry.kind, 'live-acceptance');
    assert.equal(entry.required, true);
    assert.equal(entry.implementation, 'unimplemented');
    assert.ok(entry.observation.length > 30, entry.id);
    assert.ok(entry.requiredEvidence.length >= 2, entry.id);
    assert.ok(entry.requiredEvidence.every((value) => typeof value === 'string' && value.length > 10));
  }
});

test('component: --case explicitly fails each unimplemented live case without skipping', () => {
  for (const id of requiredIds) {
    const result = invoke('--case', id);
    assert.ifError(result.error);
    assert.equal(result.status, 1, `${id}: ${result.stderr}`);
    assert.equal(result.stderr, '');
    const report = JSON.parse(result.stdout);
    assert.equal(report.type, 'acceptance-results');
    assert.equal(report.releaseGate, 'failed');
    assert.deepEqual(report.counts, { selected: 1, passed: 0, failed: 1, skipped: 0, unimplemented: 1 });
    assert.equal(report.results[0].id, id);
    assert.equal(report.results[0].kind, 'live-acceptance');
    assert.equal(report.results[0].status, 'failed');
    assert.equal(report.results[0].code, 'ACCEPTANCE_NOT_IMPLEMENTED');
    assert.match(report.results[0].reason, /not implemented/i);
    assert.ok(report.results[0].requiredEvidence.length >= 2);
  }
});

test('component: named suites select live cases and the exact CI release command fails all 15', () => {
  for (const [suite, ids] of Object.entries(suiteIds)) {
    const result = invoke('--profile', 'ci', '--suite', suite);
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.releaseGate, 'failed');
    assert.equal(report.options.profile, 'ci');
    assert.equal(report.options.keepOnFailure, false);
    assert.deepEqual(report.results.map(({ id }) => id), ids);
    assert.deepEqual(report.counts, {
      selected: ids.length, passed: 0, failed: ids.length, skipped: 0, unimplemented: ids.length,
    });
    assert.ok(report.results.every(({ code }) => code === 'ACCEPTANCE_NOT_IMPLEMENTED'));
    const inventory = invoke('--list', '--suite', suite);
    assert.equal(inventory.status, 0, inventory.stderr);
    assert.deepEqual(JSON.parse(inventory.stdout).cases.map(({ id }) => id), ids);
  }
});

test('component: missing, invalid or ambiguous selectors never default to success', () => {
  const invalid = [
    [], ['--profile', 'ci'], ['--case', 'missing-case'], ['--case'], ['--case='],
    ['--case', 'fresh-ui-create-deploy', '--profile', 'production'],
    ['--list', '--profile', 'production'], ['--list', '--case', 'missing-case'],
    ['--suite', 'component'], ['--suite='], ['--suite'], ['--profile'],
    ['--case', 'fresh-ui-create-deploy', '--suite', 'all'],
    ['--suite', 'smoke', '--suite', 'all'],
    ['--case', 'two-proxies', '--case', 'cli-stdio'],
    ['--list', '--list'], ['--list', '--profile', 'lab', '--profile', 'ci'],
    ['--list', '--unknown'], ['--list=false'], ['--list', 'extra'],
  ];
  for (const args of invalid) {
    const result = invoke(...args);
    assert.ifError(result.error);
    assert.equal(result.status, 2, `${JSON.stringify(args)}: ${result.stdout}`);
    assert.equal(result.stdout, '');
    const error = JSON.parse(result.stderr);
    assert.equal(error.type, 'usage-error');
    assert.equal(error.code, 'INVALID_ARGUMENTS');
    assert.ok(error.message.length > 0);
  }
});

test('component: artifact and keep flags are validated without fabricating a live run', () => {
  const directory = join(tmpdir(), `mcp acceptance ${randomUUID()}`);
  assert.equal(existsSync(directory), false);
  const result = invoke('--profile=lab', '--case=cli-stdio', '--artifacts', directory, '--keep-on-failure');
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report.options, {
    profile: 'lab', case: 'cli-stdio', suite: null, artifactsDirectory: directory, keepOnFailure: true,
  });
  assert.equal(report.liveExecution, 'not-started');
  assert.deepEqual(report.artifacts, []);
  assert.equal(existsSync(directory), false);
  const defaults = JSON.parse(invoke('--case=two-proxies').stdout);
  assert.equal(defaults.options.profile, 'lab');
  assert.equal(defaults.options.artifactsDirectory, null);
  assert.equal(defaults.options.keepOnFailure, false);
  for (const args of [
    ['--artifacts'], ['--artifacts='], ['--artifacts', ' '],
    ['--artifacts', directory, '--artifacts', directory],
    ['--keep-on-failure', '--keep-on-failure'], ['--keep-on-failure=false'],
  ]) {
    const invalid = invoke('--case=cli-stdio', ...args);
    assert.equal(invalid.status, 2, JSON.stringify(args));
    assert.equal(JSON.parse(invalid.stderr).code, 'INVALID_ARGUMENTS');
  }
});
