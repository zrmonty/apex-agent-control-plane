// Imported command-boundary faults, not actual Docker/image acceptance.
import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyStartup } from './startup.mjs';
import { expectedCases, imageId, ownershipProjection, startupBoundary } from './startup-fixtures.mjs';

async function refused(options, code = 'STARTUP_FAILED') {
  const boundary = startupBoundary(options);
  const report = await verifyStartup('example:startup', boundary.execute);
  const index = options.caseIndex ?? 0;
  assert.equal(report.ok, false);
  assert.equal(report.code, code);
  assert.equal(report.readinessVerified, false);
  assert.equal(report.protocolHandshakeVerified, false);
  assert.equal(report.cases.length, 8);
  assert.deepEqual(report.cases.map(({ passed }) => passed), expectedCases.map((_, i) => i < index));
  assert.equal(boundary.containers.length, index + 1, 'failure must prevent every subsequent create');
  assert.ok(boundary.containers.slice(0, index).every(({ started, removed }) => started && removed));
  assert.ok(report.cases.slice(index + 1).every((item) =>
    item.runId === null && item.containerId === null && item.observedExitCode === null));
  const serialized = JSON.stringify(report);
  assert.ok(serialized.length < 4096);
  assert.doesNotMatch(serialized, /CANARY|APEX_MCP_|NODE_ENV|--env|stderr|argv/);
  return { ...boundary, report, failed: boundary.containers[index] };
}

for (const [caseIndex, definition] of expectedCases.entries()) {
  test(`component: ${definition.id} rejects the wrong actual exit code`, async () => {
    const observed = definition.expectedExitCode === 0 ? 1 : 0;
    const result = await refused({ caseIndex, afterPatch: { exitCode: observed } });
    assert.equal(result.report.cases[caseIndex].observedExitCode, observed);
    assert.equal(result.failed.started, true);
    assert.equal(result.failed.removed, true);
  });

  test(`component: ${definition.id} rejects unexpected stdout, even whitespace`, async () => {
    const result = await refused({ caseIndex, stdout: caseIndex % 2 === 0 ? 'RAW_STDOUT_CANARY' : '\n' });
    assert.equal(result.report.cases[caseIndex].observedExitCode, definition.expectedExitCode);
    assert.equal(result.failed.started, true);
    assert.equal(result.failed.removed, true);
  });

  test(`component: ${definition.id} rejects a container still running after attach`, async () => {
    const result = await refused({ caseIndex, afterPatch: { running: true, status: 'running' } });
    assert.equal(result.report.cases[caseIndex].observedExitCode, null);
    assert.equal(result.failed.started, true);
    assert.equal(result.failed.removed, true);
  });
}

const unsafe = [
  ['user', '0:0'], ['network', 'bridge'], ['readonly', false], ['privileged', true],
  ['capDrop', []], ['capDrop', ['ALL', 'CHOWN']], ['capAdd', ['SYS_ADMIN']],
  ['securityOpt', []], ['securityOpt', ['no-new-privileges:true', 'seccomp=unconfined']],
  ['mounts', 1], ['binds', 1], ['ports', 1], ['devices', 1], ['pidMode', 'host'],
  ['memory', 0], ['nanoCpus', 0], ['pids', -1], ['logDriver', 'json-file'],
  ['healthDisabled', false], ['openStdin', true], ['tty', true],
];
for (const phase of ['before', 'after']) {
  for (const [index, [field, value]] of unsafe.entries()) {
    test(`component: ${phase} confinement rejects ${field} variant ${index}`, async () => {
      const result = await refused({ [`${phase}Patch`]: { [field]: value } });
      assert.equal(result.failed.started, phase === 'after');
      assert.equal(result.failed.removed, true);
      assert.equal(result.report.cases[0].observedExitCode, null);
    });
  }
}

for (const [field, value] of [
  ['id', 'f'.repeat(64)], ['name', '/FOREIGN_NAME_CANARY'],
  ['image', `sha256:${'f'.repeat(64)}`], ['run', 'FOREIGN_RUN_CANARY'],
]) {
  test(`component: foreign ${field} forbids both start and deletion`, async () => {
    const result = await refused({ identityPatch: { [field]: value } }, 'CLEANUP_UNCONFIRMED');
    assert.equal(result.failed.started, false);
    assert.equal(result.failed.removed, false);
    assert.equal(result.calls.filter(({ args }) => args[1] === 'rm').length, 0);
  });

  test(`component: ${field} changes after start fail even if cleanup later verifies ownership`, async () => {
    const result = await refused({ afterPatch: { [field]: value } });
    assert.equal(result.failed.started, true);
    assert.equal(result.failed.removed, true);
    assert.equal(result.report.cases[0].observedExitCode, null);
  });
}

for (const [label, afterPatch] of [
  ['created', { status: 'created' }], ['restarting', { status: 'restarting' }],
  ['missing status', { status: null }], ['negative exit', { exitCode: -1 }],
  ['oversized exit', { exitCode: 256 }], ['fractional exit', { exitCode: 1.5 }],
  ['string exit', { exitCode: '1' }], ['null exit', { exitCode: null }],
]) {
  test(`component: invalid terminal observation rejects ${label}`, async () => {
    const result = await refused({ afterPatch });
    assert.equal(result.report.cases[0].observedExitCode, null);
    assert.equal(result.failed.started, true);
    assert.equal(result.failed.removed, true);
  });
}

for (const beforePatch of [{ running: true }, { status: 'exited' }]) {
  test('component: previously started or exited object must not be restarted', async () => {
    const result = await refused({ beforePatch });
    assert.equal(result.failed.started, false);
    assert.equal(result.failed.removed, true);
  });
}

for (const startFailure of ['COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT', 'RAW_CODE_CANARY']) {
  test(`component: attach ${startFailure} fails despite a matching inspected exit`, async () => {
    const result = await refused({ caseIndex: 3, startFailure });
    assert.equal(result.failed.started, true);
    assert.equal(result.failed.removed, true);
    assert.equal(result.report.cases[3].observedExitCode, 1);
  });
}

test('component: positive control cannot accept a failed CLI result despite observed exit zero', async () => {
  const result = await refused({ caseIndex: 7, startFailure: 'COMMAND_FAILED' });
  assert.equal(result.report.cases[7].observedExitCode, 0);
  assert.equal(result.failed.removed, true);
});

for (const startResult of [{ ok: true, code: 'COMMAND_TIMEOUT', stdout: '' },
  { ok: false, code: 'OK', stdout: '' }, { ok: true, code: 'OK', stdout: null }]) {
  test('component: contradictory or unknown attach fields cannot prove a negative case passed', async () => {
    const result = await refused({ startResult });
    assert.equal(result.report.cases[0].observedExitCode, 1);
    assert.equal(result.failed.removed, true);
  });
}

for (const [label, options] of [
  ['lost create reply', { createLost: true }], ['thrown create', { createThrows: true }],
  ['malformed create ID', { createOutput: 'RAW_ID_CANARY' }],
  ['multiple create IDs', { createOutput: `${'a'.repeat(64)}\n${'b'.repeat(64)}\n` }],
]) {
  test(`component: ${label} recovers exact ownership but still stops the suite`, async () => {
    const result = await refused({ ...options, caseIndex: 2 });
    assert.equal(result.failed.started, false);
    assert.equal(result.failed.removed, true);
    assert.equal(result.report.cases[2].containerId, result.failed.id);
    assert.equal(result.report.imageId, imageId);
  });
}

for (const [label, options] of [
  ['object not found', { createAbsent: true }], ['lookup failure', { lookupFailure: true }],
  ['duplicate ownership matches', { duplicate: true }], ['ownership inspect failure', { inspectFailure: true }],
]) {
  test(`component: ${label} cannot confirm cleanup or create another case`, async () => {
    const result = await refused({ ...options, caseIndex: 2 }, 'CLEANUP_UNCONFIRMED');
    assert.equal(result.failed.removed, false);
    assert.equal(result.calls.filter(({ args }) => args[1] === 'rm').length, 2);
    if (options.createAbsent) {
      assert.equal(result.calls.filter(({ args }) => args[1] === 'ls' &&
        args.includes(`name=^/${result.failed.name}$`)).length, 3, 'missing-object lookup has only three attempts');
    }
  });
}

for (const options of [{ removeFailure: true }, { leak: true }]) {
  test('component: failed removal or remaining owned object overrides a passing case', async () => {
    const result = await refused({ ...options, caseIndex: 2 }, 'CLEANUP_UNCONFIRMED');
    assert.equal(result.failed.started, true);
    assert.equal(result.report.cases[2].observedExitCode, 1);
    assert.equal(result.calls.filter(({ args }) => args[1] === 'rm').length, 3);
  });
}

for (const options of [{ confinementInspectFailure: true }, { inspectOutput: 'RAW_INSPECT_CANARY' },
  { inspectOutput: 'x'.repeat(4097) }, { inspectOutput: 'null' }, { inspectOutput: '[]' }]) {
  test('component: bad confinement observation does not weaken ownership-only cleanup', async () => {
    const result = await refused(options);
    assert.equal(result.failed.started, false);
    assert.equal(result.failed.removed, true);
    const inspections = result.calls.filter(({ args }) => args[1] === 'inspect' && args[0] === 'container');
    assert.equal(inspections.length, 2);
    assert.deepEqual(inspections[1].args,
      ['container', 'inspect', '--format', ownershipProjection, result.failed.id]);
  });
}
