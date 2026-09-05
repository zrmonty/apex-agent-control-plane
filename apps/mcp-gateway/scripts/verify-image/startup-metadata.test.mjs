// Projection/CLI command-boundary coverage only; no Go-template or image execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { main } from '../verify-image.mjs';
import { verifyStartup } from './startup.mjs';
import { imageId, ownershipProjection, startupBoundary } from './startup-fixtures.mjs';

const invalidMetadata = [
  ['foreign ID', { id: 'RAW_IMAGE_CANARY' }], ['array ID', { id: [imageId] }],
  ['missing ID', { id: undefined }], ['declared volumes', { volumeCount: 1 }],
  ['unknown volumes', { volumeCount: null }], ['string volumes', { volumeCount: '0' }],
  ['baked APEX selector', { apexSelectors: '1' }], ['unknown APEX count', { apexSelectors: null }],
  ['numeric APEX count', { apexSelectors: 0 }], ['missing NODE_ENV', { nodeEnvEntries: '' }],
  ['duplicate NODE_ENV', { nodeEnvEntries: '11' }], ['numeric NODE_ENV count', { nodeEnvEntries: 1 }],
  ['non-production NODE_ENV', { productionEntries: '' }], ['duplicate production', { productionEntries: '11' }],
  ['missing production count', { productionEntries: undefined }],
  ['changed entrypoint', { entrypointExpected: false }], ['unknown entrypoint', { entrypointExpected: null }],
  ['string entrypoint flag', { entrypointExpected: 'true' }], ['nonempty CMD', { cmdEmpty: false }],
  ['unknown CMD', { cmdEmpty: null }], ['changed working directory', { workingDirExpected: false }],
  ['unknown working directory', { workingDirExpected: null }], ['extra field', { secret: 'RAW_METADATA_CANARY' }],
];

async function rejectedImage(options) {
  const boundary = startupBoundary(options);
  const report = await verifyStartup('example:startup', boundary.execute);
  assert.equal(report.ok, false);
  assert.equal(report.code, 'STARTUP_FAILED');
  assert.equal(report.imageId, null);
  assert.equal(report.readinessVerified, false);
  assert.equal(report.protocolHandshakeVerified, false);
  assert.equal(report.cases.length, 8);
  assert.ok(report.cases.every(({ passed, runId, containerId, observedExitCode }) =>
    !passed && runId === null && containerId === null && observedExitCode === null));
  assert.equal(boundary.containers.length, 0);
  assert.equal(boundary.calls.length, 1);
  assert.ok(JSON.stringify(report).length < 4096);
  assert.doesNotMatch(JSON.stringify(report), /CANARY/);
}

for (const [label, imagePatch] of invalidMetadata) {
  test(`component: image ${label} fails before creating a container`, () => rejectedImage({ imagePatch }));
}
for (const [label, options] of [
  ['timeout', { imageFailure: true }], ['malformed JSON', { imageOutput: 'RAW_JSON_CANARY' }],
  ['oversized projection', { imageOutput: 'x'.repeat(4097) }], ['null', { imageOutput: 'null' }],
  ['array', { imageOutput: '[]' }], ['number', { imageOutput: '0' }], ['empty', { imageOutput: '' }],
]) {
  test(`component: image inspection ${label} fails before creating a container`, () => rejectedImage(options));
}

test('component: image defaults use guarded count/boolean projections, never raw config values', async () => {
  const boundary = startupBoundary();
  assert.equal((await verifyStartup('example:startup', boundary.execute)).ok, true);
  const format = boundary.calls[0].args[3];
  assert.ok(format.includes('"volumeCount":{{if index .Config "Volumes"}}{{len (index .Config "Volumes")}}{{else}}0{{end}}'));
  for (const [field, prefix] of [['apexSelectors', 'APEX_MCP_'], ['nodeEnvEntries', 'NODE_ENV=']]) {
    assert.ok(format.includes(`"${field}":"{{range .Config.Env}}{{if ge (len .) 9}}` +
      `{{if eq (slice . 0 9) "${prefix}"}}1{{end}}{{end}}{{end}}"`));
  }
  assert.ok(format.includes('"productionEntries":"{{range .Config.Env}}{{if eq . "NODE_ENV=production"}}1{{end}}{{end}}"'));
  assert.ok(format.includes('"entrypointExpected":{{if index .Config "Entrypoint"}}{{if eq (len .Config.Entrypoint) 2}}'));
  assert.ok(format.includes('(eq (index .Config.Entrypoint 0) "node") (eq (index .Config.Entrypoint 1) "dist/index.js")'));
  assert.ok(format.includes('"cmdEmpty":{{if index .Config "Cmd"}}false{{else}}true{{end}}'));
  assert.ok(format.includes('"workingDirExpected":{{if eq .Config.WorkingDir "/app/apps/mcp-gateway"}}true{{else}}false{{end}}'));
  assert.deepEqual([...format.matchAll(/\{\{json ([^}]+)\}\}/g)].map((match) => match[1]), ['.Id']);
  assert.doesNotMatch(format, /\{\{(?:\.Config|\.)\}\}|\{\{printf/);
});

test('component: container projections verify startup guards and cleanup excludes unrelated fields', async () => {
  const boundary = startupBoundary();
  assert.equal((await verifyStartup('example:startup', boundary.execute)).ok, true);
  const inspections = boundary.calls.filter(({ args }) => args[0] === 'container' && args[1] === 'inspect');
  assert.equal(inspections.length, 24);
  for (let index = 0; index < inspections.length; index += 3) {
    assert.equal(inspections[index].args[3], inspections[index + 1].args[3]);
    const format = inspections[index].args[3];
    assert.ok(format.includes('"status":{{json .State.Status}}'));
    assert.ok(format.includes('"logDriver":{{json .HostConfig.LogConfig.Type}}'));
    assert.ok(format.includes('"openStdin":{{json .Config.OpenStdin}},"tty":{{json .Config.Tty}}'));
    assert.ok(format.includes('"healthDisabled":{{if index .Config "Healthcheck"}}{{if eq (len .Config.Healthcheck.Test) 1}}'));
    assert.ok(format.includes('{{if eq (index .Config.Healthcheck.Test 0) "NONE"}}true{{else}}false{{end}}'));
    assert.doesNotMatch(format, /\{\{json \.Config\.(?:Env|Entrypoint|Cmd|Healthcheck)/);
    assert.equal(inspections[index + 2].args[3], ownershipProjection);
  }
});

test('component: all eight cases confirm ID and scoped-name absence before the next create', async () => {
  const boundary = startupBoundary();
  assert.equal((await verifyStartup('example:startup', boundary.execute)).ok, true);
  const commands = boundary.calls.map(({ args }) => args.slice(0, 2).join(' '));
  assert.deepEqual(commands, ['image inspect', ...Array.from({ length: 8 }, () => [
    'container create', 'container inspect', 'container start', 'container inspect',
    'container ls', 'container inspect', 'container rm', 'container ls', 'container ls',
  ]).flat()]);
  assert.equal(commands.length, 73);
  for (let i = 0; i < 8; i++) {
    const offset = 1 + i * 9;
    const id = boundary.containers[i].id;
    assert.ok(boundary.calls[offset + 7].args.includes(`id=${id}`));
    assert.ok(boundary.calls[offset + 8].args.includes(`name=^/${boundary.containers[i].name}$`));
    assert.equal(boundary.calls[offset].limits.timeoutMs, 30_000);
    assert.equal(boundary.calls[offset + 2].limits.timeoutMs, 20_000);
    assert.ok(boundary.calls.slice(offset + 4, offset + 9).every(({ limits }) => limits.timeoutMs === 10_000));
  }
});

test('component: startup dispatch also accepts suite-first order without a packaging eval override', async () => {
  const boundary = startupBoundary();
  const report = await main(['--suite', 'startup', '--image', 'example:startup'], boundary.execute);
  assert.equal(report.ok, true);
  assert.equal(report.type, 'image-startup-verification');
  assert.ok(boundary.calls.every(({ args }) => !args.includes('--eval') && !args.includes('--entrypoint')));
});

const invalidArgs = [
  [], ['--image', 'x'], ['--image', 'x', '--suite', 'startup', '--extra', 'CANARY'],
  ['--image', 'x', '--image', 'y'], ['--suite', 'startup', '--suite', 'startup'],
  ['--image', '--bad', '--suite', 'startup'], ['--image', 'x;CANARY', '--suite', 'startup'],
  ['--image', 'x\nCANARY', '--suite', 'startup'], ['--image', '', '--suite', 'startup'],
  ['--image', 'x'.repeat(256), '--suite', 'startup'], ['--image', 'x', '--suite', 'STARTUP'],
  ['--image', 'x', '--suite', 'startup\0CANARY'], ['--env', 'CANARY', '--suite', 'startup'],
];
test('component: strict startup CLI rejects malformed input and never calls the command boundary', async () => {
  let calls = 0;
  const forbidden = async () => { calls++; throw Error('RAW_BOUNDARY_CANARY'); };
  for (const args of invalidArgs) {
    const report = await main(args, forbidden);
    assert.deepEqual(report, { type: 'image-packaging-verification', ok: false,
      code: args.at(-1) === 'STARTUP' ? 'UNSUPPORTED_SUITE' : 'INVALID_ARGUMENTS', readinessVerified: false });
  }
  assert.equal(calls, 0, 'validation retains the legacy error contract before suite dispatch');
});

test('component: direct startup API rejects invalid image references without commands', async () => {
  let calls = 0;
  for (const image of [undefined, null, [], '', '--flag', 'x y', 'x;CANARY', 'x'.repeat(256)]) {
    const report = await verifyStartup(image, async () => { calls++; throw Error('RAW_BOUNDARY_CANARY'); });
    assert.equal(report.code, 'STARTUP_FAILED');
    assert.equal(report.imageId, null);
    assert.equal(report.readinessVerified, false);
    assert.equal(report.protocolHandshakeVerified, false);
  }
  assert.equal(calls, 0);
});

test('actual CLI rejects malformed startup arguments with one static JSON result before Docker', () => {
  const cli = fileURLToPath(new URL('../verify-image.mjs', import.meta.url));
  const result = spawnSync(process.execPath,
    [cli, '--image', 'RAW_CLI_CANARY;bad', '--suite', 'startup'],
    { encoding: 'utf8', timeout: 3000, maxBuffer: 4096, windowsHide: true });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 2);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout, JSON.stringify({ type: 'image-packaging-verification', ok: false,
    code: 'INVALID_ARGUMENTS', readinessVerified: false }) + '\n');
});
