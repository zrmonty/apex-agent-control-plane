import assert from 'node:assert/strict';
import test from 'node:test';
import { main } from '../verify-image.mjs';
import { expectedCases, expectedIdentity, imageId, startupBoundary } from './startup-fixtures.mjs';

test('component: startup suite runs eight fixed original-entrypoint cases with confirmed scoped cleanup', async () => {
  const boundary = startupBoundary();
  const report = await main(['--image', 'example:startup', '--suite', 'startup'], boundary.execute);
  const creates = boundary.calls.filter(({ args }) => args[0] === 'container' && args[1] === 'create');
  for (const { args } of creates) {
    const env = args.flatMap((value, index) => value === '--env' ? [args[index + 1]] : []);
    const identity = env.filter((value) =>
      /^APEX_MCP_(?:PRINCIPAL|AGENT_ID|WORKSPACE_ID|NAMESPACE_ID|TRACE_ID)=/.test(value));
    assert.deepEqual(identity, expectedIdentity, 'every case must supply exactly five valid fixed identity entries');
  }
  assert.equal(creates.length, 8);
  assert.equal(report.ok, true, report.code);
  assert.equal(report.type, 'image-startup-verification');
  assert.equal(report.suite, 'startup');
  assert.equal(report.code, 'STARTUP_OK');
  assert.equal(report.imageId, imageId);
  assert.equal(report.readinessVerified, false);
  assert.equal(report.protocolHandshakeVerified, false);
  assert.deepEqual(Object.keys(report).sort(), ['type', 'suite', 'ok', 'code', 'imageId',
    'cases', 'readinessVerified', 'protocolHandshakeVerified'].sort());
  for (const item of report.cases) {
    assert.deepEqual(Object.keys(item).sort(), ['id', 'passed', 'expectedExitCode',
      'observedExitCode', 'runId', 'containerId'].sort());
    assert.match(item.runId, /^[0-9a-f-]{36}$/);
    assert.match(item.containerId, /^[0-9a-f]{64}$/);
  }
  assert.ok(JSON.stringify(report).length < 4096);
  assert.deepEqual(report.cases.map(({ id, passed, expectedExitCode, observedExitCode }) =>
    ({ id, passed, expectedExitCode, observedExitCode })),
  expectedCases.map(({ id, expectedExitCode }) =>
    ({ id, passed: true, expectedExitCode, observedExitCode: expectedExitCode })));
  assert.equal(boundary.containers.length, 8);
  assert.ok(boundary.containers.every(({ started, removed }) => started && removed));
  assert.equal(new Set(boundary.containers.map(({ name }) => name)).size, 8);
  assert.equal(new Set(boundary.containers.map(({ runId }) => runId)).size, 8);
});
