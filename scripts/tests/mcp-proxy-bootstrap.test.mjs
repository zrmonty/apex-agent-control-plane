// Source-policy checks only: this is not a YAML parser, Compose validation,
// startup execution, or readiness proof. Main validates resolved Compose JSON.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

function source(path) {
  return readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8').replaceAll('\r\n', '\n');
}

function proxyServiceSource() {
  const lines = source('deploy/compose/compose.mcp-proxy.yaml').split('\n');
  const heading = '  mcp-proxy-portfolio:';
  assert.equal(lines.filter((line) => line === heading).length, 1);
  const start = lines.indexOf(heading);
  const end = lines.findIndex((line, index) => index > start && /^  \S/.test(line));
  assert.ok(end > start, 'expected the known following fixture service');
  return `${lines.slice(start + 1, end).join('\n')}\n`;
}

test('source-only: bootstrap health is explicitly disabled without the known always-pass probe', () => {
  const service = proxyServiceSource();
  assert.doesNotMatch(service, /process\.exit\(\s*0\s*\)/);
  assert.equal(service.match(/^    healthcheck:$/gm)?.length, 1);
  const health = service.match(/^    healthcheck:\n((?: {6}[^\n]*\n)*)/m)?.[1];
  assert.equal(health, '      disable: true\n');
});

test('source-only: bootstrap proxy explicitly selects managed profile and live governance', () => {
  const service = proxyServiceSource();
  const environment = service.match(/^    environment:\n((?: {6}[^\n]*\n)*)/m)?.[1];
  assert.ok(environment, 'expected the known proxy environment mapping');
  for (const [key, expected] of [
    ['APEX_MCP_PROFILE', 'managed'],
    ['APEX_MCP_GOVERNANCE_MODE', 'live'],
  ]) {
    const values = [...environment.matchAll(new RegExp(`^      ${key}: (.*)$`, 'gm'))];
    assert.deepEqual(values.map((match) => match[1]), [expected], key);
  }
});

test('source-only: local example explicitly selects development standalone without managed sources', () => {
  const environment = source('apps/mcp-gateway/.env.example');
  for (const [key, expected] of [
    ['NODE_ENV', 'development'],
    ['APEX_MCP_PROFILE', 'development-standalone'],
    ['APEX_MCP_GOVERNANCE_MODE', 'local'],
  ]) {
    const values = [...environment.matchAll(new RegExp(`^${key}=(.*)$`, 'gm'))];
    assert.deepEqual(values.map((match) => match[1]), [expected], key);
  }
  assert.doesNotMatch(environment, /^\s*(?:export\s+)?APEX_MCP_PROXY_REVISION_CONFIG(?:_FILE)?\s*=/m);
});

function liveStepWith(command) {
  const steps = source('.github/workflows/live-mtls-e2e.yml').split(/^      - name: /m);
  const matching = steps.filter((step) => step.includes(command));
  assert.equal(matching.length, 1, 'expected one live proof step');
  return matching[0];
}

test('source-only: bootstrap CI runs real image safety checks and retains container isolation inspection', () => {
  const step = liveStepWith('docker compose $P build mcp-proxy-portfolio');
  const install = 'pnpm --dir ../../apps/mcp-gateway install --frozen-lockfile --ignore-scripts';
  const harnessTests = 'node --test ../../apps/mcp-gateway/scripts/verify-image/*.test.mjs';
  assert.ok(step.indexOf(install) >= 0 && step.indexOf(install) < step.indexOf(harnessTests),
    'host descriptor tests require installed gateway dependencies before they run');
  assert.match(step, /node .*verify-image\.mjs --image "\$image" --suite packaging/);
  assert.match(step, /node .*verify-image\.mjs --image "\$image" --suite startup/);
  assert.match(step, /docker compose \$P create --no-build mcp-proxy-portfolio/);
  assert.match(step, /docker compose \$P ps -a -q mcp-proxy-portfolio/);
  assert.match(step, /APEX_CONTROL_LIVE_MCP_PROXY_RUNTIME=1/);
  assert.match(step, /cargo test -p apex-control-plane-api --test live_mcp_proxy_runtime/);
  assert.doesNotMatch(step, /State\.Health|\bhealthy\b|up -d/);
});

test('source-only: live stdio proof opts into development startup but retains real governance', () => {
  const step = liveStepWith('node scripts/live_proof.mjs');
  assert.match(step, /^          NODE_ENV: development$/m);
  assert.match(step, /^          APEX_MCP_PROFILE: development-standalone$/m);
  assert.match(step, /^          APEX_MCP_GOVERNANCE_MODE: live$/m);
  assert.doesNotMatch(step, /APEX_MCP_PROXY_REVISION_CONFIG|APEX_MCP_GOVERNANCE_MODE: local/);
  assert.match(step, /verify_mcp_projection\.py/);
});
