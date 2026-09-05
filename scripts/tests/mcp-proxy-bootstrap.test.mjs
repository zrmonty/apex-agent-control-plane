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
