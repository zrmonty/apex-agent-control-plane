import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDiagnostics } from './diagnostics.mjs';

test('unknown dependency failures use the current static component without exposing error data', () => {
  const diagnostics = createDiagnostics();
  const failure = new Error('secret-canary https://not-an-allowed-output.invalid/?code=secret-canary');
  failure.stack = 'stack-secret-canary';
  for (const phase of ['configuration', 'browser', 'login', 'scope', 'response', 'inventory',
    'privacy', 'artifact', 'identity', 'protocol', 'offline', 'logout']) {
    diagnostics.phase(phase);
    assert.equal(diagnostics.category(failure), phase);
  }
});

test('an explicit cookie lifetime rejection is never replaced by the surrounding component', () => {
  const diagnostics = createDiagnostics(); diagnostics.phase('privacy');
  assert.equal(diagnostics.category(new Error('cookie_lifetime')), 'cookie_lifetime');
  assert.equal(diagnostics.category(new Error('cookie')), 'cookie');
  assert.equal(diagnostics.category(new Error('cleanup')), 'cleanup');
});

test('non-errors and forged diagnostic strings cannot become output', () => {
  const diagnostics = createDiagnostics(); diagnostics.phase('identity');
  for (const error of ['secret-canary', { message: 'cookie_lifetime' }, null, undefined,
    new Error('cookie_lifetime\nsecret-canary'), new Error('cookie_lifetime secret-canary')]) {
    assert.equal(diagnostics.category(error), 'identity');
  }
  diagnostics.phase('secret-canary');
  assert.equal(diagnostics.category(new Error('secret-canary')), 'internal');
});

test('unknown early failures retain a static configuration category before any phase notification', () => {
  assert.equal(createDiagnostics().category(new Error('path-secret-canary')), 'configuration');
});
