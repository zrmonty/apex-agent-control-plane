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

for (const operation of ['initial_inventory', 'create', 'detail_reload', 'inventory_reload', 'restored_inventory']) {
  for (const stage of ['wait', 'status', 'cache', 'body', 'size', 'utf8', 'json']) {
    test(`only the exact ${operation} ${stage} response category can cross the diagnostic boundary`, () => {
      const category = `response_${operation}_${stage}`;
      const diagnostics = createDiagnostics(); diagnostics.phase(category);
      assert.equal(diagnostics.category(new Error('secret-canary')), category);
      diagnostics.phase('identity');
      assert.equal(diagnostics.category(new Error(category)), category);
      for (const forged of [`${category}\nsecret-canary`, `${category} secret-canary`, `${category}_extra`]) {
        assert.equal(diagnostics.category(new Error(forged)), 'identity');
        diagnostics.phase(forged);
        assert.equal(diagnostics.category(new Error('secret-canary')), 'internal');
        diagnostics.phase('identity');
      }
    });
  }
}

test('response vocabulary does not accept arbitrary operation or stage suffixes', () => {
  const diagnostics = createDiagnostics(); diagnostics.phase('identity');
  for (const label of ['response_secret-canary_body', 'response_create_secret-canary',
    'response_create_body_502', 'response_detail_reload_url', 'response_create_body\r\n']) {
    assert.equal(diagnostics.category(new Error(label)), 'identity');
  }
});
