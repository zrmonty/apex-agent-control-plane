import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PassThrough } from 'node:stream';
import { backendAddress, allowedBrowserUrl, requestPath, safeHeaders, verifiedProxy } from './policy.mjs';
import { parentProtocol } from './protocol.mjs';

test('BFF target accepts only a literal IPv4 loopback and valid port', () => {
  assert.deepEqual(backendAddress('127.0.0.1:18490'), { hostname: '127.0.0.1', port: 18490 });
  for (const input of [undefined, 'localhost:80', '127.0.0.2:80', '127.0.0.1:0', '127.0.0.1:65536',
    'http://127.0.0.1:80', '127.0.0.1:080', '127.0.0.1:80/path', '127.0.0.1:80\n', '[::1]:80']) {
    assert.throws(() => backendAddress(input), undefined, 'unsafe backend accepted');
  }
});
test('browser origin guard rejects remote origins, credentials and non-HTTPS schemes', () => {
  for (const url of ['https://console.example/', 'https://console.example:443/api/session',
    'https://127.0.0.1:18451/realms/apex/login-actions/authenticate?a=b']) assert.equal(allowedBrowserUrl(url), true);
  for (const url of ['https://console.example.evil/', 'https://console.example:444/',
    'http://console.example/', 'https://user@console.example/', 'https://127.0.0.1:18461/',
    'https://localhost:18451/', 'file:///etc/passwd', 'data:text/html,x', 'not a url']) {
    assert.equal(allowedBrowserUrl(url), false);
  }
});
test('raw frontend path validation blocks traversal, smuggling and oversized URLs', () => {
  assert.equal(requestPath('/auth/callback?code=abc%2Bdef&state=xyz'), '/auth/callback');
  assert.equal(requestPath('/assets/a-font.woff2'), '/assets/a-font.woff2');
  for (const path of ['https://evil.test/', '//evil.test/a', '/../secret', '/%2e%2e/secret',
    '/assets/%2fsecret', '/a\\b', '/a%00b', '/a%5cb', '/a%ZZ', '/a\n', '/' + 'x'.repeat(8192)]) {
    assert.throws(() => requestPath(path), undefined, 'unsafe path accepted');
  }
});
test('proxy drops hop-by-hop, nominated headers, forwarding authority and compression', () => {
  const clean = safeHeaders({ host: 'console.example', connection: 'keep-alive, x-remove',
    'x-remove': 'secret', 'keep-alive': 'timeout=500', 'proxy-authorization': 'secret',
    'x-forwarded-for': 'evil', forwarded: 'host=evil', 'transfer-encoding': 'chunked',
    'accept-encoding': 'gzip', cookie: 'opaque', origin: 'https://console.example', 'x-apex-csrf': 'proof' });
  assert.deepEqual(clean, { host: 'console.example', cookie: 'opaque', origin: 'https://console.example', 'x-apex-csrf': 'proof' });
});
test('saved identity must be a real matching acme/prod UUIDv7 response', () => {
  const proxy = { proxyId: '01990000-1234-7000-8000-123456789abc', workspaceId: 'acme', namespaceId: 'prod',
    displayName: 'Browser journey draft', slug: 'browser-journey-draft' };
  assert.equal(verifiedProxy({ proxy }, proxy.displayName, proxy.slug), proxy.proxyId);
  for (const delta of [{ proxyId: 'not-a-uuid' }, { proxyId: '01990000-1234-4000-8000-123456789abc' },
    { workspaceId: 'other' }, { namespaceId: 'dev' }, { displayName: 'fabricated' }, { slug: 'other' }]) {
    assert.throws(() => verifiedProxy({ proxy: { ...proxy, ...delta } }, proxy.displayName, proxy.slug));
  }
});
test('parent protocol emits only ordered LF markers and waits for each acknowledgement', async () => {
  const input = new PassThrough(); const output = new PassThrough(); const abort = new AbortController();
  let text = ''; output.on('data', bytes => { text += bytes; });
  const protocol = parentProtocol(input, output, abort, 100);
  try {
    let complete = false;
    const down = protocol.exchange('D').then(() => { complete = true; });
    assert.equal(text, 'UI_READY_FOR_RESTART\n');
    await Promise.resolve(); assert.equal(complete, false);
    input.write('D'); await Promise.resolve(); assert.equal(complete, false);
    input.write('\n'); await down;
    const up = protocol.exchange('R'); input.write('R\n'); await up;
    protocol.passed();
    assert.equal(text, 'UI_READY_FOR_RESTART\nUI_OFFLINE_OBSERVED\nUI_JOURNEY_PASSED\n');
  } finally { protocol.dispose(); input.destroy(); output.destroy(); }
});
for (const invalid of ['R\n', 'D\r\n', 'D\nR\n', 'secret-canary'.repeat(100)]) {
  test('parent protocol cancels malformed or premature control input without reflecting it', async () => {
    const input = new PassThrough(); const output = new PassThrough(); const abort = new AbortController();
    const protocol = parentProtocol(input, output, abort, 50);
    try {
      const pending = protocol.exchange('D'); const check = assert.rejects(pending, { message: 'protocol' });
      input.write(invalid); await check;
      assert.equal(abort.signal.aborted, true);
      assert.equal(String(abort.signal.reason).includes('secret-canary'), false);
    } finally { protocol.dispose(); input.destroy(); output.destroy(); }
  });
}
test('stdin EOF cancels an active journey even outside acknowledgement waits', async () => {
  const input = new PassThrough(); const output = new PassThrough(); const abort = new AbortController();
  const protocol = parentProtocol(input, output, abort, 50);
  try {
    input.end(); await new Promise(resolve => setImmediate(resolve));
    assert.equal(abort.signal.aborted, true);
  } finally { protocol.dispose(); input.destroy(); output.destroy(); }
});
test('missing parent acknowledgement has a real bounded timeout', async () => {
  const input = new PassThrough(); const output = new PassThrough(); const abort = new AbortController();
  const protocol = parentProtocol(input, output, abort, 20);
  try { await assert.rejects(protocol.exchange('D'), { message: 'protocol' }); }
  finally { protocol.dispose(); input.destroy(); output.destroy(); }
});
