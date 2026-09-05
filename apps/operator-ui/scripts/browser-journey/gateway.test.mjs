import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import { once } from 'node:events';
import { gateway } from './gateway.mjs';

async function listen(handler) {
  const server = http.createServer(handler); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return server;
}
function close(server) { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); }
function request(server, path, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port: server.address().port, path, method: options.method ?? 'GET',
      headers: { host: 'console.example', ...options.headers }, agent: false }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(1000, () => req.destroy(new Error('test timeout'))); req.on('error', reject); req.end(options.body);
  });
}
async function fixture(t, handler, options = {}) {
  const upstream = await listen(handler);
  const assets = new Map([['/index.html', { body: Buffer.from('<main>actual fixture file</main>'), type: 'text/html' }],
    ['/assets/app.js', { body: Buffer.from('export const builtAsset = true;'), type: 'text/javascript' }]]);
  const controller = new AbortController();
  const front = await listen(gateway({ backend: { hostname: '127.0.0.1', port: upstream.address().port },
    assets, signal: controller.signal, timeoutMs: 100, requestLimit: 64, responseLimit: 128, ...options }));
  t.after(async () => { controller.abort(); await Promise.all([close(front), close(upstream)]); });
  return { front, controller };
}
test('real loopback proxy preserves OAuth redirects/cookies and management body without retry', async t => {
  const seen = [];
  const { front } = await fixture(t, (req, res) => {
    let body = ''; req.on('data', chunk => { body += chunk; }); req.on('end', () => {
      seen.push({ path: req.url, body, origin: req.headers.origin });
      res.writeHead(303, { location: '/', 'set-cookie': ['__Host-apex_session=opaque; Secure; HttpOnly; SameSite=Lax; Path=/'],
        'cache-control': 'no-store' }); res.end();
    });
  });
  const result = await request(front, '/api/save', { method: 'POST', body: '{"real":"bytes"}', headers: { origin: 'https://console.example' } });
  assert.equal(result.status, 303); assert.equal(result.headers.location, '/');
  assert.equal(result.headers['set-cookie'][0], '__Host-apex_session=opaque; Secure; HttpOnly; SameSite=Lax; Path=/');
  assert.deepEqual(seen, [{ path: '/api/save', body: '{"real":"bytes"}', origin: 'https://console.example' }]);
});
test('static/SPA serving is separate from exact auth/api prefixes and refuses hostile hosts', async t => {
  let calls = 0;
  const { front } = await fixture(t, (_req, res) => { calls++; res.setHeader('cache-control', 'no-store'); res.end('upstream'); });
  const asset = await request(front, '/assets/app.js');
  assert.equal(asset.body, 'export const builtAsset = true;');
  assert.equal(asset.headers['cache-control'], 'no-store');
  assert.equal((await request(front, '/mcp-proxies/new')).body, '<main>actual fixture file</main>');
  assert.equal((await request(front, '/api/session')).body, 'upstream');
  assert.equal((await request(front, '/authentication')).status, 404);
  assert.equal((await request(front, '/assets/missing.js')).status, 404);
  assert.equal((await request(front, '/api/session', { headers: { host: 'evil.example' } })).status, 400);
  assert.equal(calls, 1);
});
test('oversized requests are refused before upstream dispatch', async t => {
  let calls = 0;
  const { front } = await fixture(t, (_req, res) => { calls++; res.end(); });
  const response = await request(front, '/api/save', { method: 'POST', body: 'x'.repeat(65) });
  assert.equal(response.status, 413); assert.equal(calls, 0);
});
test('oversized and token-bearing upstream replies are never relayed', async t => {
  let calls = 0;
  const { front } = await fixture(t, (_req, res) => { calls++; res.setHeader('cache-control', 'no-store');
    res.end(calls === 1 ? 'x'.repeat(129) : '{"access_token":"secret-canary"}'); });
  for (let i = 0; i < 2; i++) {
    const response = await request(front, '/api/read'); assert.equal(response.status, 502);
    assert.equal(response.body.includes('secret-canary'), false); assert.equal(response.body.length, 0);
  }
  assert.equal(calls, 2);
});
test('absolute proxy deadline terminates trickled replies instead of resetting per chunk', async t => {
  const intervals = [];
  const { front } = await fixture(t, (_req, res) => { res.setHeader('cache-control', 'no-store');
    const timer = setInterval(() => res.write('a'), 5); intervals.push(timer); res.on('close', () => clearInterval(timer)); }, { timeoutMs: 35 });
  t.after(() => intervals.forEach(clearInterval));
  assert.equal((await request(front, '/api/read')).status, 502);
});
test('a dead upstream yields an empty unavailable response, never fallback inventory', async t => {
  let violations = 0;
  const { front } = await fixture(t, (req) => req.socket.destroy(), { onViolation: () => { violations++; } });
  const response = await request(front, '/api/session');
  assert.equal(response.status, 502); assert.equal(response.body, ''); assert.equal(violations, 0);
});
test('escaped provider-token keys are rejected after JSON decoding, not just raw text scanning', async t => {
  const { front } = await fixture(t, (_req, res) => {
    res.setHeader('cache-control', 'no-store');
    res.setHeader('content-type', 'application/json'); res.end('{"\\u0061ccess_token":"secret-canary"}');
  });
  const response = await request(front, '/api/read');
  assert.equal(response.status, 502); assert.equal(response.body, '');
});
test('global cancellation terminates already active proxy I/O', { timeout: 1000 }, async t => {
  let entered; const started = new Promise(resolve => { entered = resolve; });
  const { front, controller } = await fixture(t, () => entered());
  const pending = request(front, '/api/session');
  assert.equal(await Promise.race([started.then(() => true), pending.then(() => false)]), true, 'proxy never dispatched');
  controller.abort();
  assert.equal((await pending).status, 502);
});

for (const [name, cache] of [['missing', undefined], ['cacheable', 'public, max-age=3600'],
  ['revalidation-only', 'no-cache'], ['conflicting', 'no-store, public']]) {
  test(`${name} upstream cache policy fails closed without relay, retry or SPA fallback`, async t => {
    let calls = 0; let violations = 0;
    const { front } = await fixture(t, (_req, res) => {
      calls++; if (cache !== undefined) res.setHeader('cache-control', cache);
      res.end('upstream-secret-canary');
    }, { onViolation: () => { violations++; } });
    const response = await request(front, '/api/session');
    assert.equal(response.status, 502); assert.equal(response.body, '');
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(calls, 1); assert.equal(violations, 1);
  });
}

for (const status of [200, 401, 503]) {
  test(`actual upstream no-store ${status} status and body survive unchanged`, async t => {
    let calls = 0; let violations = 0;
    const { front } = await fixture(t, (_req, res) => {
      calls++; res.writeHead(status, { 'cache-control': 'no-store', 'content-type': 'application/json' });
      res.end('{"actual":"upstream"}');
    }, { onViolation: () => { violations++; } });
    const response = await request(front, '/api/session');
    assert.equal(response.status, status); assert.equal(response.body, '{"actual":"upstream"}');
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(calls, 1); assert.equal(violations, 0);
  });
}

test('an upstream unavailable response missing no-store is a violation, not accepted as the offline proof', async t => {
  let violations = 0;
  const { front } = await fixture(t, (_req, res) => { res.writeHead(502); res.end(); },
    { onViolation: () => { violations++; } });
  const response = await request(front, '/api/session');
  assert.equal(response.status, 502); assert.equal(response.body, ''); assert.equal(violations, 1);
});
