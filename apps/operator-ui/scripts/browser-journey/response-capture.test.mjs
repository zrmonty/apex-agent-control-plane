import assert from 'node:assert/strict';
import { test } from 'node:test';
import { getEventListeners } from 'node:events';
import { createResponseCapture } from './response-capture.mjs';
import { jsonResponse } from './response.mjs';

const ROOT = 'https://console.example/api/apex/v1/McpProxyService/';
const CANARY = 'private-capture-canary';
const postData = '{"workspaceId":"acme","namespaceId":"prod","requestId":"original-id"}';
function request(id = 'one', method = 'ListProxies', overrides = {}) {
  return { requestId: id, frameId: 'main', request: { method: 'POST', url: ROOT + method,
    postData, headers: { cookie: CANARY, 'x-apex-csrf': CANARY } }, ...overrides };
}
function response(id = 'one', method = 'ListProxies', overrides = {}) {
  return { ...request(id, method), responseStatusCode: 200,
    responseHeaders: [{ name: 'Cache-Control', value: 'no-store' }, { name: 'Set-Cookie', value: CANARY }], ...overrides };
}
function deferred() { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function fixture(t, read = async () => ({ body: '{"proxies":[]}', base64Encoded: false }), continued = async () => {}) {
  const calls = []; const failures = []; const abort = new AbortController();
  const owner = createResponseCapture({ send: (method, params) => {
    calls.push([method, params]);
    return method === 'Fetch.getResponseBody' ? read() : continued();
  } }, { signal: abort.signal, onFailure: value => failures.push(value) });
  t.after(() => owner.dispose());
  return { owner, calls, failures, abort };
}
async function rejected(promise) {
  await assert.rejects(promise, error => {
    assert.equal(error.message, 'response');
    assert.equal(error.cause, undefined);
    assert.ok(!String(error.stack).includes(CANARY));
    return true;
  });
}

test('captures only the bound original response before continuing with no overrides', async t => {
  const bytes = Buffer.from('{"proxies":[],"nextPageToken":"é"}');
  const read = deferred(); const f = fixture(t, () => read.promise);
  const pending = f.owner.expect('CreateProxy');
  f.owner.request(request('one', 'CreateProxy'));
  const handling = f.owner.response(response('one', 'CreateProxy'));
  assert.deepEqual(f.calls, [['Fetch.getResponseBody', { requestId: 'one' }]]);
  read.resolve({ body: bytes.toString('base64'), base64Encoded: true });
  await handling;
  const actual = await pending;
  assert.equal(actual.status(), 200);
  assert.deepEqual(actual.headers(), { 'cache-control': 'no-store' });
  assert.equal(actual.url(), ROOT + 'CreateProxy');
  assert.equal(actual.request().method(), 'POST');
  assert.deepEqual(actual.request().postDataJSON(), JSON.parse(postData));
  assert.deepEqual(await actual.body(), bytes);
  assert.deepEqual(f.calls, [['Fetch.getResponseBody', { requestId: 'one' }], ['Fetch.continueRequest', { requestId: 'one' }]]);
  await f.owner.finish();
  assert.equal(getEventListeners(f.abort.signal, 'abort').length, 0);
  assert.deepEqual(f.failures, []);
});

test('an older response cannot satisfy a later arm even with identical method and URL', async t => {
  const f = fixture(t); f.owner.request(request('old'));
  const pending = f.owner.expect('ListProxies'); let delivered = false;
  pending.then(() => { delivered = true; }, () => {});
  await f.owner.response(response('old'));
  assert.equal(delivered, false);
  assert.deepEqual(f.calls, [['Fetch.continueRequest', { requestId: 'old' }]]);
  f.owner.request(request('new')); await f.owner.response(response('new'));
  assert.deepEqual(await (await pending).body(), Buffer.from('{"proxies":[]}'));
  await f.owner.finish();
});

test('unselected methods and GETs continue without reading or retaining a body', async t => {
  const f = fixture(t); const pending = f.owner.expect('ListProxies');
  const get = { request: { method: 'GET', url: ROOT + 'ListProxies' } };
  f.owner.request(request('get', 'ListProxies', get)); await f.owner.response(response('get', 'ListProxies', get));
  f.owner.request(request('other', 'GetProxy')); await f.owner.response(response('other', 'GetProxy'));
  assert.deepEqual(f.calls, [['Fetch.continueRequest', { requestId: 'get' }], ['Fetch.continueRequest', { requestId: 'other' }]]);
  f.abort.abort(); await rejected(pending);
});

for (const id of [undefined, '', 'x'.repeat(257)]) {
  test(`invalid response ID (${String(id).length} characters) cannot bind an unstarted expectation`, async t => {
    const f = fixture(t); const pending = f.owner.expect('ListProxies');
    await rejected(f.owner.response(response('one', 'ListProxies', { requestId: id, frameId: undefined })));
    await rejected(pending);
    assert.deepEqual(f.calls, []);
  });
}

for (const duplicate of ['arm', 'request-id', 'matching-request', 'response']) {
  test(`ambiguous ${duplicate} fails instead of guessing a capture`, async t => {
    const read = deferred(); const f = fixture(t, () => read.promise);
    const pending = f.owner.expect('ListProxies'); f.owner.request(request());
    let work;
    if (duplicate === 'response') work = f.owner.response(response());
    if (duplicate === 'arm') assert.throws(() => f.owner.expect('ListProxies'), { message: 'response' });
    else if (duplicate === 'request-id') assert.throws(() => f.owner.request(request()), { message: 'response' });
    else if (duplicate === 'matching-request') assert.throws(() => f.owner.request(request('two')), { message: 'response' });
    else await rejected(f.owner.response(response()));
    await rejected(pending);
    read.resolve({ body: '{}', base64Encoded: false });
    if (work) await rejected(work);
    assert.ok(!f.calls.some(([method]) => method === 'Fetch.continueRequest'));
    assert.deepEqual(f.failures, ['response']);
  });
}

for (const [name, overrides] of [
  ['redirect', { responseStatusCode: 302 }], ['redirect-chain', { redirectedRequestId: 'prior' }],
  ['network-error', { responseErrorReason: 'Failed' }], ['frame-mismatch', { frameId: 'other' }],
  ['method-mismatch', { request: { method: 'GET', url: ROOT + 'ListProxies' } }],
  ['URL-mismatch', { request: { method: 'POST', url: ROOT + 'GetProxy' } }],
  ['duplicate-cache', { responseHeaders: [{ name: 'Cache-Control', value: 'no-store' }, { name: 'cache-control', value: 'no-store' }] }],
]) {
  test(`selected ${name} fails before body retrieval`, async t => {
    const f = fixture(t); const pending = f.owner.expect('ListProxies'); f.owner.request(request());
    await rejected(f.owner.response(response('one', 'ListProxies', overrides)));
    await rejected(pending); assert.deepEqual(f.calls, []);
  });
}

for (const [name, wire] of [
  ['bad-base64', { body: 'e31=', base64Encoded: true }],
  ['base64-whitespace', { body: 'e30=\n', base64Encoded: true }],
  ['missing-encoding', { body: '{}' }], ['non-string', { body: {}, base64Encoded: false }],
  ['encoded-overflow', { body: 'A'.repeat(4 * Math.ceil(1024 * 1024 / 3) + 4), base64Encoded: true }],
  ['decoded-overflow', { body: Buffer.alloc(1024 * 1024 + 1).toString('base64'), base64Encoded: true }],
  ['UTF8-byte-overflow', { body: 'é'.repeat(524289), base64Encoded: false }],
  ['unpaired-surrogate', { body: '\ud800', base64Encoded: false }],
]) {
  test(`${name} cannot become an adapter or resume the selected response`, async t => {
    const f = fixture(t, async () => wire); const pending = f.owner.expect('ListProxies'); f.owner.request(request());
    await rejected(f.owner.response(response())); await rejected(pending);
    assert.deepEqual(f.calls, [['Fetch.getResponseBody', { requestId: 'one' }]]);
  });
}

for (const [name, overrides, wire, expected] of [
  ['status', { responseStatusCode: 503 }, '{}', 'response_initial_inventory_status'],
  ['cache', { responseHeaders: [] }, '{}', 'response_initial_inventory_cache'],
  ['utf8', {}, Buffer.from([0xff]).toString('base64'), 'response_initial_inventory_utf8'],
  ['privacy', {}, '{"access_token":"private-capture-canary"}', 'privacy'],
  ['json', {}, '{', 'response_initial_inventory_json'],
]) {
  test(`original ${name} still reaches the existing JSON checker`, async t => {
    const f = fixture(t, async () => ({ body: wire, base64Encoded: name === 'utf8' }));
    const pending = f.owner.expect('ListProxies'); f.owner.request(request());
    await f.owner.response(response('one', 'ListProxies', overrides));
    await assert.rejects(jsonResponse('initial_inventory', () => pending, () => {}), { message: expected });
  });
}

test('exactly one MiB remains accepted and a body can be consumed only once', async t => {
  const bytes = Buffer.alloc(1024 * 1024, 32); bytes.write('{}');
  const f = fixture(t, async () => ({ body: bytes.toString('base64'), base64Encoded: true }));
  const pending = f.owner.expect('ListProxies'); f.owner.request(request()); await f.owner.response(response());
  const actual = await pending; assert.deepEqual(await actual.body(), bytes);
  await rejected(actual.body());
});

test('create post data is required and bounded before reading a response', async t => {
  for (const postData of [undefined, 'x'.repeat(256 * 1024 + 1), '{']) {
    const f = fixture(t); const pending = f.owner.expect('CreateProxy');
    const event = request('one', 'CreateProxy'); event.request.postData = postData;
    assert.throws(() => f.owner.request(event), { message: 'response' });
    await rejected(pending); assert.deepEqual(f.calls, []);
  }
});

for (const phase of ['waiting', 'body', 'continue']) {
  for (const end of ['abort', 'timeout']) {
    test(`${end} during ${phase} rejects once, retains no replacement and never dispatches late`, async t => {
      t.mock.timers.enable({ apis: ['setTimeout'] });
      const held = deferred(); const f = fixture(t,
        () => phase === 'body' ? held.promise : Promise.resolve({ body: '{}', base64Encoded: false }),
        () => phase === 'continue' ? held.promise : Promise.resolve());
      const pending = f.owner.expect('ListProxies'); let work;
      if (phase !== 'waiting') { f.owner.request(request()); work = f.owner.response(response()); }
      await Promise.resolve(); await Promise.resolve();
      if (end === 'abort') f.abort.abort(CANARY); else t.mock.timers.tick(20_000);
      await rejected(pending);
      assert.throws(() => f.owner.expect('ListProxies'), { message: 'response' });
      const count = f.calls.length;
      held.resolve({ body: '{}', base64Encoded: false });
      if (work) await rejected(work);
      assert.equal(f.calls.length, count);
      await rejected(f.owner.finish());
      assert.equal(getEventListeners(f.abort.signal, 'abort').length, 0);
      assert.deepEqual(f.failures, ['response']);
    });
  }
}

test('CDP failure never retains its private message, stack or cause', async t => {
  const f = fixture(t, async () => { throw new Error(CANARY, { cause: CANARY }); });
  const pending = f.owner.expect('ListProxies'); f.owner.request(request());
  await rejected(f.owner.response(response())); await rejected(pending);
  assert.deepEqual(f.failures, ['response']);
});

test('finish refuses an outstanding expectation and releases its listener', async t => {
  const f = fixture(t); const pending = f.owner.expect('ListProxies');
  await rejected(f.owner.finish()); await rejected(pending);
  assert.equal(getEventListeners(f.abort.signal, 'abort').length, 0);
});

test('drain waits for unselected continuation and finish prevents later work', async t => {
  const held = deferred(); const f = fixture(t, undefined, () => held.promise);
  f.owner.request(request('old')); const work = f.owner.response(response('old'));
  let done = false; const finish = f.owner.finish().then(() => { done = true; });
  await Promise.resolve(); assert.equal(done, false);
  held.resolve(); await work; await finish;
  assert.throws(() => f.owner.expect('ListProxies'), { message: 'response' });
  assert.equal(f.calls.length, 1);
});
