import assert from 'node:assert/strict';
import { test } from 'node:test';
import { EventEmitter } from 'node:events';
import { setImmediate as tick } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { observeLoginCookies } from './cookie-observer.mjs';

const token = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const wire = `__Host-apex_login=${token}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`;
const login = { name: '__Host-apex_login', value: token, secure: true, httpOnly: true,
  sameSite: 'Lax', domain: 'console.example', path: '/', expires: 1600.0004 };
const session = { ...login, name: '__Host-apex_session', value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE', expires: 4600 };
function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture(t, options = {}) {
  const page = new EventEmitter(); page.closed = false; page.isClosed = () => page.closed;
  const abort = new AbortController(); const failures = []; let jar = [login]; let reads = 0;
  const observer = observeLoginCookies(page, { signal: abort.signal, onFailure: category => failures.push(category),
    readJar: async () => { reads++; return jar; }, now: () => 1010, timeoutMs: 100, ...options });
  t.after(() => abort.abort());
  function reply(headers = [wire], suffix = '/auth/login', status = 302, host = 'https://console.example') {
    page.emit('response', { url: () => host + suffix, status: () => status,
      request: () => ({ method: () => suffix === '/auth/login' ? 'GET' : 'POST' }),
      headerValues: name => { assert.equal(name, 'set-cookie'); return typeof headers === 'function' ? headers() : Promise.resolve(headers); } });
  }
  return { page, abort, failures, observer, reply, jar: value => { jar = value; }, reads: () => reads };
}

test('actual-header observation correlates a private pre-credential jar and retains it through logout', async t => {
  const f = fixture(t); f.jar([]); await f.observer.verify('initial');
  f.jar([login]); f.reply(); await f.observer.capture();
  f.jar([session, login]); await f.observer.verify('authenticated');
  f.reply(['__Host-apex_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax'], '/auth/logout', 204);
  f.jar([login]); await f.observer.verify('signed-out');
  f.page.closed = true; await f.observer.finish();
  assert.equal(f.reads(), 4); assert.deepEqual(f.failures, []); assert.equal(f.page.listenerCount('response'), 0);
});
test('capture awaits the original actual headers before reading the jar', async t => {
  const gate = deferred(); const f = fixture(t); f.reply(() => gate.promise);
  let done = false; const capture = f.observer.capture().then(() => { done = true; });
  try { await tick(); assert.equal(done, false); assert.equal(f.reads(), 0); }
  finally { gate.resolve([wire]); }
  await capture; assert.equal(f.reads(), 1);
});
test('missing original response cannot be substituted by a plausible existing jar', async t => {
  const f = fixture(t); await assert.rejects(f.observer.capture(), { message: 'cookie' });
});
test('capture cannot be repeated to refresh the original expiry baseline', async t => {
  const f = fixture(t); f.reply(); await f.observer.capture();
  f.jar([{ ...login, expires: 1700 }]); await assert.rejects(f.observer.capture(), { message: 'cookie' });
});
test('a later binding issuance is rejected even with the same opaque value and Max-Age', async t => {
  const f = fixture(t); f.reply(); await f.observer.capture();
  f.reply([wire], '/auth/callback', 303);
  await assert.rejects(f.observer.drain(), { message: 'cookie' }); assert.deepEqual(f.failures, ['cookie']);
});
test('a second original login response cannot race the first asynchronous header read', async t => {
  const gate = deferred(); const f = fixture(t); f.reply(() => gate.promise); f.reply();
  await assert.rejects(f.observer.drain(), { message: 'cookie' }); gate.resolve([wire]);
});
test('a rejected actual-header read is sanitized, remembered and fails finalization', async t => {
  const f = fixture(t); f.reply(() => Promise.reject(new Error('header-secret-canary')));
  f.page.closed = true;
  await assert.rejects(f.observer.finish(), { message: 'cookie' }); assert.deepEqual(f.failures, ['cookie']);
});
test('finalization waits for late response validation after browser closure before permitting success', async t => {
  const f = fixture(t); f.reply(); await f.observer.capture();
  const gate = deferred(); f.reply(() => gate.promise, '/api/read', 200); f.page.closed = true;
  let done = false; const ending = f.observer.finish().then(() => { done = true; }, error => error.message);
  try { await tick(); assert.equal(done, false); } finally { gate.resolve([wire]); }
  assert.equal(await ending, 'cookie'); assert.equal(done, false);
});
test('finalization cannot detach observation while the owned page can still receive replies', async t => {
  const f = fixture(t); f.reply(); await f.observer.capture();
  await assert.rejects(f.observer.finish(), { message: 'cookie' });
});
test('hanging header reads are bounded and cannot silently permit capture', { timeout: 1000 }, async t => {
  const f = fixture(t, { timeoutMs: 25 }); f.reply(() => new Promise(() => {}));
  await assert.rejects(f.observer.capture(), { message: 'cookie' });
});
test('hanging jar reads are bounded before credentials would be submitted', { timeout: 1000 }, async t => {
  const f = fixture(t, { timeoutMs: 25, readJar: () => new Promise(() => {}) }); f.reply();
  await assert.rejects(f.observer.capture(), { message: 'cookie' });
});
test('cancellation ends pending observation and cannot dispatch a delayed jar read', async t => {
  const gate = deferred(); const f = fixture(t); f.reply(() => gate.promise);
  const capture = f.observer.capture(); f.abort.abort();
  await assert.rejects(capture, { message: 'cookie' }); gate.resolve([wire]);
  await tick(); assert.equal(f.reads(), 0);
});
test('response fanout fails before dispatching more than the bounded active header reads', async t => {
  let reads = 0; const f = fixture(t);
  for (let index = 0; index < 33; index++) f.reply(() => { reads++; return new Promise(() => {}); }, '/api/read', 200);
  await assert.rejects(f.observer.drain(), { message: 'cookie' }); assert.ok(reads <= 32);
});
test('total same-origin response observations are bounded even after earlier reads drain', async t => {
  const f = fixture(t);
  for (let index = 0; index < 512; index++) { f.reply([], '/api/read', 200); await f.observer.drain(); }
  f.reply([], '/api/read', 200); await assert.rejects(f.observer.drain(), { message: 'cookie' });
});
test('Keycloak cookie headers are not read or exposed by the console-only observer', async t => {
  const f = fixture(t); f.reply(() => { throw new Error('must-not-read-provider-headers'); }, '/realms/apex', 200, 'https://127.0.0.1:18451');
  await f.observer.drain(); assert.deepEqual(f.failures, []);
});
test('a changed binding value or extended expiry after capture fails despite a valid session', async t => {
  const f = fixture(t); f.reply(); await f.observer.capture();
  f.jar([session, { ...login, expires: 1600.001 }]);
  await assert.rejects(f.observer.verify('authenticated'), { message: 'cookie' });
});
test('a late event-loop poll does not dispatch a header read after its absolute deadline', async t => {
  let reads = 0; const f = fixture(t, { timeoutMs: 5 });
  f.reply(() => { reads++; return Promise.resolve([wire]); });
  const until = performance.now() + 15;
  while (performance.now() < until) { /* Controlled same-thread delayed poll. */ }
  await assert.rejects(f.observer.drain(), { message: 'cookie' });
  assert.equal(reads, 0);
});
