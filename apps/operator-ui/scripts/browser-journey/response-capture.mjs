import { CONSOLE } from './policy.mjs';

const ROOT = CONSOLE + '/api/apex/v1/McpProxyService/';
const METHODS = new Set(['ListProxies', 'CreateProxy', 'GetProxy']);
const LIMIT = 1024 * 1024;
export const responsePatterns = [...METHODS].map(method => ({ urlPattern: ROOT + method, requestStage: 'Response' }));
const error = () => new Error('response');
const check = value => { if (!value) throw error(); };
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 256;

function bytes(wire) {
  check(typeof wire?.body === 'string' && typeof wire.base64Encoded === 'boolean');
  check(wire.body.length <= 4 * Math.ceil(LIMIT / 3));
  if (!wire.base64Encoded) check(wire.body.isWellFormed() && Buffer.byteLength(wire.body, 'utf8') <= LIMIT);
  const value = Buffer.from(wire.body, wire.base64Encoded ? 'base64' : 'utf8');
  check(value.length <= LIMIT && (!wire.base64Encoded || value.toString('base64') === wire.body));
  return value;
}

function cacheHeader(headers) {
  check(Array.isArray(headers) && headers.length <= 128);
  const matches = headers.filter(header => typeof header?.name === 'string' && header.name.toLowerCase() === 'cache-control');
  check(matches.length <= 1);
  if (!matches.length) return {};
  check(typeof matches[0].value === 'string' && matches[0].value.length <= 256);
  return { 'cache-control': matches[0].value };
}

// Separate closure scope: do not keep the CDP event/owner (and auth headers)
// alive through an adapter whose caller needs only these bounded values.
function adapter(method, input, status, headers, body) {
  return {
    url: () => ROOT + method,
    status: () => status,
    headers: () => headers,
    request: () => ({ method: () => 'POST', postDataJSON: () => input }),
    body: async () => { check(body !== undefined); const value = body; body = undefined; return value; },
  };
}

// Chromium can discard streamed bodies before Network.getResponseBody reads
// them. Read original bytes at Fetch's response pause instead, then continue
// unchanged. Request-stage binding fences older responses and ambiguous calls.
// This owner never fulfills requests, retries HTTP, or retains auth headers.
export function createResponseCapture(cdp, { signal, onFailure = () => {} }) {
  let pending; let failed = false; let closed = false;
  const work = new Set();
  const fail = () => {
    if (!failed) {
      failed = true;
      if (pending) { clearTimeout(pending.timer); pending.reject(error()); pending = undefined; }
      signal.removeEventListener('abort', fail);
      try { onFailure('response'); } catch { /* only a static failure leaves this owner */ }
    }
    return error();
  };
  const live = () => { if (failed || signal.aborted) throw fail(); };
  signal.addEventListener('abort', fail, { once: true });
  if (signal.aborted) fail();

  const owner = {
    expect(method) {
      live();
      if (closed || pending || !METHODS.has(method)) throw fail();
      let resolve; let reject;
      const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
      promise.catch(() => {});
      pending = { method, resolve, reject, timer: setTimeout(fail, 20_000) };
      return promise;
    },
    request(event) {
      live();
      if (closed) throw fail();
      if (!pending || event.request?.method !== 'POST' || event.request.url !== ROOT + pending.method) return;
      try {
        check(!pending.id && !event.redirectedRequestId && identifier(event.requestId) && identifier(event.frameId));
        let input;
        if (pending.method === 'CreateProxy') {
          const text = event.request.postData;
          check(typeof text === 'string' && text.length <= 256 * 1024 && Buffer.byteLength(text) <= 256 * 1024);
          input = JSON.parse(text);
        }
        Object.assign(pending, { id: event.requestId, frame: event.frameId, input });
      } catch { throw fail(); }
    },
    response(event) {
      const task = (async () => {
        live();
        if (closed) throw fail();
        check(identifier(event.requestId));
        const selected = pending?.id === event.requestId ? pending : undefined;
        if (!selected) {
          await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
          live(); return;
        }
        check(!selected.reading); selected.reading = true;
        check(event.frameId === selected.frame && event.request?.method === 'POST'
          && event.request.url === ROOT + selected.method && !event.redirectedRequestId && !event.responseErrorReason);
        check(Number.isInteger(event.responseStatusCode) && event.responseStatusCode >= 200
          && event.responseStatusCode <= 599 && !(event.responseStatusCode >= 300 && event.responseStatusCode <= 399));
        const headers = cacheHeader(event.responseHeaders);
        const status = event.responseStatusCode;
        const body = bytes(await cdp.send('Fetch.getResponseBody', { requestId: selected.id }));
        live();
        // getResponseBody must finish before any operation resumes this request.
        await cdp.send('Fetch.continueRequest', { requestId: selected.id });
        live();
        clearTimeout(selected.timer); pending = undefined;
        selected.resolve(adapter(selected.method, selected.input, status, headers, body));
      })().catch(() => { throw fail(); });
      work.add(task);
      task.then(() => work.delete(task), () => work.delete(task));
      return task;
    },
    async drain() {
      while (work.size) await Promise.all([...work]);
      live();
    },
    async finish() {
      if (pending) throw fail();
      await owner.drain();
      closed = true; signal.removeEventListener('abort', fail);
    },
    dispose() {
      if (pending || work.size) fail();
      closed = true; signal.removeEventListener('abort', fail);
    },
  };
  return owner;
}
