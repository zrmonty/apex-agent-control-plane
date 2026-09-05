import { performance } from 'node:perf_hooks';
import { setMaxListeners } from 'node:events';
import { CONSOLE, requireValue } from './policy.mjs';
import { readLoginCookie } from './cookie-headers.mjs';
import { freezeLoginBinding, verifyCookieJar } from './cookies.mjs';

function bounded(action, signal, timeoutMs) {
  return new Promise((resolve, reject) => {
    const deadline = performance.now() + timeoutMs; let done = false;
    const finish = (ok, value) => {
      if (done) return;
      done = true; clearTimeout(timer); signal.removeEventListener('abort', cancel);
      if (ok && !signal.aborted && performance.now() < deadline) resolve(value);
      else reject(new Error('cookie'));
    };
    const cancel = () => finish(false);
    const timer = setTimeout(cancel, timeoutMs);
    signal.addEventListener('abort', cancel, { once: true });
    if (signal.aborted) { cancel(); return; }
    // Observe rejection even if timeout/cancellation wins. Do not dispatch late.
    Promise.resolve().then(() => {
      if (done || signal.aborted || performance.now() >= deadline) { cancel(); return; }
      return action();
    })
      .then(value => finish(true, value), cancel);
  });
}

// Only this context's console responses are observed; provider cookies never
// cross this seam. Header APIs have no Playwright default timeout of their own.
export function observeLoginCookies(page, { signal, onFailure, readJar,
  now = () => Date.now() / 1000, timeoutMs = 5_000 }) {
  const pending = new Set(); const local = new AbortController();
  setMaxListeners(40, local.signal); // <=32 reads plus the current drain/jar work.
  let failure; let total = 0; let loginSeen = false; let captureStarted = false;
  let issuance; let original; let previous; let stopped = false;
  const check = () => { if (failure) throw failure; requireValue(!signal.aborted && !stopped, 'cookie'); };
  const failed = error => {
    if (failure) return;
    const category = error instanceof Error && error.message === 'cookie_lifetime' ? 'cookie_lifetime' : 'cookie';
    failure = new Error(category); local.abort(); page.off('response', observe);
    onFailure(category);
  };
  const aborted = () => failed(new Error('cookie'));
  const observe = response => {
    try {
      check();
      const url = response.url();
      requireValue(typeof url === 'string' && url.length <= 8192, 'cookie');
      if (new URL(url).origin !== CONSOLE) return;
      requireValue(++total <= 512 && pending.size < 32, 'cookie');
      const first = url === CONSOLE + '/auth/login' && response.request().method() === 'GET' && response.status() === 302;
      if (first) { requireValue(!loginSeen, 'cookie'); loginSeen = true; }
      const task = bounded(() => response.headerValues('set-cookie'), local.signal, timeoutMs)
        .then(headers => {
          check();
          const receipt = readLoginCookie(headers, first);
          if (receipt) { requireValue(!issuance, 'cookie'); issuance = receipt; }
        }).catch(failed).finally(() => pending.delete(task));
      pending.add(task);
    } catch (error) { failed(error); }
  };
  const guarded = async action => {
    try { check(); return await action(); }
    catch (error) { failed(error); throw failure; }
  };
  const drain = () => guarded(async () => {
    await bounded(async () => { while (pending.size) await Promise.all([...pending]); }, local.signal, timeoutMs);
    check();
  });
  page.on('response', observe); signal.addEventListener('abort', aborted, { once: true });
  if (signal.aborted) aborted();
  return {
    drain,
    capture: () => guarded(async () => {
      requireValue(!captureStarted, 'cookie'); captureStarted = true;
      await drain(); requireValue(issuance, 'cookie');
      const cookies = await bounded(readJar, local.signal, timeoutMs);
      await drain();
      original = freezeLoginBinding(cookies, { now: now(), issuance }); previous = original;
    }),
    verify: phase => guarded(async () => {
      await drain();
      const cookies = await bounded(readJar, local.signal, timeoutMs);
      await drain();
      previous = verifyCookieJar(cookies, { phase, now: now(), original, previous });
    }),
    // Called only after confirmed browser closure: no later response can escape
    // observation, and pending validation cannot race UI_JOURNEY_PASSED.
    finish: () => guarded(async () => {
      requireValue(page.isClosed(), 'cookie');
      try { await drain(); requireValue(original, 'cookie'); }
      finally {
        stopped = true; page.off('response', observe); signal.removeEventListener('abort', aborted);
        issuance = undefined; original = undefined; previous = undefined;
      }
    }),
  };
}
