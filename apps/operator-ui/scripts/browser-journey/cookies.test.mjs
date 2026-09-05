import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyCookieJar } from './cookies.mjs';

// Literal canonical 32-byte opaque values, never live cookies or credentials.
const login = { name: '__Host-apex_login', value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  secure: true, httpOnly: true, sameSite: 'Lax', domain: 'console.example', path: '/', expires: 1600 };
const session = { ...login, name: '__Host-apex_session', value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE', expires: 4600 };
const original = Object.freeze({ value: login.value, expires: 1600 });
const options = { phase: 'authenticated', now: 1010, original };
const rejects = (cookies, settings = options, category = 'cookie') =>
  assert.throws(() => verifyCookieJar(cookies, settings), { message: category });

test('fresh prelogin jar has no application session or binding cookie', () => {
  assert.equal(verifyCookieJar([], { phase: 'initial', now: 1000 }), undefined);
  rejects([login], { phase: 'initial', now: 1000 });
  rejects([session], { phase: 'initial', now: 1000 });
});
test('postlogin permits one original bounded binding alongside exactly one session', () => {
  assert.doesNotThrow(() => verifyCookieJar([session, login], options));
});
test('postlogout permits the unexpired binding but never a surviving session', () => {
  assert.doesNotThrow(() => verifyCookieJar([login], { ...options, phase: 'signed-out', now: 1030 }));
  rejects([session, login], { ...options, phase: 'signed-out', now: 1030 });
});
test('absence of a binding after login or logout is permitted without weakening session count', () => {
  assert.equal(verifyCookieJar([session], options), undefined);
  assert.equal(verifyCookieJar([], { ...options, phase: 'signed-out' }), undefined);
  rejects([], options); rejects([session, session], options);
  rejects([session, login, login], options);
});
for (const [field, bad] of [['secure', false], ['secure', 'true'], ['httpOnly', false], ['httpOnly', 'true'],
  ['sameSite', 'None'], ['sameSite', 'Strict'], ['domain', '.console.example'], ['domain', 'other.example'],
  ['path', '/auth'], ['value', ''], ['value', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'],
  ['value', 'secret-canary'], ['value', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=']]) {
  test(`binding rejects invalid ${field} without echoing a cookie`, () => {
    rejects([session, { ...login, [field]: bad }]);
  });
}
for (const expires of [1010, 1009, -1, 0, 1600.001, 1601, NaN, Infinity, undefined, '1600']) {
  test('binding expiry must be finite, future and no later than the frozen original expiry', () => {
    rejects([session, { ...login, expires }]);
  });
}
test('a later observation cannot extend the frozen expiry by treating remaining lifetime as newly issued', () => {
  rejects([session, { ...login, expires: 1700 }], { ...options, now: 1100 });
});
test('valid binding survives time passing without extending expiry or replacing the token', () => {
  const previous = verifyCookieJar([session, login], options);
  assert.ok(previous, 'original binding observation is retained');
  assert.doesNotThrow(() => verifyCookieJar([session, login], { ...options, now: 1599.9, previous }));
  rejects([session, { ...login, expires: 1601 }], { ...options, now: 1100, previous });
  rejects([session, { ...login, value: session.value }], { ...options, now: 1100, previous });
  rejects([session, login], { ...options, now: 1600, previous });
});
test('an original shorter lifetime cannot be extended within the overall ten-minute ceiling', () => {
  const previous = verifyCookieJar([session, { ...login, expires: 1500 }], options);
  rejects([session, { ...login, expires: 1501 }], { ...options, now: 1100, previous });
});
test('expired binding removed by the browser is acceptable; an expired binding present in the jar is not', () => {
  const previous = verifyCookieJar([session, login], options);
  assert.doesNotThrow(() => verifyCookieJar([session], { ...options, now: 1600, previous }));
  rejects([session, login], { ...options, now: 1600, previous });
});
for (const invalid of [{ now: NaN }, { now: Infinity }, { original: undefined }, { original: { value: login.value, expires: NaN } },
  { original: { value: 'secret-canary', expires: 1600 } }, { phase: 'unknown' }]) {
  test('binding validation requires the captured original binding and known phase', () => {
    rejects([session, login], { ...options, ...invalid });
  });
}
for (const delta of [{ secure: false }, { httpOnly: false }, { secure: 'true' }, { sameSite: 'None' },
  { domain: '.console.example' }, { path: '/api' }, { value: 'secret-canary' }, { expires: 1010 }, { expires: -1 }]) {
  test('existing session constraints remain strict including expiry', () => {
    rejects([{ ...session, ...delta }]);
  });
}
