import assert from 'node:assert/strict';
import { test } from 'node:test';
import { freezeLoginBinding, verifyCookieJar } from './cookies.mjs';

const login = { name: '__Host-apex_login', value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  secure: true, httpOnly: true, sameSite: 'Lax', domain: 'console.example', path: '/', expires: 1600.0004 };
const session = { ...login, name: '__Host-apex_session', value: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE', expires: 4600 };
const issuance = { value: login.value, maxAge: 600 };
const original = Object.freeze({ value: login.value, expires: 1600.0004 });

test('pre-credential snapshot correlates the original wire value and preserves browser sub-ms expiry', () => {
  const frozen = freezeLoginBinding([login], { now: 1000.1, issuance });
  assert.deepEqual(frozen, original); assert.ok(Object.isFrozen(frozen));
  assert.doesNotThrow(() => verifyCookieJar([session, login], { phase: 'authenticated', now: 1010, original: frozen }));
});
test('snapshot does not pretend a later inspection calibrates Chromium creation time', () => {
  const frozen = freezeLoginBinding([login], { now: 1300, issuance });
  assert.equal(frozen.expires, 1600.0004);
  assert.throws(() => verifyCookieJar([session, { ...login, expires: 1600.001 }],
    { phase: 'authenticated', now: 1599, original: frozen }), { message: 'cookie' });
});
test('pre-credential snapshot requires no session and exactly one matching original binding', () => {
  for (const cookies of [[], [session, login], [login, login], [{ ...login, value: session.value }]]) {
    assert.throws(() => freezeLoginBinding(cookies, { now: 1010, issuance }), { message: 'cookie' });
  }
});
test('pre-credential snapshot retains every jar security and finite future expiry constraint', () => {
  for (const delta of [{ secure: false }, { httpOnly: false }, { sameSite: 'None' }, { domain: '.console.example' },
    { path: '/auth' }, { expires: -1 }, { expires: 1010 }, { expires: NaN }, { expires: Infinity }]) {
    assert.throws(() => freezeLoginBinding([{ ...login, ...delta }], { now: 1010, issuance }), { message: 'cookie' });
  }
});
test('later checks require the original snapshot even if the browser has removed the binding', () => {
  assert.throws(() => verifyCookieJar([session], { phase: 'authenticated', now: 1010 }), { message: 'cookie' });
  assert.throws(() => verifyCookieJar([], { phase: 'signed-out', now: 1010 }), { message: 'cookie' });
});
test('non-increasing expiry is preserved when an earlier observation already shortened it', () => {
  const previous = Object.freeze({ value: login.value, expires: 1500 });
  assert.throws(() => verifyCookieJar([session, { ...login, expires: 1501 }],
    { phase: 'authenticated', now: 1100, original, previous }), { message: 'cookie' });
});
