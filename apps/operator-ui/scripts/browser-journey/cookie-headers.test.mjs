import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readLoginCookie } from './cookie-headers.mjs';

const token = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const wire = `__Host-apex_login=${token}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`;
const rejects = (headers, original = true, category = 'cookie') =>
  assert.throws(() => readLoginCookie(headers, original), { message: category });

for (const age of ['1', '599', '600']) {
  test(`original login wire validates the production ${age}-second remaining lifetime`, () => {
    const receipt = readLoginCookie([wire.replace('Max-Age=600', `Max-Age=${age}`)], true);
    assert.deepEqual(receipt, { value: token, maxAge: Number(age) }); assert.ok(Object.isFrozen(receipt));
  });
}
test('attribute names are case-insensitive, with no duplicate or ambiguous attributes', () => {
  const receipt = readLoginCookie([`__Host-apex_login=${token}; path=/; secure; samesite=Lax; httponly; max-age=600`], true);
  assert.equal(receipt.value, token); assert.equal(receipt.maxAge, 600);
});
for (const value of ['', '0', '-1', '+600', '0600', '600.0', '601', '999999999999', 'NaN', '600junk']) {
  test('invalid or overlong wire Max-Age fails without reflecting its input', () => {
    rejects([wire.replace('Max-Age=600', `Max-Age=${value}`)], true, 'cookie_lifetime');
  });
}
for (const attribute of ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=600']) {
  test(`missing ${attribute.split('=')[0]} is not a valid original binding`, () => {
    rejects([wire.replace(`; ${attribute}`, '')]);
  });
}
for (const suffix of ['; Domain=console.example', '; Domain=.console.example', '; Path=/auth', '; Max-Age=600',
  '; max-age=599', '; Secure', '; Expires=Thu, 01 Jan 2099 00:00:00 GMT', '; Partitioned', '; Unknown=1']) {
  test('extra or repeated cookie attributes cannot override the validated policy', () => rejects([wire + suffix]));
}
for (const [from, to] of [['Secure', 'Secure=true'], ['HttpOnly', 'HttpOnly=true'], ['SameSite=Lax', 'SameSite=None'],
  ['Path=/', 'Path=/auth'], [token, token + '='], [token, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB'],
  [token, 'secret-canary'], ['Max-Age=600', 'Max-Age=600\nsecret-canary']]) {
  test('invalid flags, path, encoding or control characters fail with static errors', () => rejects([wire.replace(from, to)]));
}
test('original response needs exactly one binding and later responses can never issue it', () => {
  rejects([]); rejects([wire, wire]); rejects([wire], false);
  rejects([wire.replace('__Host-apex_login', '__Host-apex_session')]);
  assert.equal(readLoginCookie([], false), undefined);
  assert.equal(readLoginCookie(['__Host-apex_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax'], false), undefined);
});
test('cookie header count and byte bounds are checked before parsing header contents', () => {
  rejects(Array(9).fill('other=value'), false);
  rejects(['other=' + 'x'.repeat(4096)], false);
  rejects(Array(3).fill('other=' + 'x'.repeat(3000)), false);
  rejects('not-an-array', false);
});
