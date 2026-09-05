import { requireValue } from './policy.mjs';

function opaque(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
    && Buffer.from(value, 'base64url').length === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;
}
function secured(cookie, now) {
  requireValue(cookie.secure === true && cookie.httpOnly === true && cookie.sameSite === 'Lax'
    && cookie.path === '/' && cookie.domain === 'console.example' && opaque(cookie.value)
    && Number.isFinite(cookie.expires) && cookie.expires > now, 'cookie');
}
export function freezeLoginBinding(cookies, { now, issuance }) {
  requireValue(Array.isArray(cookies) && Number.isFinite(now) && now > 0 && issuance && opaque(issuance.value)
    && Number.isInteger(issuance.maxAge) && issuance.maxAge >= 1 && issuance.maxAge <= 600, 'cookie');
  const bindings = cookies.filter(cookie => cookie.name === '__Host-apex_login');
  requireValue(bindings.length === 1 && !cookies.some(cookie => cookie.name === '__Host-apex_session'), 'cookie');
  const binding = bindings[0]; secured(binding, now);
  requireValue(binding.value === issuance.value, 'cookie');
  // Chromium anchors Max-Age to its creation clock. Preserve its actual expiry;
  // do not manufacture a Node-response or later-inspection + Max-Age deadline.
  return Object.freeze({ value: binding.value, expires: binding.expires });
}
// Pure observation of the real browser jar. The binding is not a session and
// not the one-use OAuth state row; production intentionally retains it for tabs.
export function verifyCookieJar(cookies, { phase, now, original, previous }) {
  requireValue(Array.isArray(cookies) && Number.isFinite(now) && now > 0
    && ['initial', 'authenticated', 'signed-out'].includes(phase), 'cookie');
  requireValue(phase === 'initial' ? original === undefined
    : original && opaque(original.value) && Number.isFinite(original.expires) && original.expires > 0, 'cookie');
  const sessions = cookies.filter(cookie => cookie.name === '__Host-apex_session');
  const bindings = cookies.filter(cookie => cookie.name === '__Host-apex_login');
  requireValue(sessions.length === (phase === 'authenticated' ? 1 : 0), 'cookie');
  requireValue(bindings.length <= (phase === 'initial' ? 0 : 1), 'cookie');
  if (sessions.length) secured(sessions[0], now);
  // Browser removal on expiry is fine; an expired cookie still present is not.
  if (!bindings.length) return previous;
  const binding = bindings[0];
  secured(binding, now);
  requireValue(binding.value === original.value && binding.expires <= original.expires, 'cookie');
  if (previous) requireValue(binding.value === previous.value && binding.expires <= previous.expires, 'cookie');
  return Object.freeze({ value: binding.value, expires: binding.expires });
}
