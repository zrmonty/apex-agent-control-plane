import { requireValue } from './policy.mjs';

// Strict known-BFF profile, not a general Set-Cookie parser. Bound before split.
export function readLoginCookie(headers, original) {
  requireValue(Array.isArray(headers) && headers.length <= 8, 'cookie');
  let bytes = 0;
  for (const header of headers) {
    requireValue(typeof header === 'string' && header.length <= 4096 && /^[\x20-\x7e]*$/.test(header), 'cookie');
    bytes += header.length; requireValue(bytes <= 8192, 'cookie');
  }
  const bindings = headers.filter(header => header.split('=', 1)[0].trim() === '__Host-apex_login');
  requireValue(bindings.length === (original ? 1 : 0), 'cookie');
  if (!original) return undefined;
  const parts = bindings[0].split(';').map(part => part.trim());
  requireValue(parts.length === 6 && parts[0].startsWith('__Host-apex_login='), 'cookie');
  const value = parts[0].slice('__Host-apex_login='.length);
  requireValue(/^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').length === 32
    && Buffer.from(value, 'base64url').toString('base64url') === value, 'cookie');
  const attributes = new Map();
  for (const part of parts.slice(1)) {
    const equals = part.indexOf('=');
    const name = (equals < 0 ? part : part.slice(0, equals)).toLowerCase();
    requireValue(!attributes.has(name), 'cookie');
    attributes.set(name, equals < 0 ? undefined : part.slice(equals + 1));
  }
  requireValue(attributes.size === 5 && attributes.has('secure') && attributes.get('secure') === undefined
    && attributes.has('httponly') && attributes.get('httponly') === undefined
    && attributes.get('samesite') === 'Lax' && attributes.get('path') === '/' && attributes.has('max-age'), 'cookie');
  const age = attributes.get('max-age');
  requireValue(typeof age === 'string' && /^[1-9][0-9]{0,2}$/.test(age) && Number(age) <= 600, 'cookie_lifetime');
  return Object.freeze({ value, maxAge: Number(age) });
}
