export const CONSOLE = 'https://console.example';
export const KEYCLOAK = 'https://127.0.0.1:18451';
export const UUID7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function requireValue(condition, category = 'assertion') {
  if (!condition) throw new Error(category);
}
export function backendAddress(value) {
  requireValue(typeof value === 'string' && /^127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(value), 'configuration');
  const port = Number(value.split(':')[1]);
  requireValue(port <= 65535, 'configuration');
  return { hostname: '127.0.0.1', port };
}
export function allowedBrowserUrl(value) {
  try {
    if (typeof value !== 'string' || /[\x00-\x20\x7f\\]/.test(value)) return false;
    const url = new URL(value);
    return !url.username && !url.password && [CONSOLE, KEYCLOAK].includes(url.origin);
  } catch { return false; }
}
export function requestPath(value) {
  requireValue(typeof value === 'string' && value.length <= 8192 && value.startsWith('/') && !value.startsWith('//')
    && !/[\x00-\x20\x7f-\uffff\\#]/.test(value) && !/%(?![0-9a-f]{2})/i.test(value), 'transport');
  const raw = value.split('?')[0];
  requireValue(!/%(?:2f|5c)/i.test(raw), 'transport');
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { throw new Error('transport'); }
  requireValue(!/[\x00-\x20\x7f\\]/.test(decoded) && !decoded.split('/').some(part => part === '.' || part === '..'), 'transport');
  return decoded;
}
export function safeHeaders(headers) {
  const blocked = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade', 'forwarded', 'accept-encoding',
    ...String(headers.connection ?? '').toLowerCase().split(',').map(value => value.trim())]);
  return Object.fromEntries(Object.entries(headers).filter(([key]) => !blocked.has(key.toLowerCase())
    && !key.toLowerCase().startsWith('x-forwarded-')));
}
export function verifiedProxy(reply, name, slug) {
  const proxy = reply?.proxy;
  requireValue(proxy && UUID7.test(proxy.proxyId) && proxy.workspaceId === 'acme' && proxy.namespaceId === 'prod'
    && proxy.displayName === name && proxy.slug === slug);
  return proxy.proxyId;
}
