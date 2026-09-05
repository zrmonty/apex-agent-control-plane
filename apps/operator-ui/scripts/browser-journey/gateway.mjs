import http from 'node:http';
import { performance } from 'node:perf_hooks';
import { allowedBrowserUrl, requestPath, safeHeaders } from './policy.mjs';

// This is only an owned lab TLS-termination hop, never an API fixture.
export function gateway({ backend, assets, signal, timeoutMs = 5_000,
  requestLimit = 256 * 1024, responseLimit = 1024 * 1024, onViolation = () => {} }) {
  let active = 0;
  return (request, response) => {
    let settled = false; let upstream; let reply; let timer;
    const deadline = performance.now() + timeoutMs;
    const finish = (status, headers = {}, body = Buffer.alloc(0)) => {
      if (settled) return;
      settled = true; clearTimeout(timer); active--;
      signal.removeEventListener('abort', cancel);
      upstream?.destroy(); reply?.destroy();
      response.writeHead(status, { 'cache-control': 'no-store', ...headers, 'content-length': body.length,
        'x-content-type-options': 'nosniff', connection: 'close' });
      response.end(request.method === 'HEAD' ? undefined : body);
    };
    const cancel = () => finish(502);
    active++;
    request.on('error', cancel); request.on('aborted', cancel);
    response.on('error', cancel); response.on('close', () => { if (!response.writableFinished) cancel(); });
    signal.addEventListener('abort', cancel, { once: true });
    timer = setTimeout(cancel, timeoutMs);
    if (signal.aborted) { cancel(); return; }
    if (active > 32) { finish(503); return; }
    let pathname;
    try { pathname = requestPath(request.url); } catch { finish(400); return; }
    if (!['console.example', 'console.example:443'].includes(request.headers.host)) { finish(400); return; }
    const proxy = pathname.startsWith('/api/') || pathname.startsWith('/auth/');
    if (!proxy) {
      if (!['GET', 'HEAD'].includes(request.method)) { finish(405); return; }
      const spa = pathname === '/' || pathname === '/mcp-proxies' || pathname === '/mcp-proxies/new'
        || /^\/mcp-proxies\/[0-9a-f-]{36}(?:\/activity)?$/.test(pathname);
      const asset = assets.get(pathname) ?? (spa ? assets.get('/index.html') : undefined);
      if (!asset) { finish(404); return; }
      finish(200, { 'content-type': asset.type }, asset.body); return;
    }
    if (!['GET', 'POST', 'HEAD'].includes(request.method)) { finish(405); return; }
    if (request.headers['content-encoding']) { finish(415); return; }
    const declared = request.headers['content-length'];
    if (declared !== undefined && (!/^[0-9]+$/.test(declared) || Number(declared) > requestLimit)) { finish(413); return; }
    const chunks = []; let size = 0;
    request.on('data', chunk => {
      if (settled) return;
      if (performance.now() >= deadline) { cancel(); return; }
      size += chunk.length;
      if (size > requestLimit) { finish(413); return; }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (settled) return;
      if (performance.now() >= deadline) { cancel(); return; }
      const body = Buffer.concat(chunks, size);
      const headers = { ...safeHeaders(request.headers), 'content-length': body.length };
      // No redirects, retries, DNS, ambient proxy settings, or arbitrary target URLs.
      upstream = http.request({ ...backend, path: request.url, method: request.method, headers,
        agent: false, maxHeaderSize: 32 * 1024 }, incoming => {
        reply = incoming;
        if (settled) { incoming.destroy(); return; }
        // Assert the actual BFF contract before relaying anything. Local
        // static/error responses may set no-store, but must not manufacture
        // evidence that an upstream reply was non-cacheable.
        if (incoming.headers['cache-control'] !== 'no-store') { onViolation(); cancel(); return; }
        if (incoming.headers['content-encoding'] || Number(incoming.headers['content-length'] ?? 0) > responseLimit) { cancel(); return; }
        const parts = []; let count = 0;
        incoming.on('error', cancel); incoming.on('aborted', cancel);
        incoming.on('data', chunk => {
          if (settled) return;
          count += chunk.length;
          if (count > responseLimit || performance.now() >= deadline) { cancel(); return; }
          parts.push(chunk);
        });
        incoming.on('end', () => {
          if (settled) return;
          if (performance.now() >= deadline) { cancel(); return; }
          const bytes = Buffer.concat(parts, count);
          let privacyText = bytes.toString('utf8');
          if (String(incoming.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
            try { privacyText = JSON.stringify(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); }
            catch { onViolation(); cancel(); return; }
          }
          const location = incoming.headers.location;
          if (location && !(location.startsWith('/') && !location.startsWith('//')) && !allowedBrowserUrl(location)) {
            onViolation(); cancel(); return;
          }
          // Fail closed if the actual BFF ever attempts to deliver provider tokens.
          if (/(?:access[_-]?token|refresh[_-]?token|id[_-]?token)\s*["'=:%]/i.test(privacyText)
            || (location && /(?:access_token|refresh_token|id_token)=/i.test(location))) {
            onViolation(); cancel(); return;
          }
          finish(incoming.statusCode ?? 502, safeHeaders(incoming.headers), bytes);
        });
      });
      upstream.on('error', cancel); upstream.end(body);
    });
  };
}
