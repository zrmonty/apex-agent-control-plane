import path from 'node:path';
import { CONSOLE, KEYCLOAK, requireValue, allowedBrowserUrl, verifiedProxy, UUID7 } from './policy.mjs';
import { observeLoginCookies } from './cookie-observer.mjs';
import { jsonResponse } from './response.mjs';
import { createResponseCapture, responsePatterns } from './response-capture.mjs';

const NAME = 'Browser journey draft';
const SLUG = 'browser-journey-draft';

function opaque(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value)
    && Buffer.from(value, 'base64url').length === 32 && Buffer.from(value, 'base64url').toString('base64url') === value;
}
function challenge(value) {
  const query = value.searchParams;
  requireValue(query.get('client_id') === 'apex-browser' && query.get('redirect_uri') === CONSOLE + '/auth/callback'
    && query.get('response_type') === 'code' && query.get('code_challenge_method') === 'S256'
    && query.get('scope') === 'openid' && !query.has('client_secret') && !query.has('code_verifier'), 'login');
  for (const key of ['state', 'nonce', 'code_challenge']) requireValue(query.getAll(key).length === 1 && opaque(query.get(key)), 'login');
  requireValue(query.get('state') !== query.get('nonce'), 'login');
}
function matches(response, suffix) {
  return response.url() === CONSOLE + suffix && response.request().method() === (suffix === '/api/session' ? 'GET' : 'POST');
}
async function responseFor(page, suffix, action) {
  const pending = page.waitForResponse(response => matches(response, suffix));
  // Attach immediately so an action failure cannot leave an unhandled timeout.
  pending.catch(() => {});
  await action();
  return pending;
}
async function capturedResponse(capture, method, action) {
  const pending = capture.expect(method);
  await action();
  return pending;
}
async function absent(page, locator) { requireValue(await locator.count() === 0, 'assertion'); }

async function privacy(page, phase, cookieObservation, onPhase) {
  onPhase('privacy');
  requireValue(new URL(page.url()).origin === CONSOLE, 'privacy');
  const clean = await page.evaluate(async () => document.cookie === '' && localStorage.length === 0
    && sessionStorage.length === 0 && (await indexedDB.databases()).length === 0 && (await caches.keys()).length === 0);
  requireValue(clean, 'privacy');
  await cookieObservation.verify(phase);
}

async function screenshotPair(page, directory, view, onPhase) {
  if (!directory) return;
  onPhase('artifact');
  requireValue(new URL(page.url()).origin === CONSOLE && !new URL(page.url()).search, 'artifact');
  requireValue(await page.locator('input[type="password"]').count() === 0, 'artifact');
  for (const [name, viewport] of [['desktop', { width: 1440, height: 1000 }], ['mobile', { width: 390, height: 844 }]]) {
    await page.setViewportSize(viewport);
    await page.screenshot({ path: path.join(directory, `${view}-${name}.png`), animations: 'disabled',
      fullPage: false, timeout: 5_000 });
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
}

// Runs only when the parent has started the real production root. No request
// fulfillment, provider tokens, injected session state, or direct create calls.
export async function journey({ browser, credentials, protocol, abort, artifacts, onPhase = () => {} }) {
  onPhase('browser');
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 },
    serviceWorkers: 'block', acceptDownloads: false, ignoreHTTPSErrors: false });
  context.setDefaultTimeout(20_000); context.setDefaultNavigationTimeout(20_000);
  const page = await context.newPage();
  const fail = category => abort.abort(new Error(category));
  const cookieObservation = observeLoginCookies(page, { signal: abort.signal, onFailure: fail,
    readJar: () => context.cookies(CONSOLE) });
  context.on('page', other => { if (other !== page) { fail('traffic'); void other.close().catch(() => {}); } });
  page.on('download', download => { fail('traffic'); void download.cancel().catch(() => {}); });
  page.on('crash', () => fail('browser'));
  await context.routeWebSocket('**/*', socket => { fail('traffic'); socket.close(); });
  // CDP Fetch observes EVERY redirect hop. Playwright page.route explicitly
  // documents first-URL-only handling for redirects; it is insufficient here.
  const cdp = await context.newCDPSession(page);
  const capture = createResponseCapture(cdp, { signal: abort.signal, onFailure: fail });
  try {
  let requests = 0; let challenged = false; let callbackSeen = false;
  cdp.on('Fetch.requestPaused', event => {
    void (async () => {
      if (event.responseStatusCode !== undefined || event.responseErrorReason !== undefined) {
        await capture.response(event); return;
      }
      const request = event.request;
      if (abort.signal.aborted || ++requests > 512 || request.url.length > 8192 || !allowedBrowserUrl(request.url)) {
        await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'BlockedByClient' }); fail('traffic'); return;
      }
      const url = new URL(request.url);
      if (url.origin === CONSOLE) {
        requireValue(!Object.keys(request.headers).some(name => name.toLowerCase() === 'authorization'), 'privacy');
        if (url.pathname === '/auth/callback') {
          requireValue(challenged && url.searchParams.has('code') && !url.searchParams.has('error'), 'login');
          callbackSeen = true;
        }
      } else if (url.pathname === '/realms/apex/protocol/openid-connect/auth') {
        challenge(url); challenged = true;
      }
      capture.request(event);
      await cdp.send('Fetch.continueRequest', { requestId: event.requestId });
    })().catch(() => fail('traffic'));
  });
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }, ...responsePatterns] });

  onPhase('login');
  const initial = await responseFor(page, '/api/session', () => page.goto(CONSOLE + '/mcp-proxies', { waitUntil: 'domcontentloaded' }));
  requireValue(initial.status() === 401, 'login');
  await page.getByRole('link', { name: 'Sign in', exact: true }).waitFor();
  await privacy(page, 'initial', cookieObservation, onPhase);
  onPhase('login');
  await page.getByRole('link', { name: 'Sign in', exact: true }).click();
  await page.locator('#kc-form-login').waitFor();
  requireValue(new URL(page.url()).origin === KEYCLOAK && challenged, 'login');
  const action = await page.locator('#kc-form-login').getAttribute('action');
  const target = new URL(action, page.url());
  requireValue(target.origin === KEYCLOAK && target.pathname === '/realms/apex/login-actions/authenticate', 'login');
  // Await actual issuing headers and freeze the correlated console-only jar
  // after redirect, before filling or submitting any credentials. Never use a
  // later privacy check as a fresh expiry baseline.
  await cookieObservation.capture();
  // Secrets come only from the read-only lab realm and are never argv/output.
  await page.locator('#username').fill(credentials.username);
  await page.locator('#password').fill(credentials.password);
  credentials.password = ''; credentials.username = '';
  const initialInventory = capture.expect('ListProxies');
  initialInventory.catch(() => {});
  await page.locator('#kc-login').click();
  onPhase('scope');
  await page.getByLabel('Workspace and namespace').waitFor();
  await page.getByLabel('Workspace and namespace').selectOption('acme/prod');
  requireValue(await page.getByLabel('Workspace and namespace').inputValue() === 'acme/prod', 'scope');
  requireValue(callbackSeen, 'login');
  const { value: empty } = await jsonResponse('initial_inventory', () => initialInventory, onPhase);
  onPhase('inventory');
  // Protobuf JSON omits an empty repeated field. Never infer emptiness from an
  // unavailable reply: jsonResponse() above required an actual no-store HTTP 200.
  requireValue((empty.proxies === undefined || (Array.isArray(empty.proxies) && empty.proxies.length === 0))
    && !empty.nextPageToken, 'inventory');
  await page.getByRole('heading', { name: 'No proxies yet', exact: true }).waitFor();
  await absent(page, page.locator('article.proxy-card'));
  await privacy(page, 'authenticated', cookieObservation, onPhase);
  await screenshotPair(page, artifacts, 'inventory', onPhase);

  onPhase('identity');
  await page.getByRole('link', { name: 'New proxy', exact: true }).click();
  await page.getByRole('heading', { name: 'New MCP proxy', exact: true }).waitFor();
  await page.getByLabel('Display name', { exact: true }).fill(NAME);
  await page.getByLabel('Stable slug', { exact: true }).fill(SLUG);
  await screenshotPair(page, artifacts, 'draft', onPhase);
  onPhase('identity');
  const { response: createdResponse, value: created } = await jsonResponse('create', () =>
    capturedResponse(capture, 'CreateProxy', () => page.getByRole('button', { name: 'Create draft', exact: true }).click()), onPhase);
  onPhase('identity');
  const id = verifiedProxy(created, NAME, SLUG);
  const input = createdResponse.request().postDataJSON();
  requireValue(UUID7.test(input.requestId) && input.proxyId === id && input.workspaceId === 'acme'
    && input.namespaceId === 'prod', 'identity');
  await page.getByRole('heading', { name: NAME, exact: true }).waitFor();
  requireValue(new URL(page.url()).pathname === '/mcp-proxies/' + id, 'identity');
  // A hard detail reload proves a fresh actual GetProxy, not create cache data.
  const { value: detail } = await jsonResponse('detail_reload', () =>
    capturedResponse(capture, 'GetProxy', () => page.reload({ waitUntil: 'domcontentloaded' })), onPhase);
  onPhase('identity');
  requireValue(verifiedProxy(detail, NAME, SLUG) === id, 'identity');
  await page.getByRole('heading', { name: NAME, exact: true }).waitFor();
  onPhase('inventory');
  const { value: inventory } = await jsonResponse('inventory_reload', () =>
    capturedResponse(capture, 'ListProxies', () => page.goto(CONSOLE + '/mcp-proxies', { waitUntil: 'domcontentloaded' })), onPhase);
  onPhase('inventory');
  verifyInventory(inventory, id);
  await page.getByRole('link', { name: 'Open ' + NAME, exact: true }).waitFor();
  await privacy(page, 'authenticated', cookieObservation, onPhase);

  onPhase('protocol');
  await protocol.exchange('D');
  onPhase('offline');
  const offline = await responseFor(page, '/api/session', () => page.reload({ waitUntil: 'domcontentloaded' }));
  requireValue(offline.status() >= 500 && offline.status() <= 599, 'offline');
  await page.getByRole('alert').filter({ hasText: 'Session unavailable.' }).waitFor();
  await absent(page, page.locator('article.proxy-card'));
  await absent(page, page.getByRole('heading', { name: NAME, exact: true }));
  await absent(page, page.getByRole('heading', { name: 'No proxies yet', exact: true }));
  await absent(page, page.getByRole('link', { name: 'New proxy', exact: true }));

  onPhase('protocol');
  await protocol.exchange('R');
  onPhase('inventory');
  const { value: restored } = await jsonResponse('restored_inventory', () =>
    capturedResponse(capture, 'ListProxies', () => page.reload({ waitUntil: 'domcontentloaded' })), onPhase);
  onPhase('inventory');
  verifyInventory(restored, id);
  const link = page.getByRole('link', { name: 'Open ' + NAME, exact: true });
  await link.waitFor(); requireValue(await link.getAttribute('href') === '/mcp-proxies/' + id, 'identity');
  await privacy(page, 'authenticated', cookieObservation, onPhase);
  onPhase('logout');
  const logout = await responseFor(page, '/auth/logout', () => page.getByRole('button', { name: 'Sign out', exact: true }).click());
  requireValue(logout.status() === 204, 'logout');
  await page.getByRole('link', { name: 'Sign in', exact: true }).waitFor();
  const ended = await responseFor(page, '/api/session', () => page.reload({ waitUntil: 'domcontentloaded' }));
  requireValue(ended.status() === 401, 'logout');
  await page.getByRole('link', { name: 'Sign in', exact: true }).waitFor();
  await absent(page, page.locator('article.proxy-card'));
  await privacy(page, 'signed-out', cookieObservation, onPhase);
  await cookieObservation.drain();
  await capture.finish();
  requireValue(!abort.signal.aborted, 'cancelled');
  return cookieObservation.finish;
  } finally { capture.dispose(); }
}

function verifyInventory(reply, id) {
  requireValue(Array.isArray(reply.proxies) && reply.proxies.length === 1 && !reply.nextPageToken, 'inventory');
  requireValue(verifiedProxy({ proxy: reply.proxies[0] }, NAME, SLUG) === id, 'identity');
}
