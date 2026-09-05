#!/usr/bin/env node
// Parent protocol only. Never use console/error stacks, traces, HARs, storage
// snapshots or Playwright Test's automatic failure attachments in this runner.
import https from 'node:https';
import path from 'node:path';
import os from 'node:os';
import { once } from 'node:events';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { lstatSync, mkdtempSync, realpathSync } from 'node:fs';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { backendAddress, requireValue } from './browser-journey/policy.mjs';
import { parentProtocol } from './browser-journey/protocol.mjs';
import { readBounded, loadAssets, labCredentials } from './browser-journey/files.mjs';
import { gateway } from './browser-journey/gateway.mjs';
import { journey } from './browser-journey/journey.mjs';
import { createCleanup } from './browser-journey/cleanup.mjs';
import { createDiagnostics } from './browser-journey/diagnostics.mjs';

const rawOut = process.stdout.write.bind(process.stdout);
const rawError = process.stderr.write.bind(process.stderr);
// This is a dedicated child, not an imported library. Keep dependency debug
// switches and accidental console calls from corrupting the parent protocol.
const quiet = (_chunk, encoding, callback) => {
  const done = typeof encoding === 'function' ? encoding : callback;
  if (done) queueMicrotask(done);
  return true;
};
process.stdout.write = quiet; process.stderr.write = quiet;
process.env.DEBUG = ''; process.env.PWDEBUG = '0';
const output = new Writable({ write(bytes, _encoding, done) { rawOut(bytes, done); } });
const abort = new AbortController();
const cancel = category => abort.abort(new Error(category));
let notifyingBrowser = false;
const terminated = () => { if (!notifyingBrowser) cancel('cancelled'); };
process.on('SIGTERM', terminated); process.on('SIGINT', terminated); process.on('SIGHUP', terminated);
process.on('uncaughtException', () => cancel('internal'));
process.on('unhandledRejection', () => cancel('internal'));
process.stdout.on('error', () => cancel('protocol'));
const protocol = parentProtocol(process.stdin, output, abort);
const watchdog = setTimeout(() => cancel('deadline'), 120_000);
let browser; let launching; let server; let credentials; let finishObservation;
const sockets = new Set();
const diagnostics = createDiagnostics();

function localDirectory(value) {
  requireValue(typeof value === 'string' && path.isAbsolute(value) && !/^[\\/]{2}/.test(value)
    && !/[\x00-\x1f]/.test(value), 'configuration');
  const directory = realpathSync(value);
  requireValue(directory !== path.parse(directory).root && lstatSync(directory).isDirectory(), 'configuration');
  return directory;
}
function artifactDirectory(value) {
  if (value === undefined) return undefined;
  const directory = localDirectory(value); const temp = realpathSync(os.tmpdir());
  const relative = path.relative(temp, directory);
  requireValue(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'artifact');
  // Preserve screenshots for the parent's single inspection batch; never
  // delete the parent artifact directory or any shared fixture.
  return mkdtempSync(path.join(directory, 'ui-journey-'));
}
const cleanup = createCleanup({
  getLaunching: () => launching,
  closeFrontend: () => {
    if (credentials) { credentials.password = ''; credentials.username = ''; }
    return server ? new Promise(resolve => {
      server.close(resolve); server.closeAllConnections();
      for (const socket of sockets) socket.destroy();
    }) : Promise.resolve();
  },
  // Playwright 1.62's default launch owns an exit/SIGTERM process-tree guard.
  // First notification closes gracefully; repeated notifications kill only
  // its owned tree and await child exit, including cancellation during launch.
  // No private Playwright API, process enumeration, or broad kill.
  notifyBrowser: () => {
    notifyingBrowser = true;
    try { process.emit('SIGTERM'); } finally { notifyingBrowser = false; }
  },
  emergencyExit: () => { rawError('UI_JOURNEY_FAILED_cleanup\n'); process.exit(1); },
});
const cancelled = new Promise((_, reject) => abort.signal.addEventListener('abort', () => {
  // The main failure path reports cancellation; a close failure retains its
  // own bounded non-success escalation without an unhandled rejection.
  void cleanup().catch(() => {}); reject(abort.signal.reason);
}, { once: true }));
cancelled.catch(() => {});

async function run() {
  requireValue(process.argv.length === 2, 'configuration');
  const backend = backendAddress(process.env.APEX_ROOT_BROWSER_HTTP_ADDR);
  const ui = fileURLToPath(new URL('../', import.meta.url));
  const pki = localDirectory(process.env.APEX_BROWSER_TEST_PKI_DIR);
  const trusted = realpathSync(path.join(pki, 'trusted-host'));
  requireValue(trusted.startsWith(pki + path.sep), 'configuration');
  const cert = readBounded(path.join(trusted, 'control-plane-server.pem'), 256 * 1024);
  const key = readBounded(path.join(trusted, 'control-plane-server.key'), 256 * 1024);
  const leaf = new X509Certificate(cert);
  requireValue(leaf.checkPrivateKey(createPrivateKey(key)), 'configuration');
  const pin = createHash('sha256').update(leaf.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  const realm = readBounded(path.resolve(ui, '../../deploy/compose/gateway-ref/keycloak/apex-realm.json'), 1024 * 1024);
  credentials = labCredentials(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(realm)));
  realm.fill(0);
  const assets = loadAssets(path.join(ui, 'dist'));
  const artifacts = artifactDirectory(process.env.APEX_UI_ARTIFACT_DIR);
  abort.signal.throwIfAborted();
  server = https.createServer({ cert, key, minVersion: 'TLSv1.2', handshakeTimeout: 5_000,
    maxHeaderSize: 32 * 1024, headersTimeout: 5_000, requestTimeout: 5_000, connectionsCheckingInterval: 500 },
  gateway({ backend, assets, signal: abort.signal, onViolation: () => cancel('privacy') }));
  server.maxConnections = 32;
  server.on('connection', socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    socket.setTimeout(5_000, () => socket.destroy());
  });
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('tlsClientError', () => {});
  server.on('error', () => cancel('transport'));
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  abort.signal.throwIfAborted();
  diagnostics.phase('browser');
  const { chromium } = await import('playwright');
  abort.signal.throwIfAborted();
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.toUpperCase().startsWith('APEX_')
    && !['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'NODE_OPTIONS', 'DEBUG', 'PWDEBUG'].includes(name.toUpperCase())));
  launching = chromium.launch({ headless: true, timeout: 20_000, env, args: [
    '--no-proxy-server', '--disable-quic',
    `--host-resolver-rules=MAP console.example:443 127.0.0.1:${server.address().port}, EXCLUDE 127.0.0.1, MAP * ~NOTFOUND`,
    `--ignore-certificate-errors-spki-list=${pin}`,
  ] });
  browser = await launching;
  abort.signal.throwIfAborted();
  finishObservation = await journey({ browser, credentials, protocol, abort, artifacts, onPhase: diagnostics.phase });
}

let succeeded = false;
try {
  await Promise.race([run(), cancelled]);
  await cleanup();
  // The closed browser cannot produce more responses. Await every tracked
  // header validation before PASS; a late rejection remains non-success.
  await finishObservation();
  abort.signal.throwIfAborted();
  protocol.passed();
  // Flush the final exact marker before exiting; the parent never accepts a
  // success marker followed by a failed cleanup or nonzero exit.
  await new Promise((resolve, reject) => output.end(error => error ? reject(error) : resolve()));
  succeeded = true;
} catch (error) {
  const category = diagnostics.category(error);
  rawError(`UI_JOURNEY_FAILED_${category}\n`);
  // Already a failure: preserve its category even if shutdown also fails.
  // A rejected cleanup keeps its owned-tree guard/emergency exit running.
  await cleanup().catch(() => {});
} finally {
  clearTimeout(watchdog); protocol.dispose(); process.stdin.destroy();
  process.exitCode = succeeded ? 0 : 1;
}
