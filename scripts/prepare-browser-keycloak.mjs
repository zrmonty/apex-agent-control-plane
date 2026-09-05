#!/usr/bin/env node
// Disposable LAB provider only. Importing this module never contacts Docker.
import { execFile } from 'node:child_process';
import { createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const composePath = path.join(root, 'deploy/compose/working-browser/compose.json');
const realmPath = path.join(root, 'deploy/compose/gateway-ref/keycloak/apex-realm.json');
const template = JSON.parse(readFileSync(composePath, 'utf8'));
const IMAGE = template.services.keycloak.image;
const KIND = 'working-browser-keycloak';
const OWNER_LABEL = 'io.apex.browser-fixture.owner';
const KIND_LABEL = 'io.apex.browser-fixture.kind';
const PROJECT_LABEL = 'com.docker.compose.project';
const ID = /^[a-f0-9]{64}$/;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function ownedProject(ownedId) {
  requireValue(typeof ownedId === 'string' && /^[a-f0-9]{32}$/.test(ownedId),
    'owned-id must be the exact 32-character lowercase hex ID emitted by this helper');
  return `apex-browser-lab-${ownedId}`;
}

function portNumber(value) {
  requireValue(/^[1-9][0-9]{3,4}$/.test(String(value)) && Number(value) >= 1024 &&
    Number(value) <= 65535, 'port must be a decimal integer in 1024..65535');
  return Number(value);
}

function pkiDirectory(value) {
  requireValue(typeof value === 'string' && path.isAbsolute(value) &&
    !/^[\\/]{2}/.test(value) && !/[\x00-\x1f$]/.test(value),
  'APEX_BROWSER_TEST_PKI_DIR must be an absolute local PKI directory (no UNC, URL or interpolation)');
  const resolved = path.resolve(value);
  requireValue(path.parse(resolved).root !== resolved, 'PKI directory must not be a filesystem root');
  return resolved;
}

export function parseArgs(args, env = process.env) {
  if (args.length === 1 && args[0] === '--help') return { action: 'help' };
  const rest = [...args];
  const action = rest[0] && !rest[0].startsWith('--') ? rest.shift() : 'start';
  requireValue(['start', 'stop', 'config'].includes(action), 'expected start, stop or config');
  const values = {};
  const allowed = action === 'stop' ? ['--owned-id'] : ['--port', '--issuer-port', '--pki-dir'];
  while (rest.length) {
    const key = rest.shift();
    requireValue(allowed.includes(key) && !(key in values), 'unknown or duplicate argument');
    requireValue(rest.length > 0 && !rest[0].startsWith('--'), 'missing argument value');
    values[key] = rest.shift();
  }
  if (action === 'stop') {
    ownedProject(values['--owned-id']);
    return { action, ownedId: values['--owned-id'] };
  }
  return { action, port: portNumber(values['--port'] ?? '18451'),
    ...(Object.hasOwn(values, '--issuer-port') ? { issuerPort: portNumber(values['--issuer-port']) } : {}),
    pkiDir: pkiDirectory(values['--pki-dir'] ?? env.APEX_BROWSER_TEST_PKI_DIR) };
}

export function makeConfig(options, ownedId = randomBytes(16).toString('hex')) {
  const project = ownedProject(ownedId);
  const port = portNumber(options.port);
  const issuerPort = portNumber(options.issuerPort === undefined ? port : options.issuerPort);
  const pkiDir = pkiDirectory(options.pkiDir);
  const trusted = path.join(pkiDir, 'trusted-host');
  const base = `https://127.0.0.1:${issuerPort}`;
  const backend = `https://127.0.0.1:${port}/realms/apex`;
  const paths = { compose: composePath, realm: realmPath,
    ca: path.join(trusted, 'ca.pem'), cert: path.join(trusted, 'control-plane-server.pem'),
    key: path.join(trusted, 'control-plane-server.key') };
  const variables = {
    APEX_BROWSER_OWNED_ID: ownedId, APEX_BROWSER_KEYCLOAK_BASE: base,
    APEX_BROWSER_KEYCLOAK_PORT: String(port), APEX_BROWSER_KEYCLOAK_CERT_FILE: paths.cert,
    APEX_BROWSER_KEYCLOAK_KEY_FILE: paths.key, APEX_BROWSER_KEYCLOAK_REALM_FILE: paths.realm,
  };
  const interpolate = value => {
    if (typeof value === 'string') return value.replace(/\$\{([A-Z_]+):\?required\}/g, (_, key) => {
      requireValue(Object.hasOwn(variables, key), 'unknown Compose substitution');
      return variables[key];
    });
    if (Array.isArray(value)) return value.map(interpolate);
    if (value && typeof value === 'object') return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, interpolate(item)]));
    return value;
  };
  return { ownedId, project, paths, clientId: 'apex-browser', username: 'apex-browser-lab',
    callbackUrl: 'https://console.example/auth/callback', postLogoutUrl: 'https://console.example/',
    env: { APEX_BROWSER_KEYCLOAK_ISSUER: `${base}/realms/apex`, APEX_BROWSER_TEST_PKI_DIR: pkiDir },
    readiness: { discoveryUrl: `${backend}/.well-known/openid-configuration`,
      jwksUrl: `${backend}/protocol/openid-connect/certs` },
    compose: interpolate(template) };
}

export function cleanupPlan(ownedId, inventory) {
  const project = ownedProject(ownedId);
  const { containers, networks, volumes } = inventory;
  requireValue(Array.isArray(containers) && Array.isArray(networks) && Array.isArray(volumes),
    'invalid Docker inventory');
  requireValue(containers.length <= 1 && networks.length <= 1 && volumes.length === 0,
    'unexpected resources in fixture project; cleanup refused');
  const owned = labels => labels?.[PROJECT_LABEL] === project &&
    labels?.[OWNER_LABEL] === ownedId && labels?.[KIND_LABEL] === KIND;
  for (const item of containers) {
    requireValue(ID.test(item.Id) && owned(item.Config?.Labels) &&
      item.Config.Labels['com.docker.compose.service'] === 'keycloak' &&
      item.Config.Image === IMAGE && item.Name === `/${project}-keycloak-1`,
    'container ownership/configuration mismatch; cleanup refused');
    const bindings = item.HostConfig?.PortBindings;
    const port = bindings?.['8443/tcp'];
    requireValue(bindings && Object.keys(bindings).length === 1 && Array.isArray(port) &&
      port.length === 1 && port[0].HostIp === '127.0.0.1', 'unsafe port binding; cleanup refused');
    portNumber(port[0].HostPort);
  }
  const ids = containers.map(item => item.Id);
  for (const item of networks) {
    requireValue(ID.test(item.Id) && owned(item.Labels) && item.Name === `${project}_browser` &&
      item.Labels['com.docker.compose.network'] === 'browser' &&
      Object.keys(item.Containers ?? {}).every(id => ids.includes(id)),
    'network ownership or attached container mismatch; cleanup refused');
  }
  return { containers: ids, networks: networks.map(item => item.Id) };
}

export function validateDiscovery(doc, issuer) {
  requireValue(doc.issuer === issuer, 'discovery issuer differs from configured HTTPS loopback issuer');
  for (const [key, endpoint] of Object.entries({ authorization_endpoint: 'auth',
    token_endpoint: 'token', jwks_uri: 'certs', end_session_endpoint: 'logout',
    revocation_endpoint: 'revoke' })) {
    requireValue(doc[key] === `${issuer}/protocol/openid-connect/${endpoint}`,
      `unexpected discovery ${key}`);
  }
  for (const [key, expected] of [
    ['code_challenge_methods_supported', 'S256'], ['response_types_supported', 'code'],
    ['grant_types_supported', 'authorization_code'], ['grant_types_supported', 'refresh_token'],
    ['token_endpoint_auth_methods_supported', 'client_secret_basic'],
  ]) requireValue(Array.isArray(doc[key]) && doc[key].includes(expected), `missing provider support: ${expected}`);
}

// Cleanup runs even after partially failed creation. Success transfers ownership
// to the caller for the integration test and its explicit stop --owned-id call.
export async function runOwned({ create, ready, cleanup }) {
  let result;
  let failure;
  let keep = false;
  try {
    await create();
    result = await ready();
    keep = true;
  } catch (error) {
    failure = error;
  } finally {
    if (!keep) {
      try { await cleanup(); } catch (error) {
        failure = new AggregateError([failure, error], 'startup failed and owned cleanup failed; use the emitted owned-id');
      }
    }
  }
  if (failure) throw failure;
  return result;
}

function readPki(config) {
  const trusted = realpathSync(path.join(config.env.APEX_BROWSER_TEST_PKI_DIR, 'trusted-host'));
  const read = filename => {
    const resolved = realpathSync(filename);
    const relative = path.relative(trusted, resolved);
    requireValue(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'PKI file escapes trusted-host');
    const stat = statSync(resolved);
    requireValue(stat.isFile() && stat.size > 0 && stat.size <= 1_048_576, 'invalid PKI file size/type');
    return readFileSync(resolved);
  };
  const ca = read(config.paths.ca);
  const authority = new X509Certificate(ca);
  const cert = new X509Certificate(read(config.paths.cert));
  requireValue(authority.ca && cert.checkIP('127.0.0.1') && cert.verify(authority.publicKey) &&
    cert.checkPrivateKey(createPrivateKey(read(config.paths.key))), 'PKI must match the trusted CA/key and IP SAN 127.0.0.1');
  for (const item of [cert, authority]) requireValue(Date.parse(item.validFrom) <= Date.now() &&
    Date.parse(item.validTo) > Date.now(), 'PKI certificate is not currently valid');
  return ca;
}

function docker(args, { input, signal, timeout = 30_000 } = {}) {
  return new Promise((resolve, reject) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('COMPOSE_')));
    const child = execFile('docker', args, { env, cwd: root, shell: false, windowsHide: true,
      signal, timeout, maxBuffer: 2 * 1024 * 1024 }, (error, stdout) => {
      if (error) reject(new Error(`Docker ${args[0]} failed (exit ${error.code ?? 'unknown'}); no provider logs or secrets printed`));
      else resolve(stdout.trim());
    });
    child.stdin.on('error', () => {}); // Early CLI exit is reported through the callback.
    child.stdin.end(input);
  });
}

async function inspect(kind, ids) {
  requireValue(ids.every(id => ID.test(id)), 'invalid Docker ID; inspection refused');
  if (!ids.length) return [];
  const result = JSON.parse(await docker([kind, 'inspect', ...ids]));
  requireValue(Array.isArray(result) && result.length === ids.length &&
    result.every(item => ids.includes(item.Id)), 'Docker inspect returned unexpected IDs');
  return result;
}

async function inventory(ownedId) {
  const filter = `label=${PROJECT_LABEL}=${ownedProject(ownedId)}`;
  const lines = value => value ? value.split(/\r?\n/) : [];
  const [containerIds, networkIds, volumes] = await Promise.all([
    docker(['container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', filter]).then(lines),
    docker(['network', 'ls', '--quiet', '--no-trunc', '--filter', filter]).then(lines),
    docker(['volume', 'ls', '--quiet', '--filter', filter]).then(lines),
  ]);
  const [containers, networks] = await Promise.all([
    inspect('container', containerIds), inspect('network', networkIds),
  ]);
  return { containers, networks, volumes };
}

export async function stopFixture(ownedId) {
  const plan = cleanupPlan(ownedId, await inventory(ownedId));
  for (const id of plan.containers) {
    cleanupPlan(ownedId, { containers: await inspect('container', [id]), networks: [], volumes: [] });
    await docker(['container', 'rm', '--force', id]);
  }
  for (const id of plan.networks) {
    cleanupPlan(ownedId, { containers: [], networks: await inspect('network', [id]), volumes: [] });
    await docker(['network', 'rm', id]);
  }
  const remaining = await inventory(ownedId);
  requireValue(Object.values(remaining).every(items => items.length === 0), 'owned fixture resources remain');
  return { stoppedOwnedId: ownedId, removed: plan };
}

function getJson(url, ca, signal) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, { ca, rejectUnauthorized: true, agent: false,
      signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]) }, response => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error('provider readiness returned a non-200 status')); return;
      }
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 262_144) request.destroy(new Error('provider readiness response exceeds bound'));
        else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('provider readiness returned invalid JSON')); }
      });
    });
    request.on('error', reject);
  });
}

async function waitForProvider(config, ca, signal) {
  const issuer = config.env.APEX_BROWSER_KEYCLOAK_ISSUER;
  const deadline = performance.now() + 300_000;
  while (performance.now() < deadline) {
    signal.throwIfAborted();
    let discovery;
    try { discovery = await getJson(config.readiness.discoveryUrl, ca, signal); }
    catch { await delay(1000, undefined, { signal }); continue; }
    validateDiscovery(discovery, issuer);
    // Validate the genuine canonical URLs above, then fetch only our fixed
    // physical backend certs path. The response never chooses a network target.
    const jwks = await getJson(config.readiness.jwksUrl, ca, signal);
    requireValue(Array.isArray(jwks.keys) && jwks.keys.some(key => key.use === 'sig' &&
      key.kty === 'RSA' && typeof key.kid === 'string'), 'provider has no imported realm signing key');
    const resources = cleanupPlan(config.ownedId, await inventory(config.ownedId));
    requireValue(resources.containers.length === 1 && resources.networks.length === 1, 'fixture ownership missing');
    signal.throwIfAborted();
    return { ...config, resources, ready: true };
  }
  throw new Error('Keycloak TLS/discovery readiness timed out after 300 seconds');
}

export async function startFixture(options) {
  const config = makeConfig(options);
  const ca = readPki(config); // Reuses existing material; never generates, copies or changes permissions.
  const before = await inventory(config.ownedId);
  requireValue(Object.values(before).every(items => items.length === 0), 'project collision; existing resources untouched');
  process.stderr.write(`LAB Keycloak owned-id: ${config.ownedId}; preserve this for explicit cleanup.\n`);
  const controller = new AbortController();
  const abort = () => controller.abort(new Error('fixture startup interrupted'));
  process.on('SIGINT', abort);
  process.on('SIGTERM', abort);
  try {
    return await runOwned({
      create: () => docker(['compose', '--project-name', config.project, '--project-directory', root,
        '--file', '-', 'up', '--detach', '--pull', 'never', '--no-build', 'keycloak'],
      { input: JSON.stringify(config.compose), signal: controller.signal, timeout: 120_000 }),
      ready: () => waitForProvider(config, ca, controller.signal),
      cleanup: () => stopFixture(config.ownedId),
    });
  } finally {
    process.removeListener('SIGINT', abort);
    process.removeListener('SIGTERM', abort);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.action === 'help') {
    process.stdout.write('LAB only: [start|config] [--port 18451] [--issuer-port PORT] [--pki-dir ABSOLUTE_DIR]\n' +
      'issuer-port defaults to port; split ports advertise a test HTTPS gate while readiness connects to port.\n' +
      'Default start preserves a ready fixture. config prints without Docker/PKI access.\n' +
      'Stop: stop --owned-id EXACT_EMITTED_ID (no PKI required)\n');
    return;
  }
  const result = options.action === 'stop' ? await stopFixture(options.ownedId) :
    options.action === 'config' ? makeConfig(options) : await startFixture(options);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
