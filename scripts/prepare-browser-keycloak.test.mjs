import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import path from 'node:path';
import * as helper from './prepare-browser-keycloak.mjs';
const owner = '0123456789abcdef0123456789abcdef';
const project = `apex-browser-lab-${owner}`;
const pkiDir = path.resolve('disposable browser PKI');
const image = 'quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007';

test('CLI defaults to start and accepts only confined, typed fixture arguments', () => {
  assert.equal(typeof helper.parseArgs, 'function', 'the fixture helper is missing');
  assert.deepEqual(helper.parseArgs([], { APEX_BROWSER_TEST_PKI_DIR: pkiDir }),
    { action: 'start', port: 18451, pkiDir });
  assert.deepEqual(helper.parseArgs(['stop', '--owned-id', owner], {}),
    { action: 'stop', ownedId: owner });
  assert.equal(helper.parseArgs(['config', '--port', '19451', '--pki-dir', pkiDir], {}).port, 19451);
  for (const args of [
    ['--port', '0'], ['--port', '443'], ['--port', '65536'], ['--port', '1.5'],
    ['--port', '018451'], ['--port', '0.0.0.0:18451'], ['--port', '18451:8443'],
    ['--port', '18451;whoami'], ['--port', '18451\n'], ['--port'],
    ['--port', '18451', '--port', '18452'], ['--bind', '0.0.0.0'],
    ['--issuer', 'https://other.invalid'], ['--image', 'keycloak:latest'],
    ['--pki-dir', '.'], ['--pki-dir', '//host/share'], ['--pki-dir', 'https://host/pki'],
    ['--pki-dir', path.parse(pkiDir).root.replaceAll('\\', '/')],
    ['--pki-dir', `${pkiDir}\n`], ['--pki-dir', `${pkiDir}$VAR`],
    ['stop'], ['stop', '--owned-id', '../unowned'], ['stop', '--owned-id', 'gateway-ref'],
    ['stop', '--owned-id', owner, '--port', '18451'],
    ['start', '--owned-id', owner], ['down'], ['start', '--help', '--port', '18451'],
  ]) assert.throws(() => helper.parseArgs(args, { APEX_BROWSER_TEST_PKI_DIR: pkiDir }), undefined, args.join(' '));
  assert.throws(() => helper.parseArgs([], {}), /PKI/);
});

test('config uses one pinned HTTPS loopback issuer, fixed mounts and secret-free output', () => {
  assert.equal(typeof helper.makeConfig, 'function', 'the fixture config builder is missing');
  const config = helper.makeConfig({ action: 'config', port: 19451, pkiDir }, owner);
  assert.equal(config.project, project);
  assert.equal(config.env.APEX_BROWSER_KEYCLOAK_ISSUER, 'https://127.0.0.1:19451/realms/apex');
  assert.equal(config.env.APEX_BROWSER_TEST_PKI_DIR, pkiDir);
  const service = config.compose.services.keycloak;
  assert.equal(service.image, image);
  assert.deepEqual(service.ports, [{ target: 8443, published: '19451', host_ip: '127.0.0.1', protocol: 'tcp' }]);
  assert.equal(service.environment.KC_HOSTNAME, 'https://127.0.0.1:19451');
  assert.equal(service.environment.KC_HTTP_ENABLED, 'false');
  assert.equal(service.environment.KC_HOSTNAME_BACKCHANNEL_DYNAMIC, 'false');
  assert.equal(service.environment.KC_DB, 'dev-mem');
  assert.equal(service.environment.KC_HOSTNAME_STRICT, 'true');
  assert.equal(service.labels['io.apex.browser-fixture.owner'], owner);
  assert.equal(config.compose.networks.browser.labels['io.apex.browser-fixture.owner'], owner);
  assert.equal(config.compose.volumes, undefined);
  assert.equal(service.network_mode, undefined);
  assert.equal(service.privileged, undefined);
  assert.equal(service.restart, 'no');
  assert.deepEqual(service.command, ['start-dev', '--import-realm']);
  assert.equal(service.volumes.length, 3);
  for (const mount of service.volumes) {
    assert.equal(mount.type, 'bind');
    assert.equal(mount.read_only, true);
    assert.equal(mount.bind.create_host_path, false);
    assert.equal(mount.source.includes('docker.sock'), false);
  }
  assert.equal(service.volumes[0].source, path.join(pkiDir, 'trusted-host', 'control-plane-server.pem'));
  assert.equal(service.volumes[1].source, path.join(pkiDir, 'trusted-host', 'control-plane-server.key'));
  assert.match(service.volumes[2].source, /apex-realm\.json$/);
  assert.equal(config.clientId, 'apex-browser');
  assert.equal(config.username, 'apex-browser-lab');
  assert.equal(config.callbackUrl, 'https://console.example/auth/callback');
  const serialized = JSON.stringify(config);
  assert.equal(serialized.includes('apex-browser-lab-client-secret'), false);
  assert.equal(serialized.includes('apex-browser-lab-password'), false);
  assert.equal(serialized.includes('${'), false);
  assert.throws(() => helper.makeConfig({ port: 0, pkiDir }, owner));
  assert.throws(() => helper.makeConfig({ port: 18451, pkiDir }, 'unowned'));
});

test('CLI accepts a separately validated canonical issuer port without changing defaults', () => {
  assert.deepEqual(helper.parseArgs([
    'start', '--port', '18462', '--issuer-port', '18461', '--pki-dir', pkiDir,
  ], {}), { action: 'start', port: 18462, issuerPort: 18461, pkiDir });
  assert.deepEqual(helper.parseArgs([], { APEX_BROWSER_TEST_PKI_DIR: pkiDir }),
    { action: 'start', port: 18451, pkiDir });
  for (const args of [
    ['--issuer-port'], ['--issuer-port', '18461', '--issuer-port', '18461'],
    ['stop', '--owned-id', owner, '--issuer-port', '18461'],
  ]) assert.throws(() => helper.parseArgs(args, { APEX_BROWSER_TEST_PKI_DIR: pkiDir }));
});

test('split-port config publishes only the physical backend and advertises the gate issuer', () => {
  const config = helper.makeConfig({ port: 18462, issuerPort: 18461, pkiDir }, owner);
  assert.equal(config.env.APEX_BROWSER_KEYCLOAK_ISSUER, 'https://127.0.0.1:18461/realms/apex');
  assert.equal(config.compose.services.keycloak.environment.KC_HOSTNAME, 'https://127.0.0.1:18461');
  assert.equal(config.compose.services.keycloak.environment.KC_HOSTNAME_BACKCHANNEL_DYNAMIC, 'false');
  assert.equal(config.compose.services.keycloak.environment.KC_HOSTNAME_STRICT, 'true');
  assert.deepEqual(config.compose.services.keycloak.ports,
    [{ target: 8443, published: '18462', host_ip: '127.0.0.1', protocol: 'tcp' }]);
});

test('issuer port is independently confined even when makeConfig bypasses CLI parsing', () => {
  for (const issuerPort of [0, 443, 65536, 1.5, '018461', '18461\n', '18461;whoami',
    '0.0.0.0:18461', 'https://other.invalid', '18461/realms/apex', '', null]) {
    assert.throws(() => helper.makeConfig({ port: 18462, issuerPort, pkiDir }, owner), /port/);
    assert.throws(() => helper.parseArgs(['--issuer-port', String(issuerPort)],
      { APEX_BROWSER_TEST_PKI_DIR: pkiDir }));
  }
});

test('readiness always connects to the fixed physical discovery and JWKS paths', () => {
  const split = helper.makeConfig({ port: 18462, issuerPort: 18461, pkiDir }, owner);
  assert.deepEqual(split.readiness, {
    discoveryUrl: 'https://127.0.0.1:18462/realms/apex/.well-known/openid-configuration',
    jwksUrl: 'https://127.0.0.1:18462/realms/apex/protocol/openid-connect/certs',
  });
  const ordinary = helper.makeConfig({ port: 18451, pkiDir }, owner);
  assert.deepEqual(ordinary.readiness, {
    discoveryUrl: 'https://127.0.0.1:18451/realms/apex/.well-known/openid-configuration',
    jwksUrl: 'https://127.0.0.1:18451/realms/apex/protocol/openid-connect/certs',
  });
});

function inventory() {
  const labels = {
    'com.docker.compose.project': project,
    'io.apex.browser-fixture.owner': owner,
    'io.apex.browser-fixture.kind': 'working-browser-keycloak',
  };
  return {
    containers: [{ Id: 'a'.repeat(64), Name: `/${project}-keycloak-1`,
      Config: { Image: image, Labels: { ...labels, 'com.docker.compose.service': 'keycloak' } },
      HostConfig: { PortBindings: { '8443/tcp': [{ HostIp: '127.0.0.1', HostPort: '18451' }] } } }],
    networks: [{ Id: 'b'.repeat(64), Name: `${project}_browser`, Labels: {
      ...labels, 'com.docker.compose.network': 'browser',
    }, Containers: { ['a'.repeat(64)]: {} } }],
    volumes: [],
  };
}

test('cleanup selects exact IDs only after checking the entire owned inventory', () => {
  assert.equal(typeof helper.cleanupPlan, 'function', 'ownership validation is missing');
  assert.deepEqual(helper.cleanupPlan(owner, inventory()), {
    containers: ['a'.repeat(64)], networks: ['b'.repeat(64)],
  });
  assert.deepEqual(helper.cleanupPlan(owner, { containers: [], networks: [], volumes: [] }),
    { containers: [], networks: [] });
  const mutations = [
    i => { delete i.containers[0].Config.Labels['io.apex.browser-fixture.owner']; },
    i => { i.containers[0].Config.Labels['com.docker.compose.project'] = 'gateway-ref'; },
    i => { i.containers[0].Config.Labels['com.docker.compose.service'] = 'postgres'; },
    i => { i.containers[0].Config.Image = 'keycloak:latest'; },
    i => { i.containers[0].Name = '/unowned'; },
    i => { i.containers[0].Id = '--all'; },
    i => { i.containers[0].HostConfig.PortBindings['8443/tcp'][0].HostIp = '0.0.0.0'; },
    i => { i.networks[0].Labels['io.apex.browser-fixture.owner'] = 'other'; },
    i => { i.networks[0].Labels['io.apex.browser-fixture.kind'] = 'production'; },
    i => { i.networks[0].Name = 'gateway-ref_default'; },
    i => { i.networks[0].Containers['c'.repeat(64)] = {}; },
    i => { i.volumes.push('unowned'); },
    i => { i.containers.push(structuredClone(i.containers[0])); },
    i => { i.networks.push(structuredClone(i.networks[0])); },
  ];
  for (const mutate of mutations) {
    const snapshot = inventory();
    mutate(snapshot);
    assert.throws(() => helper.cleanupPlan(owner, snapshot));
  }
});

test('discovery readiness refuses issuer drift, HTTP, endpoint redirects and absent S256', () => {
  assert.equal(typeof helper.validateDiscovery, 'function', 'provider readiness validation is missing');
  const issuer = 'https://127.0.0.1:18451/realms/apex';
  const doc = {
    issuer, authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
    end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
    revocation_endpoint: `${issuer}/protocol/openid-connect/revoke`,
    code_challenge_methods_supported: ['plain', 'S256'],
    response_types_supported: ['code', 'id_token'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
  };
  assert.doesNotThrow(() => helper.validateDiscovery(doc, issuer));
  for (const change of [
    { issuer: 'https://keycloak:8443/realms/apex' }, { issuer: `${issuer}/` },
    { authorization_endpoint: 'http://127.0.0.1:18451/realms/apex/protocol/openid-connect/auth' },
    { token_endpoint: 'https://other.invalid/token' }, { jwks_uri: `${issuer}/other-key` },
    { end_session_endpoint: `${issuer}/protocol/openid-connect/logout?redirect_uri=https://evil.invalid` },
    { code_challenge_methods_supported: ['plain'] }, { grant_types_supported: ['client_credentials'] },
  ]) assert.throws(() => helper.validateDiscovery({ ...doc, ...change }, issuer));
});

test('split-port readiness validates genuine front discovery before mapping fixed backend JWKS', () => {
  const issuer = 'https://127.0.0.1:18461/realms/apex';
  const backend = 'https://127.0.0.1:18462/realms/apex';
  const doc = {
    issuer, authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
    end_session_endpoint: `${issuer}/protocol/openid-connect/logout`,
    revocation_endpoint: `${issuer}/protocol/openid-connect/revoke`,
    code_challenge_methods_supported: ['S256'], response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
  };
  assert.doesNotThrow(() => helper.validateDiscovery(doc, issuer));
  for (const key of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri',
    'end_session_endpoint', 'revocation_endpoint']) {
    assert.throws(() => helper.validateDiscovery({ ...doc, [key]: doc[key].replace(issuer, backend) }, issuer));
  }
  for (const jwks_uri of [`${doc.jwks_uri}?other=1`, `${doc.jwks_uri}/../keys`,
    'https://other.invalid/keys', 'http://127.0.0.1:18462/keys']) {
    assert.throws(() => helper.validateDiscovery({ ...doc, jwks_uri }, issuer));
  }
});

test('fixture survives success but failed creation/readiness always invokes its owned cleanup', async () => {
  assert.equal(typeof helper.runOwned, 'function', 'owned lifecycle orchestration is missing');
  for (const failAt of [undefined, 'create', 'ready']) {
    const calls = [];
    const hooks = {
      create: async () => { calls.push('create'); if (failAt === 'create') throw Error('create failed'); },
      ready: async () => { calls.push('ready'); if (failAt === 'ready') throw Error('ready failed'); return 'ready'; },
      cleanup: async () => { calls.push('cleanup'); },
    };
    if (failAt) await assert.rejects(helper.runOwned(hooks), /failed/);
    else assert.equal(await helper.runOwned(hooks), 'ready');
    assert.deepEqual(calls, failAt === 'create' ? ['create', 'cleanup'] :
      failAt === 'ready' ? ['create', 'ready', 'cleanup'] : ['create', 'ready']);
  }
  await assert.rejects(helper.runOwned({
    create: async () => { throw Error('creation'); }, ready: async () => {},
    cleanup: async () => { throw Error('ownership refused'); },
  }), error => error instanceof AggregateError && error.errors.length === 2);
});

const realm = JSON.parse(readFileSync(new URL(
  '../deploy/compose/gateway-ref/keycloak/apex-realm.json', import.meta.url)));

test('browser login requires a confidential code client, S256 and exact HTTPS redirects', () => {
  const client = realm.clients.find(({ clientId }) => clientId === 'apex-browser');
  assert.ok(client, 'the real lab realm needs the browser client');
  assert.equal(client.publicClient, false);
  assert.equal(client.clientAuthenticatorType, 'client-secret');
  assert.equal(client.standardFlowEnabled, true);
  for (const flag of ['implicitFlowEnabled', 'directAccessGrantsEnabled',
    'serviceAccountsEnabled', 'bearerOnly', 'fullScopeAllowed']) {
    assert.equal(client[flag], false, flag);
  }
  assert.equal(client.attributes['pkce.code.challenge.method'], 'S256');
  assert.deepEqual(client.redirectUris, ['https://console.example/auth/callback']);
  assert.equal(client.attributes['post.logout.redirect.uris'], 'https://console.example/');
  assert.deepEqual(client.webOrigins, []);
  assert.deepEqual(client.optionalClientScopes, []);
  assert.deepEqual(client.defaultClientScopes, ['basic', 'profile', 'email']);
  assert.equal(client.attributes['oauth2.device.authorization.grant.enabled'], 'false');
  assert.equal(client.attributes['oidc.ciba.grant.enabled'], 'false');
});

test('browser grants apply only to access tokens and refresh tokens cannot be reused', () => {
  assert.equal(realm.revokeRefreshToken, true);
  assert.equal(realm.refreshTokenMaxReuse, 0);
  const client = realm.clients.find(({ clientId }) => clientId === 'apex-browser');
  const audience = client.protocolMappers.find(m => m.protocolMapper === 'oidc-audience-mapper');
  assert.equal(audience.config['included.client.audience'], 'apex-control-gateway');
  const scopes = client.protocolMappers.find(m => m.config['claim.name'] === 'apex_control_scopes');
  assert.deepEqual(JSON.parse(scopes.config['claim.value']), ['acme/prod']);
  for (const mapper of [audience, scopes]) {
    assert.equal(mapper.config['access.token.claim'], 'true');
    assert.equal(mapper.config['id.token.claim'], 'false');
  }
});

test('a dedicated lab human can finish password login without enrollment steps', () => {
  const user = realm.users?.find(({ username }) => username === 'apex-browser-lab');
  assert.ok(user, 'the realm needs a real human password credential');
  assert.equal(user.enabled, true);
  assert.deepEqual(user.requiredActions, []);
  assert.equal(user.serviceAccountClientId, undefined);
  assert.equal(user.credentials[0].type, 'password');
  assert.equal(user.credentials[0].temporary, false);
  assert.match(user.credentials[0].value, /lab/i);
  assert.equal(user.realmRoles?.includes('apex-control-break-glass') ?? false, false);
});

test('existing service grants and negative fixtures keep their distinct scope/audience/lifetime', () => {
  const cases = [
    ['apex-control-gateway', 'acme/prod', 'apex-control-gateway', '300'],
    ['apex-control-break-glass', 'acme/prod', 'apex-control-gateway', '300'],
    ['apex-control-overbroad', '*', 'apex-control-gateway', '300'],
    ['apex-control-shortlived', 'acme/prod', 'apex-control-gateway', '1'],
    ['apex-control-longlived', 'acme/prod', 'apex-control-gateway', '43200'],
    ['apex-control-wrong-audience', 'acme/prod', 'some-other-service', '300'],
  ];
  for (const [id, scope, audience, lifespan] of cases) {
    const client = realm.clients.find(c => c.clientId === id);
    assert.equal(client.serviceAccountsEnabled, true);
    assert.equal(client.standardFlowEnabled, false);
    assert.equal(client.attributes['access.token.lifespan'], lifespan);
    assert.equal(client.protocolMappers[0].config['included.client.audience'], audience);
    assert.deepEqual(JSON.parse(client.protocolMappers[1].config['claim.value']), [scope]);
  }
});
