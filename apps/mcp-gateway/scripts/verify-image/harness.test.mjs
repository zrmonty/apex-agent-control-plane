import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { main } from '../verify-image.mjs';
import { verifyPackaging } from './harness.mjs';
import { inspectorSource } from './inspector.mjs';

const imageId = `sha256:${'a'.repeat(64)}`;
const containerId = 'b'.repeat(64);
const runLabel = 'io.apex.packaging-run';
const ownershipProjection = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"run":{{json (index .Config.Labels "io.apex.packaging-run")}}}';
const cli = fileURLToPath(new URL('../verify-image.mjs', import.meta.url));
const good = { type: 'image-packaging-inspection', ok: true, code: 'PACKAGING_OK',
  files: 20, bytes: 2000, testArtifacts: 0, privateKeyFiles: 0,
  protoFiles: 2, descriptorServices: 3, rpcMethods: 4, generatedSchemas: 3 };

// Explicit Docker command boundary double: these tests prove host orchestration
// only. They are never actual image, RPC, TLS, readiness, or packaging acceptance.
function boundary(options = {}) {
  const calls = [];
  let created = false;
  let removed = false;
  let name;
  let run;
  let starts = 0;
  const ok = (body = '') => ({ ok: true, code: 'OK', stdout: body });
  const fail = () => ({ ok: false, code: 'COMMAND_TIMEOUT', stdout: 'RAW_DOCKER_CANARY' });
  async function execute(args, limits) {
    calls.push({ args, limits });
    const command = args.slice(0, 2).join(' ');
    if (command === 'image inspect') {
      if (options.imageFailure) return fail();
      return ok(JSON.stringify({ id: options.imageId ?? imageId, volumeCount: options.volumes ?? 0 }));
    }
    if (command === 'container create') {
      assert.equal(created, false);
      name = args[args.indexOf('--name') + 1];
      run = args.find((item) => item.startsWith(`${runLabel}=`))?.slice(runLabel.length + 1);
      assert.match(name, /^apex-packaging-[0-9a-f-]{36}$/);
      assert.equal(name, `apex-packaging-${run}`);
      assert.ok(args.includes(imageId), 'container must use immutable inspected ID');
      for (const [flag, value] of [['--network', 'none'], ['--user', '10001:10001'],
        ['--cap-drop', 'ALL'], ['--security-opt', 'no-new-privileges:true'],
        ['--entrypoint', 'node'], ['--pull', 'never'], ['--pids-limit', '64'],
        ['--memory', '256m'], ['--cpus', '1'], ['--log-driver', 'none']]) {
        assert.equal(args[args.indexOf(flag) + 1], value, flag);
      }
      assert.ok(args.includes('--read-only'));
      assert.ok(args.includes('--no-healthcheck'));
      for (const forbidden of ['-p', '--publish', '-v', '--volume', '--mount', '--privileged', '--rm']) {
        assert.ok(!args.includes(forbidden));
      }
      assert.ok(args.includes('NODE_OPTIONS=') && args.includes('NODE_PATH='));
      assert.equal(args.at(-1), inspectorSource());
      created = !options.createWithoutObject;
      if (options.createThrows) throw Error('RAW_DOCKER_CANARY');
      return options.createLost || options.createWithoutObject ? fail() : ok(`${containerId}\n`);
    }
    if (command === 'container inspect') {
      assert.equal(args.at(-1), containerId);
      if (options.inspectFailure) return fail();
      const ownershipOnly = args[args.indexOf('--format') + 1] === ownershipProjection;
      if (options.confinementInspectFailure && !ownershipOnly) return fail();
      const identity = { id: options.foreignId ? 'c'.repeat(64) : containerId,
        name: options.foreignName ? '/another-container' : `/${name}`,
        image: options.foreignImage ? `sha256:${'c'.repeat(64)}` : imageId,
        run: options.foreignLabel ? 'foreign-run' : run };
      if (ownershipOnly) return ok(JSON.stringify(identity));
      return ok(JSON.stringify({ ...identity, user: '10001:10001',
        network: 'none', readonly: !options.writable, privileged: false,
        capDrop: ['ALL'], capAdd: null, securityOpt: ['no-new-privileges:true'],
        mounts: options.mounts ?? 0, binds: options.binds ?? 0,
        ports: options.ports ?? 0, devices: options.devices ?? 0, pidMode: '',
        memory: 268435456, nanoCpus: 1000000000, pids: 64,
        running: options.stillRunning && starts > 0 ? true : false,
        exitCode: options.nonzero ? 9 : 0 }));
    }
    if (command === 'container start') {
      assert.deepEqual(args, ['container', 'start', '--attach', containerId]);
      starts++;
      if (options.startLost) return fail();
      const record = options.inspection ?? good;
      return { ok: !options.nonzero && record.ok, code: 'OK',
        stdout: options.rawOutput ?? JSON.stringify(record) };
    }
    if (command === 'container ls') {
      assert.ok(args.includes('--all') && args.includes('--no-trunc'));
      if (options.lookupFailure) return fail();
      const byId = args.includes(`id=${containerId}`);
      if (!byId) {
        assert.ok(args.includes(`label=${runLabel}=${run}`));
        assert.ok(args.includes(`name=^/${name}$`));
      }
      return ok(created && !removed ? `${containerId}\n${options.duplicate ? `${'c'.repeat(64)}\n` : ''}` : '');
    }
    if (command === 'container rm') {
      assert.deepEqual(args, ['container', 'rm', '--force', containerId]);
      assert.ok(!options.foreignLabel && !options.inspectFailure);
      if (!options.leak) removed = true;
      return options.removeFailure ? fail() : ok(containerId);
    }
    assert.fail('unexpected or broad Docker command');
  }
  return { execute, calls, wasRemoved: () => removed, starts: () => starts };
}

test('host gate pins image, enforces fixed confinement, and removes only validated owned ID', async () => {
  const fake = boundary();
  const report = await verifyPackaging('example:packaging', fake.execute);
  assert.equal(report.ok, true);
  assert.equal(report.code, 'PACKAGING_OK');
  assert.equal(report.imageId, imageId);
  assert.equal(report.files, 20);
  assert.equal(report.readinessVerified, false);
  assert.equal(fake.wasRemoved(), true);
  assert.equal(fake.starts(), 1);
  assert.ok(fake.calls.every(({ limits }) => limits.timeoutMs > 0 && limits.timeoutMs <= 30_000 && limits.maxBytes <= 65_536));
});

for (const [field, conditional] of [
  ['mounts', '"mounts":{{if .Mounts}}{{len .Mounts}}{{else}}0{{end}}'],
  ['binds', '"binds":{{if .HostConfig.Binds}}{{len .HostConfig.Binds}}{{else}}0{{end}}'],
  ['ports', '"ports":{{if .HostConfig.PortBindings}}{{len .HostConfig.PortBindings}}{{else}}0{{end}}'],
  ['devices', '"devices":{{if .HostConfig.Devices}}{{len .HostConfig.Devices}}{{else}}0{{end}}'],
]) {
  test(`container projection guards nullable ${field} before taking its length`, async () => {
    // Command-boundary characterization, not Go-template execution or image acceptance.
    const fake = boundary();
    assert.equal((await verifyPackaging('example:packaging', fake.execute)).ok, true);
    const inspections = fake.calls.filter(({ args }) => args[1] === 'inspect' && args[0] === 'container');
    assert.equal(inspections.length, 3);
    for (const { args } of inspections.slice(0, 2)) {
      assert.ok(args[args.indexOf('--format') + 1].includes(conditional), field);
    }
  });
}

test('cleanup uses only ownership projection when confinement inspection fails', async () => {
  const fake = boundary({ confinementInspectFailure: true });
  const report = await verifyPackaging('example:packaging', fake.execute);
  assert.equal(report.ok, false);
  assert.equal(report.code, 'PACKAGING_FAILED');
  assert.equal(fake.starts(), 0);
  assert.equal(fake.wasRemoved(), true);
  const inspections = fake.calls.filter(({ args }) => args[0] === 'container' && args[1] === 'inspect');
  assert.equal(inspections.length, 2);
  assert.deepEqual(inspections[1].args,
    ['container', 'inspect', '--format', ownershipProjection, containerId]);
});

test('image projection uses the optional Volumes conditional and still refuses declared volumes', async () => {
  // Assert command construction only, not Go-template execution or image acceptance.
  // Main separately verified this conditional with Docker on an image without Volumes.
  const format = '{"id":{{json .Id}},"volumeCount":{{if index .Config "Volumes"}}{{len (index .Config "Volumes")}}{{else}}0{{end}}}';
  for (const volumes of [0, 1]) {
    const fake = boundary({ volumes });
    const report = await verifyPackaging('example:packaging', fake.execute);
    assert.deepEqual(fake.calls[0].args,
      ['image', 'inspect', '--format', format, 'example:packaging']);
    assert.equal(report.ok, volumes === 0);
    if (volumes > 0) {
      assert.equal(fake.calls.length, 1);
      assert.equal(report.containerId, null);
    }
  }
});

for (const options of [{ createLost: true }, { createThrows: true }, { startLost: true }]) {
  test(`lost command response recovers only owned container and still refuses: ${JSON.stringify(options)}`, async () => {
    const fake = boundary(options);
    const report = await verifyPackaging('example:packaging', fake.execute);
    assert.equal(report.ok, false);
    assert.equal(fake.wasRemoved(), true);
    assert.ok(!JSON.stringify(report).includes('CANARY'));
  });
}

for (const options of [{ foreignLabel: true }, { foreignId: true }, { foreignName: true }, { foreignImage: true },
  { inspectFailure: true }, { duplicate: true },
  { lookupFailure: true }, { createWithoutObject: true }]) {
  test(`unconfirmed cleanup fails without unowned deletion: ${JSON.stringify(options)}`, async () => {
    const fake = boundary(options);
    const report = await verifyPackaging('example:packaging', fake.execute);
    assert.equal(report.ok, false);
    assert.equal(report.code, 'CLEANUP_UNCONFIRMED');
    assert.equal(fake.wasRemoved(), false);
  });
}

for (const options of [{ removeFailure: true }, { leak: true }]) {
  test(`cleanup failure prevents packaging success: ${JSON.stringify(options)}`, async () => {
    const fake = boundary(options);
    const report = await verifyPackaging('example:packaging', fake.execute);
    assert.equal(report.ok, false);
    assert.equal(report.code, 'CLEANUP_UNCONFIRMED');
  });
}

for (const options of [{ writable: true }, { mounts: 1 }, { binds: 1 }, { ports: 1 }, { devices: 1 }]) {
  test(`observed unsafe container never starts but is cleaned: ${JSON.stringify(options)}`, async () => {
    const fake = boundary(options);
    const report = await verifyPackaging('example:packaging', fake.execute);
    assert.equal(report.ok, false);
    assert.equal(fake.starts(), 0);
    assert.equal(fake.wasRemoved(), true);
  });
}

for (const options of [{ imageId: 'unsafe-inspect-canary' }, { imageId: [imageId] },
  { volumes: 1 }, { imageFailure: true }]) {
  test(`image inspection fails before any container create: ${JSON.stringify(options)}`, async () => {
    const fake = boundary(options);
    assert.equal((await verifyPackaging('example:packaging', fake.execute)).ok, false);
    assert.equal(fake.calls.length, 1);
  });
}

test('legacy test/key artifact counts are preserved as metadata, never accepted', async () => {
  const fake = boundary({ inspection: { ...good, ok: false,
    code: 'PACKAGING_ARTIFACTS_REJECTED', testArtifacts: 78, privateKeyFiles: 1, files: 100 } });
  const report = await verifyPackaging('example:old', fake.execute);
  assert.equal(report.ok, false);
  assert.equal(report.code, 'PACKAGING_ARTIFACTS_REJECTED');
  assert.equal(report.testArtifacts, 78);
  assert.equal(report.privateKeyFiles, 1);
  assert.equal(fake.wasRemoved(), true);
});

for (const options of [{ rawOutput: 'RAW_OUTPUT_CANARY' }, { rawOutput: 'x'.repeat(4097) },
  { inspection: { ...good, secret: 'RAW_OUTPUT_CANARY' } },
  { inspection: { ...good, rpcMethods: 0 } }, { nonzero: true }, { stillRunning: true }]) {
  test('malformed/incomplete output or process failure cannot claim success', async () => {
    const fake = boundary(options);
    const report = await verifyPackaging('example:packaging', fake.execute);
    assert.equal(report.ok, false);
    assert.ok(JSON.stringify(report).length < 1024);
    assert.ok(!JSON.stringify(report).includes('CANARY'));
    assert.equal(fake.wasRemoved(), true);
  });
}

test('strict CLI requires explicit packaging suite and refuses unsupported suites before Docker', async () => {
  const forbidden = async () => { assert.fail('Docker must not be called'); };
  for (const args of [[], ['--image', 'x'], ['--image', 'x', '--suite', 'ready'],
    ['--image', 'x', '--image', 'y'], ['--image', '--bad', '--suite', 'packaging'],
    ['--image', 'x;CANARY', '--suite', 'packaging'], ['--suite', 'packaging', '--image', ''],
    ['--suite', 'packaging', '--image', 'x\nCANARY'], ['--image', 'x', '--suite', 'packaging', '--extra']]) {
    const report = await main(args, forbidden);
    assert.equal(report.ok, false);
    assert.ok(['INVALID_ARGUMENTS', 'UNSUPPORTED_SUITE'].includes(report.code));
    assert.ok(!JSON.stringify(report).includes('CANARY'));
  }
  const fake = boundary();
  assert.equal((await main(['--suite', 'packaging', '--image', 'example:packaging'], fake.execute)).ok, true);
});

test('actual CLI rejects unsupported suite with one bounded static JSON result', () => {
  const result = spawnSync(process.execPath, [cli, '--image', 'CANARY', '--suite', 'readiness'],
    { encoding: 'utf8', timeout: 3000, maxBuffer: 4096, windowsHide: true });
  assert.notEqual(result.status, 0);
  assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).code, 'UNSUPPORTED_SUITE');
  assert.ok(!result.stdout.includes('CANARY'));
});

test('fixed inspector source is valid module code and refuses a host process without image privileges', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', inspectorSource()],
    { encoding: 'utf8', timeout: 3000, maxBuffer: 4096, windowsHide: true });
  assert.equal(result.status, 1);
  assert.equal(result.stderr, '');
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.code, 'PACKAGING_SCAN_FAILED');
});
