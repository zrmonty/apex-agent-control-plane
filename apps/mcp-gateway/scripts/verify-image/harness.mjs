import { randomUUID } from 'node:crypto';
import { runBounded } from './command.mjs';
import { inspectorSource } from './inspector.mjs';

const runLabel = 'io.apex.packaging-run';
const imagePattern = /^sha256:[0-9a-f]{64}$/;
const containerPattern = /^[0-9a-f]{64}$/;
const imageFormat = '{"id":{{json .Id}},"volumeCount":{{if index .Config "Volumes"}}{{len (index .Config "Volumes")}}{{else}}0{{end}}}';
// Narrow projection: never request Config.Env, credentials, raw mounts or logs.
// Cleanup must not depend on fields needed only to verify confinement.
const ownershipFormat = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},' +
  `"run":{{json (index .Config.Labels "${runLabel}")}}}`;
const containerFormat = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},' +
  `"run":{{json (index .Config.Labels "${runLabel}")}},` +
  '"user":{{json .Config.User}},"network":{{json .HostConfig.NetworkMode}},' +
  '"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},' +
  '"capDrop":{{json .HostConfig.CapDrop}},"capAdd":{{json .HostConfig.CapAdd}},' +
  '"securityOpt":{{json .HostConfig.SecurityOpt}},"mounts":{{if .Mounts}}{{len .Mounts}}{{else}}0{{end}},' +
  '"binds":{{if .HostConfig.Binds}}{{len .HostConfig.Binds}}{{else}}0{{end}},' +
  '"ports":{{if .HostConfig.PortBindings}}{{len .HostConfig.PortBindings}}{{else}}0{{end}},' +
  '"devices":{{if .HostConfig.Devices}}{{len .HostConfig.Devices}}{{else}}0{{end}},' +
  '"pidMode":{{json .HostConfig.PidMode}},' +
  '"memory":{{json .HostConfig.Memory}},"nanoCpus":{{json .HostConfig.NanoCpus}},' +
  '"pids":{{json .HostConfig.PidsLimit}},"running":{{json .State.Running}},' +
  '"exitCode":{{json .State.ExitCode}}}';

const require = (condition) => { if (!condition) throw new Error('PACKAGING_FAILED'); };
export function validImageReference(value) {
  return typeof value === 'string' && value.length <= 255 &&
    /^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/.test(value);
}
function json(output) {
  require(typeof output === 'string' && Buffer.byteLength(output) <= 4096);
  return JSON.parse(output);
}
function owned(record, state, expected) {
  require(record.id === expected && containerPattern.test(expected) &&
    record.name === `/${state.name}` && record.run === state.runId && record.image === state.imageId);
}
function confined(record) {
  require(record.user === '10001:10001' && record.network === 'none' &&
    record.readonly === true && record.privileged === false && record.mounts === 0 &&
    record.binds === 0 && record.ports === 0 && record.devices === 0 && record.pidMode === '' &&
    record.memory === 268435456 && record.nanoCpus === 1000000000 && record.pids === 64 &&
    Array.isArray(record.capDrop) && record.capDrop.length === 1 && record.capDrop[0] === 'ALL' &&
    (record.capAdd === null || (Array.isArray(record.capAdd) && record.capAdd.length === 0)) &&
    Array.isArray(record.securityOpt) && record.securityOpt.length === 1 &&
    ['no-new-privileges:true', 'no-new-privileges'].includes(record.securityOpt[0]));
}
function inspection(output) {
  const record = json(output);
  const limits = { files: 4096, bytes: 33554432, testArtifacts: 4096, privateKeyFiles: 4096,
    protoFiles: 2, descriptorServices: 3, rpcMethods: 4, generatedSchemas: 3 };
  require(record !== null && typeof record === 'object' && !Array.isArray(record) &&
    Object.keys(record).length === 11 && record.type === 'image-packaging-inspection' &&
    typeof record.ok === 'boolean' && ['PACKAGING_OK', 'PACKAGING_SCAN_FAILED',
      'PACKAGING_IMPORT_FAILED', 'PACKAGING_ARTIFACTS_REJECTED'].includes(record.code));
  const counts = {};
  for (const [key, max] of Object.entries(limits)) {
    require(Number.isSafeInteger(record[key]) && record[key] >= 0 && record[key] <= max);
    counts[key] = record[key];
  }
  require(record.privateKeyFiles <= record.files);
  require(record.ok === (record.code === 'PACKAGING_OK'));
  if (record.ok) require(record.files > 0 && record.testArtifacts === 0 && record.privateKeyFiles === 0 &&
    record.protoFiles === 2 && record.descriptorServices === 3 && record.rpcMethods === 4 && record.generatedSchemas === 3);
  return { ok: record.ok, code: record.code, ...counts };
}

async function docker(args, options) {
  return runBounded(process.platform === 'win32' ? 'docker.exe' : 'docker', args, options);
}

async function cleanup(command, state) {
  const filters = ['label=' + runLabel + '=' + state.runId, `name=^/${state.name}$`];
  const list = async (selected) => {
    const result = await command(['container', 'ls', '--all', '--no-trunc',
      ...selected.flatMap((filter) => ['--filter', filter]), '--format', '{{.ID}}'], 10_000);
    require(result.ok && typeof result.stdout === 'string' && result.stdout.length <= 130);
    const ids = result.stdout.trim() === '' ? [] : result.stdout.trim().split(/\r?\n/);
    require(ids.length <= 1 && ids.every((id) => containerPattern.test(id)));
    return ids;
  };
  // A timed-out create may have committed after the CLI response was lost.
  // Bounded lookup retries are recovery, never proof that an unseen operation
  // cannot commit later. Missing/ambiguous ownership remains a failure.
  let ids = [];
  for (let attempt = 0; attempt < 3 && ids.length === 0; attempt++) {
    ids = await list(filters);
    if (ids.length === 0 && attempt < 2) await new Promise((resolve) => setTimeout(resolve, 50));
  }
  require(ids.length === 1);
  const id = ids[0];
  require(state.containerId === null || state.containerId === id);
  const observed = await command(['container', 'inspect', '--format', ownershipFormat, id], 10_000);
  require(observed.ok);
  owned(json(observed.stdout), state, id);
  state.containerId = id;
  const removed = await command(['container', 'rm', '--force', id], 10_000);
  const remainingId = await list([`id=${id}`]);
  const remainingOwned = await list(filters);
  require(removed.ok && remainingId.length === 0 && remainingOwned.length === 0);
}

// Explicit command injection is for imported component tests only. The CLI has
// no fake mode, environment bypass, executable override, or acceptance override.
export async function verifyPackaging(image, run = docker) {
  const state = { imageId: null, containerId: null, runId: randomUUID() };
  state.name = `apex-packaging-${state.runId}`;
  let attemptedCreate = false;
  let result = { ok: false, code: 'PACKAGING_FAILED' };
  const command = (args, timeoutMs = 15_000) => run(args, { timeoutMs, maxBytes: 65_536 });
  try {
    require(validImageReference(image));
    const inspected = await command(['image', 'inspect', '--format', imageFormat, image]);
    require(inspected.ok);
    const metadata = json(inspected.stdout);
    require(typeof metadata.id === 'string' && imagePattern.test(metadata.id) && metadata.volumeCount === 0);
    state.imageId = metadata.id;
    attemptedCreate = true;
    const created = await command(['container', 'create', '--pull', 'never',
      '--name', state.name, '--label', `${runLabel}=${state.runId}`,
      '--network', 'none', '--read-only', '--user', '10001:10001',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
      '--pids-limit', '64', '--memory', '256m', '--cpus', '1',
      '--log-driver', 'none', '--no-healthcheck', '--entrypoint', 'node',
      '--workdir', '/app/apps/mcp-gateway', '--env', 'NODE_OPTIONS=', '--env', 'NODE_PATH=',
      state.imageId, '--input-type=module', '--eval', inspectorSource()], 30_000);
    require(created.ok && typeof created.stdout === 'string' && containerPattern.test(created.stdout.trim()));
    state.containerId = created.stdout.trim();
    const before = await command(['container', 'inspect', '--format', containerFormat, state.containerId]);
    require(before.ok);
    const record = json(before.stdout);
    owned(record, state, state.containerId);
    confined(record);
    require(record.running === false);
    const started = await command(['container', 'start', '--attach', state.containerId], 20_000);
    // Even an inspector refusal may carry safe legacy-artifact counts.
    const inspectedOutput = inspection(started.stdout);
    const after = await command(['container', 'inspect', '--format', containerFormat, state.containerId]);
    require(after.ok);
    const stopped = json(after.stdout);
    owned(stopped, state, state.containerId);
    confined(stopped);
    require(stopped.running === false);
    result = inspectedOutput;
    if (!started.ok || stopped.exitCode !== 0) {
      result = { ...inspectedOutput, ok: false,
        code: inspectedOutput.ok ? 'PACKAGING_FAILED' : inspectedOutput.code };
    }
  } catch { /* Never forward Docker stdout/stderr, inspect data or raw exceptions. */ }
  finally {
    if (attemptedCreate) {
      try { await cleanup(command, state); }
      catch { result = { ...result, ok: false, code: 'CLEANUP_UNCONFIRMED' }; }
    }
  }
  return { type: 'image-packaging-verification', suite: 'packaging', ...result,
    imageId: state.imageId, runId: state.runId, containerId: state.containerId, readinessVerified: false };
}
