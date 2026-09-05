// Imported component tests only. This command double never invokes Docker and
// proves orchestration, not actual image/profile/readiness behavior.
import assert from 'node:assert/strict';

export const imageId = `sha256:${'a'.repeat(64)}`;
export const runLabel = 'io.apex.packaging-run';
export const ownershipProjection = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"run":{{json (index .Config.Labels "io.apex.packaging-run")}}}';
// Independent literal expectations from the amended eight-case brief. Every
// case needs valid identity so unrelated identity rejection cannot satisfy it.
export const expectedIdentity = ['APEX_MCP_PRINCIPAL=spiffe://apex/agent/research',
  'APEX_MCP_AGENT_ID=research-agent', 'APEX_MCP_WORKSPACE_ID=acme',
  'APEX_MCP_NAMESPACE_ID=prod', 'APEX_MCP_TRACE_ID=trace-001'];
export const expectedCases = [
  { id: 'production-default', expectedExitCode: 1, env: [] },
  { id: 'managed-live-missing-file', expectedExitCode: 1,
    env: ['APEX_MCP_PROFILE=managed', 'APEX_MCP_GOVERNANCE_MODE=live'] },
  { id: 'development-without-profile', expectedExitCode: 1,
    env: ['NODE_ENV=development', 'APEX_MCP_GOVERNANCE_MODE=local'] },
  { id: 'unknown-profile', expectedExitCode: 1, env: ['APEX_MCP_PROFILE=invalid-profile'] },
  { id: 'standalone-production', expectedExitCode: 1,
    env: ['APEX_MCP_PROFILE=development-standalone', 'NODE_ENV=production', 'APEX_MCP_GOVERNANCE_MODE=local'] },
  { id: 'standalone-inline-source', expectedExitCode: 1,
    env: ['APEX_MCP_PROFILE=development-standalone', 'NODE_ENV=development', 'APEX_MCP_GOVERNANCE_MODE=local',
      'APEX_MCP_PROXY_REVISION_CONFIG='] },
  { id: 'standalone-file-source', expectedExitCode: 1,
    env: ['APEX_MCP_PROFILE=development-standalone', 'NODE_ENV=development', 'APEX_MCP_GOVERNANCE_MODE=local',
      'APEX_MCP_PROXY_REVISION_CONFIG_FILE=/run/secrets/apex-startup-missing-runtime.json'] },
  { id: 'standalone-closed-stdin', expectedExitCode: 0,
    env: ['APEX_MCP_PROFILE=development-standalone', 'NODE_ENV=development', 'APEX_MCP_GOVERNANCE_MODE=local'] },
];

export function startupBoundary(options = {}) {
  const calls = [];
  const containers = [];
  let current;
  const ok = (stdout = '') => ({ ok: true, code: 'OK', stdout });
  const failure = (code = 'COMMAND_TIMEOUT') => ({ ok: false, code, stdout: '' });
  const selected = () => current?.index === (options.caseIndex ?? 0);
  async function execute(args, limits) {
    calls.push({ args, limits });
    assert.ok(limits.timeoutMs > 0 && limits.timeoutMs <= 30_000 && limits.maxBytes === 65_536);
    const command = args.slice(0, 2).join(' ');
    if (command === 'image inspect') {
      assert.equal(containers.length, 0);
      assert.equal(args.at(-1), 'example:startup');
      assert.doesNotMatch(args[3], /\{\{json \.Config(?:\.Env)?\}\}|\{\{json \.\}\}/);
      if (options.imageFailure) return failure();
      return ok(options.imageOutput ?? JSON.stringify({ id: imageId, volumeCount: 0,
        apexSelectors: '', nodeEnvEntries: '1', productionEntries: '1',
        entrypointExpected: true, cmdEmpty: true, workingDirExpected: true, ...options.imagePatch }));
    }
    if (command === 'container create') {
      assert.ok(current === undefined || current.removed, 'previous cleanup must finish before another create');
      const index = containers.length;
      assert.ok(index < 8, 'case count is bounded');
      const name = args[args.indexOf('--name') + 1];
      assert.match(name, /^apex-startup-[0-9a-f-]{36}$/);
      const runId = name.slice('apex-startup-'.length);
      current = { index, id: (index + 1).toString(16).padStart(64, '0'), name, runId,
        started: false, removed: false, exists: true };
      containers.push(current);
      assert.deepEqual(args, ['container', 'create', '--pull', 'never', '--name', name,
        '--label', `${runLabel}=${runId}`, '--network', 'none', '--read-only', '--user', '10001:10001',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--pids-limit', '64',
        '--memory', '256m', '--cpus', '1', '--log-driver', 'none', '--no-healthcheck',
        '--env', 'NODE_OPTIONS=', '--env', 'NODE_PATH=',
        ...expectedCases[index].env.flatMap((value) => ['--env', value]),
        ...expectedIdentity.flatMap((value) => ['--env', value]), imageId]);
      if (selected() && options.createAbsent) current.exists = false;
      if (selected() && options.createThrows) throw Error('RAW_CREATE_CANARY');
      if (selected() && (options.createLost || options.createAbsent)) return failure();
      return ok(selected() && options.createOutput !== undefined ? options.createOutput : `${current.id}\n`);
    }
    assert.ok(current, 'only image inspection is legal before create');
    if (command === 'container inspect') {
      assert.equal(args.at(-1), current.id);
      const ownershipOnly = args[3] === ownershipProjection;
      if (selected() && (options.inspectFailure || (!ownershipOnly && options.confinementInspectFailure))) return failure();
      const identity = { id: current.id, name: `/${current.name}`, image: imageId, run: current.runId,
        ...(selected() ? options.identityPatch : {}) };
      if (ownershipOnly) return ok(JSON.stringify(identity));
      return ok(selected() && options.inspectOutput !== undefined ? options.inspectOutput : JSON.stringify({ ...identity,
        user: '10001:10001', network: 'none', readonly: true, privileged: false,
        capDrop: ['ALL'], capAdd: null, securityOpt: ['no-new-privileges:true'],
        mounts: 0, binds: 0, ports: 0, devices: 0, pidMode: '', memory: 268435456,
        nanoCpus: 1000000000, pids: 64, running: false,
        exitCode: current.started ? expectedCases[current.index].expectedExitCode : 0,
        status: current.started ? 'exited' : 'created', logDriver: 'none', healthDisabled: true,
        openStdin: false, tty: false,
        ...(selected() ? options[current.started ? 'afterPatch' : 'beforePatch'] : {}) }));
    }
    if (command === 'container start') {
      assert.deepEqual(args, ['container', 'start', '--attach', current.id]);
      current.started = true;
      if (selected() && options.startFailure) return failure(options.startFailure);
      if (selected() && options.startResult) return options.startResult;
      const exit = expectedCases[current.index].expectedExitCode;
      return { ok: exit === 0, code: exit === 0 ? 'OK' : 'COMMAND_FAILED',
        stdout: selected() ? (options.stdout ?? '') : '' };
    }
    if (command === 'container ls') {
      assert.ok(args.includes('--all') && args.includes('--no-trunc'));
      if (selected() && options.lookupFailure) return failure();
      if (!args.includes(`id=${current.id}`)) {
        assert.ok(args.includes(`label=${runLabel}=${current.runId}`));
        assert.ok(args.includes(`name=^/${current.name}$`));
      }
      return ok(current.exists && !current.removed
        ? `${current.id}\n${selected() && options.duplicate ? `${'f'.repeat(64)}\n` : ''}` : '');
    }
    if (command === 'container rm') {
      assert.deepEqual(args, ['container', 'rm', '--force', current.id]);
      if (!(selected() && options.leak)) current.removed = true;
      return selected() && options.removeFailure ? failure() : ok(current.id);
    }
    assert.fail('unexpected or broad Docker command');
  }
  return { execute, calls, containers };
}
