import { randomUUID } from 'node:crypto';
import { cleanup, confined, containerFormat, containerPattern, docker, imageFormat,
  imagePattern, json, owned, require as check, runLabel, validImageReference } from './harness.mjs';

const standalone = ['APEX_MCP_PROFILE=development-standalone', 'NODE_ENV=development',
  'APEX_MCP_GOVERNANCE_MODE=local'];
// Valid non-secret identity in every case prevents unrelated identity refusal
// from satisfying a negative profile/config expectation.
const identity = ['APEX_MCP_PRINCIPAL=spiffe://apex/agent/research',
  'APEX_MCP_AGENT_ID=research-agent', 'APEX_MCP_WORKSPACE_ID=acme',
  'APEX_MCP_NAMESPACE_ID=prod', 'APEX_MCP_TRACE_ID=trace-001'];
const cases = [
  { id: 'production-default', expectedExitCode: 1, env: [] },
  { id: 'managed-live-missing-file', expectedExitCode: 1,
    env: ['APEX_MCP_PROFILE=managed', 'APEX_MCP_GOVERNANCE_MODE=live'] },
  { id: 'development-without-profile', expectedExitCode: 1,
    env: ['NODE_ENV=development', 'APEX_MCP_GOVERNANCE_MODE=local'] },
  { id: 'unknown-profile', expectedExitCode: 1, env: ['APEX_MCP_PROFILE=invalid-profile'] },
  { id: 'standalone-production', expectedExitCode: 1,
    env: ['APEX_MCP_PROFILE=development-standalone', 'NODE_ENV=production', 'APEX_MCP_GOVERNANCE_MODE=local'] },
  { id: 'standalone-inline-source', expectedExitCode: 1,
    env: [...standalone, 'APEX_MCP_PROXY_REVISION_CONFIG='] },
  { id: 'standalone-file-source', expectedExitCode: 1,
    env: [...standalone, 'APEX_MCP_PROXY_REVISION_CONFIG_FILE=/run/secrets/apex-startup-missing-runtime.json'] },
  { id: 'standalone-closed-stdin', expectedExitCode: 0, env: standalone },
];

// Only fixed booleans/count markers cross this boundary, never raw image env,
// entrypoint, CMD or working-directory values. Count duplicate NODE_ENV entries.
const countPrefix = (prefix) => `{{range .Config.Env}}{{if ge (len .) ${prefix.length}}}` +
  `{{if eq (slice . 0 ${prefix.length}) "${prefix}"}}1{{end}}{{end}}{{end}}`;
const startupImageFormat = imageFormat.slice(0, -1) +
  `,"apexSelectors":"${countPrefix('APEX_MCP_')}","nodeEnvEntries":"${countPrefix('NODE_ENV=')}",` +
  '"productionEntries":"{{range .Config.Env}}{{if eq . "NODE_ENV=production"}}1{{end}}{{end}}",' +
  '"entrypointExpected":{{if index .Config "Entrypoint"}}{{if eq (len .Config.Entrypoint) 2}}' +
  '{{if and (eq (index .Config.Entrypoint 0) "node") (eq (index .Config.Entrypoint 1) "dist/index.js")}}true' +
  '{{else}}false{{end}}{{else}}false{{end}}{{else}}false{{end}},' +
  '"cmdEmpty":{{if index .Config "Cmd"}}false{{else}}true{{end}},' +
  '"workingDirExpected":{{if eq .Config.WorkingDir "/app/apps/mcp-gateway"}}true{{else}}false{{end}}}';
const startupContainerFormat = containerFormat.slice(0, -1) +
  ',"status":{{json .State.Status}},"logDriver":{{json .HostConfig.LogConfig.Type}},' +
  '"openStdin":{{json .Config.OpenStdin}},"tty":{{json .Config.Tty}},' +
  '"healthDisabled":{{if index .Config "Healthcheck"}}{{if eq (len .Config.Healthcheck.Test) 1}}' +
  '{{if eq (index .Config.Healthcheck.Test 0) "NONE"}}true{{else}}false{{end}}' +
  '{{else}}false{{end}}{{else}}false{{end}}}';

function startupConfinement(record) {
  confined(record);
  check(record.logDriver === 'none' && record.healthDisabled === true &&
    record.openStdin === false && record.tty === false);
}

async function runCase(definition, imageId, command, result) {
  const state = { imageId, containerId: null, runId: randomUUID() };
  state.name = `apex-startup-${state.runId}`;
  result.runId = state.runId;
  let attemptedCreate = false;
  let code = 'STARTUP_FAILED';
  try {
    attemptedCreate = true;
    const created = await command(['container', 'create', '--pull', 'never',
      '--name', state.name, '--label', `${runLabel}=${state.runId}`,
      '--network', 'none', '--read-only', '--user', '10001:10001',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
      '--pids-limit', '64', '--memory', '256m', '--cpus', '1',
      '--log-driver', 'none', '--no-healthcheck', '--env', 'NODE_OPTIONS=', '--env', 'NODE_PATH=',
      ...definition.env.flatMap((value) => ['--env', value]),
      ...identity.flatMap((value) => ['--env', value]), state.imageId], 30_000);
    // Nothing follows the immutable image ID: original ENTRYPOINT/CMD/cwd are
    // preserved. No -i/-t means closed stdin; host env values are never passed.
    check(created.ok && typeof created.stdout === 'string' && containerPattern.test(created.stdout.trim()));
    state.containerId = created.stdout.trim();
    const before = await command(['container', 'inspect', '--format', startupContainerFormat, state.containerId]);
    check(before.ok);
    const initial = json(before.stdout);
    owned(initial, state, state.containerId);
    startupConfinement(initial);
    check(initial.running === false && initial.status === 'created');

    const started = await command(['container', 'start', '--attach', state.containerId], 20_000);
    const after = await command(['container', 'inspect', '--format', startupContainerFormat, state.containerId]);
    check(after.ok);
    const stopped = json(after.stdout);
    owned(stopped, state, state.containerId);
    startupConfinement(stopped);
    check(stopped.running === false && stopped.status === 'exited' &&
      Number.isInteger(stopped.exitCode) && stopped.exitCode >= 0 && stopped.exitCode <= 255);
    result.observedExitCode = stopped.exitCode;
    // runBounded discards stderr. This cannot verify error-message categories
    // or stderr redaction. Inspect, not a CLI failure code, proves process exit.
    check(started.stdout === '' && ((started.ok === true && started.code === 'OK') ||
      (definition.expectedExitCode === 1 && started.ok === false && started.code === 'COMMAND_FAILED')));
    check(stopped.exitCode === definition.expectedExitCode);
    code = 'STARTUP_OK';
  } catch { /* Only fixed result codes and validated IDs leave this function. */ }
  finally {
    if (attemptedCreate) {
      try { await cleanup(command, state); }
      catch { code = 'CLEANUP_UNCONFIRMED'; }
    }
    result.containerId = state.containerId;
  }
  result.passed = code === 'STARTUP_OK';
  return code;
}

// Injection is an imported component-test seam only; the executable has no
// fake mode or environment-selected commands, cases, arguments or outcomes.
export async function verifyStartup(image, run = docker) {
  const report = { type: 'image-startup-verification', suite: 'startup', ok: false,
    code: 'STARTUP_FAILED', imageId: null,
    cases: cases.map(({ id, expectedExitCode }) => ({ id, passed: false,
      expectedExitCode, observedExitCode: null, runId: null, containerId: null })),
    readinessVerified: false, protocolHandshakeVerified: false };
  const command = (args, timeoutMs = 15_000) => run(args, { timeoutMs, maxBytes: 65_536 });
  try {
    check(validImageReference(image));
    const inspected = await command(['image', 'inspect', '--format', startupImageFormat, image]);
    check(inspected.ok);
    const metadata = json(inspected.stdout);
    check(metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata) &&
      Object.keys(metadata).length === 8 && typeof metadata.id === 'string' && imagePattern.test(metadata.id) &&
      metadata.volumeCount === 0 && metadata.apexSelectors === '' && metadata.nodeEnvEntries === '1' &&
      metadata.productionEntries === '1' && metadata.entrypointExpected === true && metadata.cmdEmpty === true &&
      metadata.workingDirExpected === true);
    report.imageId = metadata.id;
    for (const [index, definition] of cases.entries()) {
      const code = await runCase(definition, metadata.id, command, report.cases[index]);
      // Fail fast even with confirmed cleanup; ambiguous cleanup can NEVER
      // cause another case to create or a partial suite to claim success.
      if (code !== 'STARTUP_OK') { report.code = code; return report; }
    }
    report.ok = true;
    report.code = 'STARTUP_OK';
  } catch { /* No Docker output, argv/env, arbitrary metadata or raw exceptions. */ }
  return report;
}
