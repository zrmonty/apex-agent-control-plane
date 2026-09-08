// Source-only CI contract checks for the known indentation/section layout.
// Not a general YAML/shell parser, Cargo execution, PKI generation or Actions proof.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

const workflow = readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8')
  .replaceAll('\r\n', '\n');
assert.equal(workflow.split('\njobs:\n').length, 2, 'one known top-level jobs mapping');
const jobs = workflow.split('\njobs:\n')[1];
const gateName = 'Test runtime agent and shared boundaries';
const packageTests = [
  'cargo test --locked -p apex-domain',
  'cargo test --locked -p apex-auth',
  "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo --preserve-env=APEX_RUNTIME_FIXTURE_PATH,APEX_BROWSER_TEST_PKI_DIR,RUST_BACKTRACE --' cargo test --locked -p apex-proxy-runtime-agent",
];
const lintCommand = 'cargo clippy --locked -p apex-domain -p apex-auth -p apex-proxy-runtime-agent --all-targets -- -D warnings';

function job(name) {
  const lines = jobs.split('\n');
  const header = `  ${name}:`;
  assert.equal(lines.filter((line) => line === header).length, 1, `one ${name} job`);
  const start = lines.indexOf(header);
  const next = lines.findIndex((line, index) => index > start && /^  [a-z][a-z0-9-]*:$/.test(line));
  return lines.slice(start, next < 0 ? lines.length : next).join('\n');
}

function steps(section) {
  const starts = [...section.matchAll(/^      - (?:name|uses|run): .+$/gm)];
  assert.ok(starts.length > 0, 'known job must contain steps');
  return starts.map((match, index) => section.slice(match.index, starts[index + 1]?.index).trimEnd());
}

function namedStep(section, name) {
  const matches = steps(section).filter((step) => step.startsWith(`      - name: ${name}\n`));
  assert.equal(matches.length, 1, `one active step: ${name}`);
  return matches[0];
}

function commands(step) {
  const lines = step.split('\n');
  assert.equal(lines.filter((line) => line === '        run: |').length, 1, 'literal run block');
  return lines.slice(lines.indexOf('        run: |') + 1).map((line) => {
    assert.match(line, /^ {10}\S/, 'simple commands at the known block indentation');
    return line.slice(10);
  });
}

test('source-only: coverage stays in the existing cached workspace job, without an extra job', () => {
  assert.deepEqual([...jobs.matchAll(/^  ([a-z][a-z0-9-]*):$/gm)].map((match) => match[1]), [
    'gateway-contracts', 'source-line-limits', 'mcp-gateway', 'operator-ui', 'python-sdk',
    'rust-ingest', 'rust-control-plane', 'rust-agent-supervisor', 'rust-sast', 'python-sast',
    'lab-only-settings-gate', 'signed-bundles',
  ]);
  const rust = job('rust-control-plane');
  assert.match(rust, /^    defaults:\n      run:\n        working-directory: apps\/control-plane-api$/m);
  const cache = namedStep(rust, 'Cache Cargo registry, git sources, and workspace target');
  assert.match(cache, /^        uses: actions\/cache@v5$/m);
  assert.match(cache, /^          path: \|\n            ~\/\.cargo\/registry\n            ~\/\.cargo\/git\n            target$/m);
  assert.ok(rust.indexOf(cache) < rust.indexOf(namedStep(rust, 'Test (control gateway)')));
  assert.doesNotMatch(rust, /\bCARGO_TARGET_DIR\b|--target-dir\b/);
});

test('source-only: the actual collector follows the existing exporter run with no second export', () => {
  const rust = job('rust-control-plane');
  const exporter = namedStep(rust, 'Test (control gateway)');
  const collector = namedStep(rust, 'Collect only the generated runtime contract');
  assert.ok(rust.indexOf(exporter) < rust.indexOf(collector));
  assert.match(exporter, /^          TMPDIR: \$\{\{ runner\.temp \}\}\/rust-contract-export$/m);
  assert.deepEqual(commands(collector), [
    'node --test scripts/tests/collect-runtime-fixture.test.mjs',
    'node scripts/collect-runtime-fixture.mjs --root "${RUNNER_TEMP}/rust-contract-export" --out "${RUNNER_TEMP}/runtime-revision.json"',
  ]);
  assert.equal(rust.split('node scripts/collect-runtime-fixture.mjs ').length - 1, 1);
  assert.equal(rust.split('cargo test --locked --features "test-support,postgres,valkey"').length - 1, 1);
});

test('source-only: runtime coverage is immediately after collection and before artifact sharing', () => {
  const rust = job('rust-control-plane');
  const all = steps(rust);
  const collector = all.indexOf(namedStep(rust, 'Collect only the generated runtime contract'));
  assert.equal(all[collector + 1], namedStep(rust, gateName));
  assert.equal(all[collector + 2], namedStep(rust, 'Share the actual Rust export with the gateway tests'));
});

test('source-only: the gate uses the collected artifact and inherits existing PKI without regeneration', () => {
  const rust = job('rust-control-plane');
  const gate = namedStep(rust, gateName);
  const pki = namedStep(rust, 'Generate disposable browser TLS fixtures');
  assert.ok(rust.indexOf(pki) < rust.indexOf(gate));
  assert.match(pki, /^          echo "APEX_BROWSER_TEST_PKI_DIR=\$\{fixture_root\}" >> "\$GITHUB_ENV"$/m);
  assert.deepEqual(pki.match(/^          python -B deploy\/compose\/live-mtls\/generate_pki\.py .+$/gm), [
    '          python -B deploy/compose/live-mtls/generate_pki.py --out "${fixture_root}/trusted"',
    '          python -B deploy/compose/live-mtls/generate_pki.py --out "${fixture_root}/untrusted"',
  ]);
  assert.equal(rust.split('generate_pki.py').length - 1, 2);
  assert.equal(rust.split('APEX_BROWSER_TEST_PKI_DIR').length - 1, 2, 'existing GITHUB_ENV export plus the narrow runner allowlist');
  assert.equal(gate.split('APEX_RUNTIME_FIXTURE_PATH').length - 1, 2, 'one collected-artifact binding plus the narrow runner allowlist in the full package gate');
  assert.deepEqual(gate.split('\n').slice(1, -commands(gate).length), [
    '        env:',
    '          APEX_RUNTIME_FIXTURE_PATH: ${{ runner.temp }}/runtime-revision.json',
    '          CARGO_NET_RETRY: "10"',
    '          CARGO_HTTP_MULTIPLEXING: "false"',
    '          RUST_BACKTRACE: "1"',
    '        run: |',
  ], 'no conditional step, error bypass, PKI override or isolated working/target directory');
  assert.doesNotMatch(rust.slice(0, rust.indexOf('    steps:')), /^    (?:if|continue-on-error):/m);
});

test('source-only: full package tests retain dependency units, agent integrations and auth doctests', () => {
  const run = commands(namedStep(job('rust-control-plane'), gateName));
  assert.deepEqual(run.slice(0, 3), packageTests);
  // Exact unfiltered commands deliberately exclude --lib/--tests/--all-targets:
  // package-default cargo test includes the auth compile_fail lifetime doctest.
  assert.deepEqual(run, [...packageTests, lintCommand], 'no filters, skips, ignored failures or extra exporter/fixture commands');
});

test('source-only: scoped Clippy covers all targets in all three packages with warnings denied', () => {
  const run = commands(namedStep(job('rust-control-plane'), gateName));
  assert.equal(run.at(-1), lintCommand);
  assert.equal(run.filter((line) => line.startsWith('cargo clippy ')).length, 1);
});

test('source-only: only agent test execution uses the allowlisted root runner, not compilation', () => {
  const rust = job('rust-control-plane');
  const run = commands(namedStep(rust, gateName));
  const key = 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER';
  assert.equal(rust.split(key).length - 1, 1, 'one command-local host runner, not a job or step env override');
  assert.match(run[2], /^CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo --preserve-env=APEX_RUNTIME_FIXTURE_PATH,APEX_BROWSER_TEST_PKI_DIR,RUST_BACKTRACE --' cargo test --locked -p apex-proxy-runtime-agent$/);
  assert.deepEqual([run[0], run[1], run[3]], [
    'cargo test --locked -p apex-domain',
    'cargo test --locked -p apex-auth',
    lintCommand,
  ], 'shared tests and Clippy stay unprivileged; Cargo itself is never sudoed');
  assert.doesNotMatch(run.join('\n'), /sudo\s+(?:-E\b|cargo\b)|--target(?:[ =]|-dir)|--test-threads|--ignored|--skip|--lib\b|--tests\b|\|\|/);
});

test('source-only: gateway-contracts invokes this Node contract suite as an active command', () => {
  const gateway = job('gateway-contracts');
  const verify = namedStep(gateway, 'Verify generated contracts and compatibility');
  const invocation = 'node --test scripts/tests/runtime-agent-ci.test.mjs';
  assert.equal(commands(verify).filter((line) => line === invocation).length, 1);
  assert.doesNotMatch(verify, /^        (?:if|continue-on-error|working-directory|shell):/m);
  assert.doesNotMatch(gateway.slice(0, gateway.indexOf('    steps:')), /^    (?:if|continue-on-error|defaults):/m);
});

test('source-only: Linux staging and real signature verification are required acceptance gates', () => {
  const gate = namedStep(job('rust-control-plane'), 'Verify Linux runtime provisioning boundaries');
  assert.doesNotMatch(gate, /^        (?:if|continue-on-error):/m);
  assert.match(gate, /--features staging-integration --lib --test secret_staging --no-run/);
  assert.match(gate, /sudo -- "\$\{staging_test\}" --test-threads=1/);
  assert.match(gate, /sudo -- "\$\{agent_test\}" signature::tests::live_cosign_accepts_exact_signer_and_rejects_wrong_identity --exact --ignored/);
  assert.match(gate, /4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71/);
  assert.match(gate, /sha256sum --check --strict/);
  assert.match(gate, /signature::tests::filesystem:: --ignored --test-threads=1/);
  assert.match(gate, /sudo -u '#1001' -g '#1001'/);
  assert.match(gate, /signature::tests::dedicated_agent_uid_can_open_its_protected_cache --exact --ignored/);
});

test('source-only: daemon-mutating joint journeys require explicit native acceptance opt-in', () => {
  for (const file of ['journey', 'registration']) {
    const source = readFileSync(new URL(`../../apps/control-plane-api/tests/proxy_runtime_execution/${file}.rs`, import.meta.url), 'utf8');
    assert.match(source, /#\[test\]\s*#\[ignore = "requires explicit owned Linux Docker\/Cosign\/PostgreSQL fixtures; run with --ignored"\]\s*fn actual_joint_/);
  }
  const fixture = readFileSync(new URL('../../apps/control-plane-api/tests/proxy_runtime_execution/fixture.rs', import.meta.url), 'utf8');
  assert.match(fixture, /var_os\("APEX_TASK3B_ROOT"\)\.expect\("scoped owned Docker volume required"\)/);
  const acceptance = readFileSync(new URL('../../docs/operations/runtime-execution-control-plane.md', import.meta.url), 'utf8');
  assert.ok(acceptance.includes('--test proxy_runtime_execution -- --ignored --test-threads=1'));
});

test('source-only: health client gate explicitly runs ignored TLS tests using the actual launch export', () => {
  const rust = job('rust-control-plane');
  const health = namedStep(rust, 'Verify authenticated runtime health client');
  assert.ok(rust.indexOf(namedStep(rust, 'Test runtime agent and shared boundaries')) < rust.indexOf(health));
  assert.doesNotMatch(health, /^        (?:if|continue-on-error|working-directory|shell):/m);
  assert.match(health, /^          APEX_RUNTIME_FIXTURE_PATH: \$\{\{ runner\.temp \}\}\/runtime-revision.json$/m);
  assert.doesNotMatch(health, /APEX_BROWSER_TEST_PKI_DIR:|generate_pki|sudo|\|\||--skip/);
  const run = commands(health);
  assert.deepEqual(run.slice(0, 4), [
    'set -euo pipefail',
    'mkdir "${RUNNER_TEMP}/runtime-health-launch"',
    'APEX_LAUNCH_EXPORT_DIR="${RUNNER_TEMP}/runtime-health-launch" cargo test --locked -p apex-proxy-runtime-agent --lib launch::tests::export::export_launch_parity_fixture -- --exact --ignored',
    'APEX_RUNTIME_FIXTURE_PATH="${RUNNER_TEMP}/runtime-health-launch/runtime-revision.json" cargo test --locked -p apex-control-plane-api --features "test-support,postgres,valkey" --lib proxy::runtime_client::health::tests:: -- --ignored --nocapture | tee "${RUNNER_TEMP}/runtime-health-client.log"',
  ]);
  assert.equal(run.length, 5, 'a final result check must reject an empty or silently skipped suite');
  assert.ok(run[4].includes('runtime-health-client.log'));
  assert.ok(run[4].includes('0 failed; 0 ignored;'));
  assert.ok(run[4].includes('passed < 11'));
});

test('health workflow shell rejects missing coverage, skipped tests and a failed Cargo pipeline', () => {
  const run = commands(namedStep(job('rust-control-plane'), 'Verify authenticated runtime health client'));
  const script = `
cargo() {
  case "$*" in
    *export_launch_parity_fixture*) return 0 ;;
    *proxy::runtime_client::health::tests::*) printf '%s\\n' "$HEALTH_OUTPUT"; return "$HEALTH_STATUS" ;;
    *) return 97 ;;
  esac
}
${run.join('\n')}
`;
  // This tests the checked-in shell/result check, not real Cargo or TLS.
  for (const [output, status, accepted] of [
    ['test result: ok. 11 passed; 0 failed; 0 ignored;', 0, true],
    ['test result: ok. 12 passed; 0 failed; 0 ignored;', 0, true],
    ['test result: ok. 0 passed; 0 failed; 0 ignored;', 0, false],
    ['test result: ok. 11 passed; 0 failed; 1 ignored;', 0, false],
    ['no test result', 0, false],
    ['test result: ok. 11 passed; 0 failed; 0 ignored;', 1, false],
  ]) {
    const directory = mkdtempSync(path.join(tmpdir(), 'apex-health-ci-'));
    try {
      const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
      const result = spawnSync(bash, ['-c', script], {
        env: { ...process.env, RUNNER_TEMP: directory.replaceAll('\\', '/'),
          HEALTH_OUTPUT: output, HEALTH_STATUS: String(status) },
        windowsHide: true, timeout: 10_000, encoding: 'utf8',
      });
      assert.equal(result.error, undefined);
      assert.equal(result.signal, null);
      assert.equal(result.status === 0, accepted, result.stderr || output);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test('source-only: live fixture listing drains its input under pipefail', () => {
  const live = readFileSync(new URL('../../.github/workflows/live-mtls-e2e.yml', import.meta.url), 'utf8');
  for (const directory of ['secrets', 'secrets-host']) {
    assert.ok(live.includes(`ls -la ${directory} | sed -n '1,40p'`));
    assert.ok(!live.includes(`ls -la ${directory} | head`));
  }
});
