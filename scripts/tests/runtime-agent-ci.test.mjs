// Source-only CI contract checks for the known indentation/section layout.
// Not a general YAML/shell parser, Cargo execution, PKI generation or Actions proof.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8')
  .replaceAll('\r\n', '\n');
assert.equal(workflow.split('\njobs:\n').length, 2, 'one known top-level jobs mapping');
const jobs = workflow.split('\njobs:\n')[1];
const gateName = 'Test runtime agent and shared boundaries';
const packageTests = [
  'cargo test --locked -p apex-domain',
  'cargo test --locked -p apex-auth',
  'cargo test --locked -p apex-proxy-runtime-agent',
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
  assert.equal(rust.split('APEX_BROWSER_TEST_PKI_DIR').length - 1, 1, 'only the existing GITHUB_ENV export');
  assert.equal(rust.split('APEX_RUNTIME_FIXTURE_PATH').length - 1, 1, 'one explicit collected-artifact binding');
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

test('source-only: gateway-contracts invokes this Node contract suite as an active command', () => {
  const gateway = job('gateway-contracts');
  const verify = namedStep(gateway, 'Verify generated contracts and compatibility');
  const invocation = 'node --test scripts/tests/runtime-agent-ci.test.mjs';
  assert.equal(commands(verify).filter((line) => line === invocation).length, 1);
  assert.doesNotMatch(verify, /^        (?:if|continue-on-error|working-directory|shell):/m);
  assert.doesNotMatch(gateway.slice(0, gateway.indexOf('    steps:')), /^    (?:if|continue-on-error|defaults):/m);
});
