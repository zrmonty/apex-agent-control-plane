#!/usr/bin/env node
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

// Task 1 registry. Live runners belong to task 21; inventory is not release proof.
const cases = [
  {
    id: 'fresh-ui-create-deploy', title: 'Fresh UI create/deploy', suites: ['smoke'],
    observation: 'Fresh install and real login/scope selection; save/reload/discover/publish a UI draft, then observe a new container and HTTPS route without a preseeded proxy.',
    requiredEvidence: [
      'Redacted real browser journey and authenticated operation/revision IDs, including selected tools and SDK tools/list.',
      'Empty-project baseline, actual image digest, container/route ownership labels and fresh readiness handshake.',
    ],
  },
  {
    id: 'allowed-denied-call', title: 'Allowed/denied call', suites: ['smoke'],
    observation: 'Real MCP SDK calls reach Apex policy; allow and deny decisions match exact upstream counters and durably admitted evidence.',
    requiredEvidence: [
      'Redacted SDK outcomes, policy decision IDs, exact before/after upstream counters and zero unexpected writes.',
      'Expected/actual durable event IDs linked to call/proxy/revision IDs and the real activity UI/query.',
    ],
  },
  {
    id: 'two-proxies', title: 'Two proxies', suites: ['isolation'],
    observation: 'Two proxies have distinct upstreams, credentials, catalogs, tools, policy and state; cross-proxy tokens, sessions and egress are denied.',
    requiredEvidence: [
      'Distinct proxy/revision/credential-reference IDs, catalogs, runtime routes and independent state observations.',
      'Cross-proxy SDK/session/egress denial outcomes and upstream counters, with credentials and payloads removed.',
    ],
  },
  {
    id: 'cli-stdio', title: 'CLI/stdio', suites: ['isolation'],
    observation: 'Unrelated structured tools, approved CLI profiles and controlled stdio use real subprocess/SDK framing without shell or network bypass.',
    requiredEvidence: [
      'Approved profile/executable digest, process ownership and redacted SDK framing/outcomes for real CLI and stdio.',
      'Argument/shell escape and forbidden network rejection results, exact execution counters and durable event IDs; no raw argv.',
    ],
  },
  {
    id: 'approval-limits', title: 'Approval/limits', suites: ['isolation', 'failure'],
    observation: 'Pending and dual approvals revalidate policy before execution; queues are bounded and rate/concurrency/budget accounting is exact.',
    requiredEvidence: [
      'Approval IDs, distinct approver aliases, expiry/revalidation/single-consumption outcomes and correlated decision/event IDs.',
      'Queue/concurrency/rate/budget limits with expected/actual admissions, rejections and execution counters; no raw arguments.',
    ],
  },
  {
    id: 'pause-retire', title: 'Pause/retire', suites: ['smoke', 'failure'],
    observation: 'Pause during a call blocks new and existing-session admissions, drains then resumes; retirement stops/removes the runtime and route.',
    requiredEvidence: [
      'Operation IDs and observed-state timeline for pause/drain/resume/retire with existing-session and new-call rejection results.',
      'Exact in-flight/upstream counters and owned runtime/route inspection proving drain, resume and removal.',
    ],
  },
  {
    id: 'rotate-rollback', title: 'Rotate/rollback', suites: ['isolation', 'failure'],
    observation: 'Rotation changes generation and credentials, invalidates old sessions, and rollback uses valid credentials with at most one routable revision.',
    requiredEvidence: [
      'Operation/revision/generation IDs, actual image digests and credential-reference versions before/after rotation and rollback.',
      'Old-session rejection and route/drain observations proving no double routing and valid rollback readiness.',
    ],
  },
  {
    id: 'controller-runtime-crash', title: 'Controller/runtime crash', suites: ['failure'],
    observation: 'Restart control plane, runtime agent and gateway; persisted desired state resumes without duplicate execution or provisioning.',
    requiredEvidence: [
      'Fault injection boundaries and persisted operation/request/generation/fencing IDs before/after each process restart.',
      'Fresh readiness, exact provision/execution counters, runtime ownership inventory and canonical durable event IDs.',
    ],
  },
  {
    id: 'governance-identity-outage', title: 'Governance/identity outage', suites: ['failure'],
    observation: 'Governance or identity loss fails closed with actionable redacted state and no unauthorized upstream execution.',
    requiredEvidence: [
      'Separate governance/issuer/identity fault and recovery boundaries with safe client/UI error codes and observed service state.',
      'Expected/actual admission denials, upstream counters and correlated durable decisions where admission remains available.',
    ],
  },
  {
    id: 'evidence-outage', title: 'Evidence outage', suites: ['failure'],
    observation: 'Evidence admission outage never returns a successful unrecorded result; uncertain execution is reported honestly without blind retry.',
    requiredEvidence: [
      'Fault timing around execution/admission, SDK failure or uncertain outcome, and exact upstream execution counts.',
      'Expected/actual durable event IDs and recovery reconciliation proving no unrecorded success or automatic duplicate write.',
    ],
  },
  {
    id: 'projection-outage', title: 'NATS/ClickHouse/archive outage', suites: ['failure'],
    observation: 'Durable ACK survives separate NATS, ClickHouse and archive outages; UI projection lag is visible and later recovers.',
    requiredEvidence: [
      'Each downstream outage/recovery boundary, durable ACK/event IDs and unchanged accepted-call counts.',
      'Redacted UI stale/lag state, event cursors and eventual projected/archive IDs matching admitted events.',
    ],
  },
  {
    id: 'microsecond-precision', title: 'Microsecond precision', suites: ['tracing'],
    observation: 'Injected 1/7/999-us values, six-digit timestamp fractions and integers above 2^53 survive gateway, RPC/JSON, admission, store, query and UI exactly.',
    requiredEvidence: [
      'Instrumented test-clock inputs and exact decimal-string values at every production boundary, including 9007199254740993.',
      'Matching redacted durable trace JSON and UI values with six timestamp fraction digits, clock source/resolution and span ancestry.',
    ],
  },
  {
    id: 'wall-clock-jump-skew', title: 'Wall-clock jump/skew', suites: ['tracing'],
    observation: 'Backward wall-clock jumps and remote skew leave local durations nonnegative; overlapping calls remain distinct and cross-host uncertainty is visible.',
    requiredEvidence: [
      'Clock fault inputs, process anchors, monotonic duration strings, clock resolution/uncertainty and correlated overlapping spans.',
      'Real UI/trace output showing unknown/skewed clocks without inferred cross-host wire latency or summed overlapping root duration.',
    ],
  },
  {
    id: 'trace-exporter-loss', title: 'Trace exporter loss', suites: ['tracing', 'failure'],
    observation: 'Exporter outage leaves mandatory durable evidence intact while partial traces and bounded-queue loss metrics remain visible.',
    requiredEvidence: [
      'Exporter fault/recovery boundaries, durable ACK/event IDs and exact accepted-call/upstream counters.',
      'Partial/loss flags, drop counters and queue bounds matched to the real UI and redacted trace query.',
    ],
  },
  {
    id: 'backup-restore', title: 'Backup/restore', suites: ['failure'],
    observation: 'A tested database backup restores proxies, revisions, approvals and history in an owned disposable project; fresh readiness precedes routing.',
    requiredEvidence: [
      'Redacted backup/restore commands, dedicated database/project ownership and expected/actual restored record IDs/counts.',
      'Restore/restart observation timeline, fresh runtime handshake before routing and successful reconciled event/history queries.',
    ],
  },
].map((entry) => ({
  ...entry, kind: 'live-acceptance', required: true, implementation: 'unimplemented',
}));

function main() {
  const { values, tokens } = parseArgs({
    options: {
      list: { type: 'boolean' }, case: { type: 'string' },
      profile: { type: 'string', default: 'lab' }, suite: { type: 'string' },
      artifacts: { type: 'string' }, 'keep-on-failure': { type: 'boolean', default: false },
    },
    strict: true, allowPositionals: false, tokens: true,
  });
  const seen = new Set();
  for (const token of tokens.filter(({ kind }) => kind === 'option')) {
    if (seen.has(token.name)) throw new Error(`Duplicate --${token.name} is not allowed.`);
    seen.add(token.name);
  }
  if (!['lab', 'ci'].includes(values.profile)) throw new Error('--profile must be lab or ci.');
  if (values.suite !== undefined && !['smoke', 'isolation', 'failure', 'tracing', 'all'].includes(values.suite)) {
    throw new Error('--suite must be smoke, isolation, failure, tracing or all.');
  }
  if (values.case !== undefined && !cases.some(({ id }) => id === values.case)) {
    throw new Error('Unknown --case; use --list for registered case IDs.');
  }
  if (values.case !== undefined && values.suite !== undefined) {
    throw new Error('Select either --case or --suite, not both.');
  }
  if (values.artifacts !== undefined && values.artifacts.trim() === '') {
    throw new Error('--artifacts requires a nonempty directory.');
  }
  const selected = cases.filter((entry) =>
    (values.case === undefined || entry.id === values.case)
    && (values.suite === undefined || values.suite === 'all' || entry.suites.includes(values.suite)));
  if (selected.length === 0) throw new Error('Selection contains no required acceptance cases.');
  if (values.list) {
    console.log(JSON.stringify({ type: 'acceptance-inventory', releaseGate: 'not-run', cases: selected }, null, 2));
    return;
  }
  if (values.case === undefined && values.suite === undefined) {
    throw new Error('Select --list, --case <case-id> or --suite smoke|isolation|failure|tracing|all.');
  }
  const results = selected.map((entry) => ({
    ...entry, status: 'failed', code: 'ACCEPTANCE_NOT_IMPLEMENTED',
    reason: 'Required live acceptance case is not implemented. Component tests cannot satisfy this case.',
  }));
  console.log(JSON.stringify({
    type: 'acceptance-results', releaseGate: 'failed', liveExecution: 'not-started', artifacts: [], results,
    options: {
      profile: values.profile, case: values.case ?? null, suite: values.suite ?? null,
      artifactsDirectory: values.artifacts === undefined ? null : resolve(values.artifacts),
      keepOnFailure: values['keep-on-failure'],
    },
    counts: { selected: results.length, passed: 0, failed: results.length, skipped: 0, unimplemented: results.length },
  }, null, 2));
  process.exitCode = 1;
}

try {
  main();
} catch (error) {
  console.error(JSON.stringify({ type: 'usage-error', code: 'INVALID_ARGUMENTS', message: error.message }));
  process.exitCode = 2;
}
