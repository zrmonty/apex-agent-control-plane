// Explicit unsigned collector fixture: only the health dependency is scripted.
// The agent, fixed packaged health executable, sealed-stage loader and HTTP
// health transport remain real. This is NOT gateway dependency/Serving evidence.
import '/app/health-fixture/readable.mjs';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { decodeStrict, ReadinessReportSchema, RuntimeConfigurationSchema,
  RuntimeLaunchContextSchema } from '@apex/contracts';
import { startHealthServer } from '/app/apps/mcp-gateway/dist/managed/health-server.js';
import { ReadinessReportCodec } from '/app/apps/mcp-gateway/dist/managed/readiness/report-codec.js';
import { createClock } from '/app/apps/mcp-gateway/dist/telemetry/clock.js';

if (!process.argv[1].endsWith('/guard/main.js')) {
  const config = decodeStrict(RuntimeConfigurationSchema, fs.readFileSync('/apex/runtime/runtime-revision.json', 'utf8'));
  const launchText = fs.readFileSync('/apex/runtime/launch-context.json', 'utf8');
  const launch = decodeStrict(RuntimeLaunchContextSchema, launchText);
  const original = JSON.parse(launchText);
  const ids = ['CONFIG', 'LAUNCH', 'MATERIAL', 'INBOUND_AUTH', 'UPSTREAM_CATALOG',
    'GOVERNANCE', 'EVIDENCE_ADMISSION', 'NETWORK', 'ADMISSION'];
  const clock = createClock();
  // Each scripted dependency evaluation creates a NEW observation. Anchoring a
  // single sample at process startup would expire during native provisioning,
  // before the controller ever asks for health. This is not cached-report renewal
  // and is deliberately not evidence that real gateway dependencies are healthy.
  const observe = () => {
    const anchor = clock.now();
    const report = decodeStrict(ReadinessReportSchema, JSON.stringify({
    live: true, ready: true, target: original.target,
    observedAtUnixUs: anchor.unixUs.toString(), configHash: original.configHash,
    runtimeManifestHash: original.runtimeManifestHash, processInstanceId: original.processInstanceId,
    launchContextHash: original.launchContextHash,
    checks: ids.map(id => ({id: `READINESS_CHECK_ID_${id}`, status: 'READINESS_CHECK_STATUS_PASS', reason: 'READINESS_REASON_OK'})),
    stages: ids.map(id => ({name: `readiness.${id.toLowerCase()}`, startedAtUnixUs: anchor.unixUs.toString(),
      durationNs: '7001', durationUs: '7', processInstanceId: original.processInstanceId,
      clockSource: 'unsigned-scripted-health-fixture', clockResolutionNs: '1'})),
    }));
    return {report, validForNs: 10_000_000_000n - (clock.now().monotonicNs - anchor.monotonicNs)};
  };
  const encoded = fs.readFileSync('/apex/runtime/health-token');
  assert.equal(encoded.length, 43);
  const token = Buffer.from(encoded.toString('ascii'), 'base64url'); encoded.fill(0);
  assert.equal(token.length, 32);
  const server = await startHealthServer({
    codec: new ReadinessReportCodec({config, launch}), tokenBytes: token, clock,
    state: {observation: observe},
    onFatal() { process.exit(95); },
  });
  token.fill(0);
  console.log('unsigned scripted health dependency listening');
  process.once('SIGTERM', () => { void server.close().then(() => process.exit(0), () => process.exit(96)); });
}
