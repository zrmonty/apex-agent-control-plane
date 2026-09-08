// Test-only observation and failure-cleanup boundaries; not production timeouts.
import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import { ReadinessCheckStatus, type ReadinessReport } from "@apex/contracts";

export function assertRefresh(first: ReadinessReport, next: ReadinessReport, arrivals: readonly bigint[]) {
  assert.equal(next.ready, true); assert.equal(next.checks.length, 9); assert.equal(next.stages.length, 9);
  assert.equal(new Set(next.checks.map(c => c.id)).size, 9);
  assert.ok(next.checks.every(c => c.status === ReadinessCheckStatus.PASS));
  assert.ok(next.observedAtUnixUs > first.observedAtUnixUs, "new completed report, not cached PASS");
  for (const stage of first.stages) {
    assert.ok(next.stages.find(s => s.name === stage.name)!.startedAtUnixUs > stage.startedAtUnixUs);
  }
  const config = first.stages.find(s => s.name === "readiness.config")!;
  const network = first.stages.find(s => s.name === "readiness.network")!;
  assert.notEqual(network.durationNs, undefined);
  // Same process clock is a fixed monotonic->Unix mapping, not adjustable wall time.
  // 1ms allows sampling/config dispatch and microsecond quantization at sweep start.
  assert.ok(next.stages.find(s => s.name === config.name)!.startedAtUnixUs - config.startedAtUnixUs >= 4_999_000n);
  // Arrival phase varies: subtract the measured FIRST sweep's config->NETWORK-end
  // envelope (includes guard/TLS/RPC delay). Never demand exact arrival spacing.
  const allowance = (network.startedAtUnixUs - config.startedAtUnixUs) * 1000n + network.durationNs! + 1_000_000n;
  assert.ok(allowance < 2_000_000_000n, "initial sweep phase remains within RPC bound");
  assert.equal(arrivals.length, 2); assert.ok(arrivals[1] - arrivals[0] >= 5_000_000_000n - allowance);
}

export async function observePending(check: () => void, ms = 200): Promise<void> {
  const start = performance.now();
  do { check(); await delay(5); } while (performance.now() - start < ms);
  check(); // All event handlers latch progress, including between samples.
  assert.ok(performance.now() - start < 1500, "observation exceeded RPC budget margin");
}
export async function bounded<T>(work: Promise<T>, ms: number, label: string): Promise<T> {
  let timer!: NodeJS.Timeout;
  try { return await Promise.race([work, new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(Error(label)), ms);
  })]); } finally { clearTimeout(timer); }
}
export async function cleanupFixture(owner: { cancel(): void; closed: Promise<void> }, close: () => Promise<void>, ms = 1000) {
  owner.cancel();
  try {
    // Destroy synthetic operations before joining an intentionally fail-closed owner.
    await bounded(Promise.all([close(), owner.closed]), ms, "fixture cleanup deadline");
    return "fixture-cleaned";
  } catch { return "fixture-cleanup-unproved"; } // Never a graceful/empty-handoff proof.
}
