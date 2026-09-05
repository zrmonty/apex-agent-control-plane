import { performance } from "node:perf_hooks";
import process from "node:process";

export interface ClockSnapshot {
  monotonicNs: bigint;
  unixUs: bigint;
  /** Wall anchor granularity; not the resolution or accuracy of elapsed time. */
  resolutionNs: bigint;
  /** Estimated local anchor error, not UTC accuracy or a long-term drift bound. */
  uncertaintyUs?: bigint;
  source: string;
}

export interface Clock {
  now(): ClockSnapshot;
}

export interface WallClockSample {
  unixUs: bigint;
  /** Declared source granularity, including quantization in its representation. */
  resolutionNs: bigint;
  /** Local source/conversion error estimate, excluding acquisition and UTC error. */
  uncertaintyUs: bigint;
}

/** Inject time sources at the OS boundary without restricting wall precision to ms. */
export interface ClockSource {
  monotonicNowNs(): bigint;
  wallNow(): WallClockSample;
  source: string;
}

function splitMilliseconds(ms: number): { wholeUs: bigint; fractionalMs: number; roundingNs: bigint } {
  if (!Number.isFinite(ms) || ms < 0 || ms > Number.MAX_SAFE_INTEGER) {
    throw new RangeError("performance milliseconds must be finite, non-negative and safely representable");
  }
  const wholeMs = Math.trunc(ms);
  return {
    wholeUs: BigInt(wholeMs) * 1_000n,
    fractionalMs: ms - wholeMs,
    // value * epsilon conservatively bounds one double's spacing (rounded up).
    roundingNs: BigInt(Math.ceil(ms * Number.EPSILON * 1_000_000)),
  };
}

function performanceWallNow(): WallClockSample {
  // Node 24: https://nodejs.org/docs/latest-v24.x/api/perf_hooks.html#performancetimeorigin
  const originMs = performance.timeOrigin;
  const elapsedMs = performance.now();
  const origin = splitMilliseconds(originMs);
  const elapsed = splitMilliseconds(elapsedMs);
  // Only the fractions are added as doubles, so their carry survives without
  // rounding at epoch magnitude. Epoch arithmetic is exclusively bigint micros.
  const fractionalUs = BigInt(Math.floor((origin.fractionalMs + elapsed.fractionalMs) * 1_000));
  const resolutionNs = [1_000n, origin.roundingNs, elapsed.roundingNs]
    .reduce((coarsest, ns) => ns > coarsest ? ns : coarsest);
  // Node 24 builds timeOrigin from uv_gettimeofday's microsecond representation.
  // Budget 1 us for that representation, two double roundings per component
  // (native conversion and scaling), and 1 us for fractional arithmetic/truncation.
  // These are representation estimates, not measured hardware tick resolution.
  // OS synchronization error, Node's startup wall/hrtime pairing error and drift
  // since process start are unknown; the later acquisition bracket cannot bound them.
  const conversionNs = 2_000n + 2n * (origin.roundingNs + elapsed.roundingNs);
  return {
    unixUs: origin.wholeUs + elapsed.wholeUs + fractionalUs,
    resolutionNs,
    uncertaintyUs: (conversionNs + 999n) / 1_000n,
  };
}

const systemSource: ClockSource = {
  monotonicNowNs: () => process.hrtime.bigint(),
  wallNow: performanceWallNow,
  source: "process.hrtime.bigint() with node:perf_hooks performance.timeOrigin + performance.now() wall anchor",
};

function validateInterval(startNs: bigint, endNs: bigint): void {
  if (typeof startNs !== "bigint" || typeof endNs !== "bigint" || startNs < 0n || endNs < 0n) {
    throw new RangeError("monotonic clock samples must be non-negative bigints");
  }
  if (endNs < startNs) {
    throw new RangeError("monotonic clock moved backwards");
  }
}

function validateWallSample(wall: WallClockSample): void {
  if (!wall || typeof wall.unixUs !== "bigint" || wall.unixUs < 0n) {
    throw new RangeError("wall clock unixUs must be a non-negative bigint");
  }
  if (typeof wall.resolutionNs !== "bigint" || wall.resolutionNs <= 0n) {
    throw new RangeError("wall clock resolutionNs must be a positive bigint");
  }
  if (typeof wall.uncertaintyUs !== "bigint" || wall.uncertaintyUs < 0n) {
    throw new RangeError("wall clock uncertaintyUs must be a non-negative bigint");
  }
}

export function durationUs(startNs: bigint, endNs: bigint): bigint {
  validateInterval(startNs, endNs);
  return (endNs - startNs) / 1_000n;
}

/**
 * Reuse one clock per process for a stable epoch mapping. The wall sample is
 * bracketed by monotonic reads; its midpoint minimizes acquisition error.
 * Later wall adjustments never change this mapping. Declared source uncertainty
 * plus the rounded-up acquisition radius is an estimate of local anchor error,
 * not a bound on UTC accuracy, host synchronization error, or subsequent drift.
 */
export function createClock(readings: ClockSource = systemSource): Clock {
  const source = readings.source;
  if (typeof source !== "string" || source.trim().length === 0) {
    throw new RangeError("clock source must have a non-empty label");
  }
  const beforeNs = readings.monotonicNowNs();
  const wall = readings.wallNow();
  const afterNs = readings.monotonicNowNs();
  validateInterval(beforeNs, afterNs);
  validateWallSample(wall);
  const windowNs = afterNs - beforeNs;
  const anchorNs = beforeNs + windowNs / 2n;
  const anchorUnixUs = wall.unixUs;
  const resolutionNs = wall.resolutionNs;
  const radiusNs = (windowNs + 1n) / 2n;
  const uncertaintyUs = wall.uncertaintyUs + (radiusNs + 999n) / 1_000n;
  let lastNs = afterNs;

  return {
    now(): ClockSnapshot {
      const monotonicNs = readings.monotonicNowNs();
      validateInterval(lastNs, monotonicNs);
      lastNs = monotonicNs;
      return {
        monotonicNs,
        unixUs: anchorUnixUs + durationUs(anchorNs, monotonicNs),
        resolutionNs,
        uncertaintyUs,
        source,
      };
    },
  };
}
