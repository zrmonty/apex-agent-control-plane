import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { createClock } from "../../telemetry/clock.js";
import type { HealthFileSystem, TimerBoundary } from "./types.js";

/** No alternate path/platform policy. Unsupported required flags are refused
 * by the job; these imports deliberately have no zero-valued fallback. */
export const localFiles: HealthFileSystem = {
  platform: process.platform,
  flags: { readOnly: constants.O_RDONLY, noFollow: constants.O_NOFOLLOW, nonblock: constants.O_NONBLOCK },
  lstat: path => lstat(path, { bigint: true }),
  async open(path, flags) {
    const handle = await open(path, flags);
    return {
      stat: () => handle.stat({ bigint: true }),
      read: async (buffer, offset, length) => (await handle.read(buffer, offset, length, null)).bytesRead,
      close: () => handle.close(),
    };
  },
};
const timerClock = createClock();
export const timers: TimerBoundary = { monotonicNs: () => timerClock.now().monotonicNs, after(ms, callback) {
  const timer = setTimeout(callback, ms);
  return () => clearTimeout(timer);
} };
