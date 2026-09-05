import assert from "node:assert/strict";
import { GatewayError } from "../../contracts.js";
import { ControlledTime } from "../readiness/test-support.js";
import { isolatedGate, startLoad } from "./job.js";
import { fixtureData } from "./fixture-data.js";
import type { HealthFileSystem, HealthMaterialLoadOptions, Metadata } from "./types.js";

export const paths = ["/run/apex/runtime/runtime-revision.json", "/run/apex/runtime/launch-context.json", "/run/apex/runtime/health-token"];
export function metadata(size: number, index: number): Metadata {
  return { dev: 3n, ino: BigInt(index + 10), mode: 0o100400n, uid: 10001n, gid: 10001n,
    nlink: 1n, size: BigInt(size), mtimeNs: 9007199254740993n, ctimeNs: 9007199254740995n };
}
export function fixture() {
  const data = fixtureData(), time = new ControlledTime(), gate = isolatedGate();
  const calls: string[] = [], buffers: Buffer[] = [];
  const counts = { active: 0, closed: 0, fatal: 0, current: true };
  const os: HealthFileSystem = {
    platform: "linux", flags: { readOnly: 0, noFollow: 131072, nonblock: 2048 },
    async lstat(path) {
      calls.push(`lstat:${path}`);
      const index = paths.indexOf(path);
      if (index < 0) return { ...metadata(0, 99), mode: 0o40755n };
      return metadata(data.files[index].length, index);
    },
    async open(path, flags) {
      calls.push(`open:${path}`);
      assert.equal(flags, 131072 | 2048);
      const index = paths.indexOf(path); assert.ok(index >= 0);
      let position = 0, closed = false;
      counts.active++;
      return {
        async stat() { calls.push(`stat:${path}`); return metadata(data.files[index].length, index); },
        async read(buffer, offset, length) {
          assert.ok(!closed); calls.push(`read:${path}`); buffers.push(buffer);
          const count = Math.min(length, data.files[index].length - position);
          data.files[index].copy(buffer, offset, position, position + count); position += count;
          return count;
        },
        async close() { assert.ok(!closed); closed = true; calls.push(`close:${path}`); counts.active--; counts.closed++; },
      };
    },
  };
  const options: HealthMaterialLoadOptions = { owner: { expected: data.expected, isCurrent: () => counts.current },
    clock: time.clock, onFatal: () => { counts.fatal++; } };
  return { ...data, time, os, options, calls, buffers, counts,
    start(input = options, files = os) { return startLoad(input, files, { ...time.scheduler, monotonicNs: () => time.ns }, gate); } };
}
export async function rejects(completion: Promise<unknown>): Promise<void> {
  await assert.rejects(completion, (error: unknown) => {
    assert.ok(error instanceof GatewayError);
    assert.equal(error.message, "INVALID_INPUT: health material rejected safely");
    assert.equal((error as Error & { cause?: unknown }).cause, undefined);
    return true;
  });
}
export function wiped(buffers: readonly Buffer[]): boolean { return buffers.every(b => b.every(value => value === 0)); }
export async function flush(): Promise<void> { for (let i = 0; i < 80; i++) await Promise.resolve(); }
