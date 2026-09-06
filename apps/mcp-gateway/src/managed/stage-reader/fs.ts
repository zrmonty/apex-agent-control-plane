import { constants } from "node:fs";
import { lstat, open, opendir } from "node:fs/promises";
import type { FileSystem, Timers } from "./types.js";
export const localFiles: FileSystem = {
  platform: process.platform,
  flags: { readOnly: constants.O_RDONLY, directory: constants.O_DIRECTORY,
    noFollow: constants.O_NOFOLLOW, nonblock: constants.O_NONBLOCK },
  lstat: path => lstat(path, { bigint: true }),
  async open(path, flags) {
    const handle = await open(path, flags);
    return { fd: handle.fd, stat: () => handle.stat({ bigint: true }),
      read: async (buffer, offset, length) => (await handle.read(buffer, offset, length, null)).bytesRead,
      close: () => handle.close() };
  },
  async opendir(path) {
    // latin1 is one-to-one bytes; non-ASCII names fail the exact ASCII set check.
    const handle = await opendir(path, { encoding: "latin1", bufferSize: 1 });
    return { read: async () => (await handle.read())?.name ?? null, close: () => handle.close() };
  },
};
export const localTimers: Timers = {
  now: () => process.hrtime.bigint(),
  after(ms, callback) { const timer = setTimeout(callback, ms); return () => clearTimeout(timer); },
};
