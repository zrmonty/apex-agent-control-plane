import { createHash } from "node:crypto";
import type { DirectoryHandle, FileHandle, FileSystem, Metadata, Timers } from "./types.js";

// Private deterministic OS fixture. No production import of this module.
const roles = ["health-token", "governance-ca", "governance-cert", "governance-key", "governance-token",
  "evidence-ca", "evidence-cert", "evidence-key", "evidence-token", "inbound-jwks", "workload-ca",
  "workload-cert", "workload-key"];
export function completeFiles(): Record<string, Buffer> {
  return Object.fromEntries([
    ...["runtime-revision.json", "launch-context.json", "authority-profile.json", "tool-bindings.json"]
      .map(name => [name, Buffer.from("{}")] as const),
    ["instance-proof", Buffer.alloc(32, 7)],
    ...roles.map(name => [name, Buffer.from(name === "health-token" ? "A".repeat(43) : "fixture")] as const),
  ]);
}
export function fixtureHash(files: Record<string, Buffer>): string {
  const entries = Object.keys(files).sort().map(name =>
    [name, createHash("sha256").update(files[name]).digest("hex")]);
  return createHash("sha256").update(JSON.stringify(Object.fromEntries(entries))).digest("hex");
}
export class FakeTime implements Timers {
  time = 0n;
  private callbacks = new Map<object, { at: bigint; callback: () => void }>();
  now = () => this.time;
  after(ms: number, callback: () => void): () => void {
    const key = {}; this.callbacks.set(key, { at: this.time + BigInt(ms) * 1000000n, callback });
    return () => { this.callbacks.delete(key); };
  }
  advance(ms: number): void {
    this.time += BigInt(ms) * 1000000n;
    for (const [key, value] of [...this.callbacks]) if (value.at <= this.time) {
      this.callbacks.delete(key); value.callback();
    }
  }
}
export function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
export class FakeFiles implements FileSystem {
  platform = "linux";
  flags = { readOnly: 0, directory: 65536, noFollow: 131072, nonblock: 2048 };
  files = completeFiles();
  metadata = new Map<string, Metadata>();
  paths = new Map<number, string>();
  opened: string[] = [];
  closed: number[] = [];
  nextFd = 10;
  mountinfo = "21 1 0:20 / / rw - overlay overlay rw\n42 21 0:21 /stage /apex/runtime ro - ext4 /dev/test rw\n";
  fileMount = "42";
  fdinfo?: string;
  readBuffers = new Map<string, Buffer>();
  chunkSize = Infinity;
  eofAt = Infinity;
  hook?: (kind: string, path: string) => Promise<void> | void;
  directoryClosed = 0;
  directoryNames?: string[];
  canonical(path: string): string {
    const match = /^\/proc\/self\/fd\/(\d+)(.*)$/.exec(path);
    if (!match) return path;
    const base = this.paths.get(Number(match[1]));
    if (!base) throw new Error("unknown fixture FD");
    return (base === "/" && match[2] ? "" : base) + match[2];
  }
  info(path: string): Metadata {
    const found = this.metadata.get(path); if (found) return { ...found };
    const dir = ["/", "/apex", "/apex/runtime"].includes(path);
    const stage = path.startsWith("/apex/runtime");
    const data = this.files[path.slice("/apex/runtime/".length)];
    if (!dir && !data) throw new Error("fixture missing");
    return { dev: 3n, ino: BigInt([...path].reduce((n, c) => n * 31 + c.charCodeAt(0), 1) >>> 0),
      mode: dir ? stage ? 0o40500n : 0o40755n : 0o100400n,
      uid: stage ? 10001n : 0n, gid: stage ? 10001n : 0n, nlink: dir ? 2n : 1n,
      size: dir ? 4096n : BigInt(data.length), mtimeNs: 1n, ctimeNs: 1n };
  }
  async lstat(path: string): Promise<Metadata> {
    path = this.canonical(path); await this.hook?.("lstat", path); return this.info(path);
  }
  async open(path: string, _flags: number): Promise<FileHandle> {
    path = this.canonical(path); await this.hook?.("open", path);
    const fd = this.nextFd++; this.paths.set(fd, path); this.opened.push(path);
    let cursor = 0;
    const data = () => path === "/proc/self/mountinfo" ? Buffer.from(this.mountinfo) :
      path.startsWith("/proc/self/fdinfo/") ? Buffer.from(this.fdinfo ?? `pos:\t0\nflags:\t0100000\nmnt_id:\t${
        this.paths.get(Number(path.split("/").at(-1))) === "/apex/runtime" ? "42" : this.fileMount}\n`) :
      this.files[path.slice("/apex/runtime/".length)];
    return { fd, stat: async () => { await this.hook?.("stat", path); return this.info(path); },
      read: async (buffer, offset, length) => {
        this.readBuffers.set(path, buffer);
        await this.hook?.("read", path);
        const bytes = data();
        const count = Math.max(0, Math.min(length, this.chunkSize, bytes.length - cursor,
          path.startsWith("/apex/runtime/") ? this.eofAt - cursor : Infinity));
        bytes.copy(buffer, offset, cursor, cursor + count); cursor += count; return count;
      }, close: async () => { await this.hook?.("close", path); this.closed.push(fd); this.paths.delete(fd); } };
  }
  async opendir(path: string): Promise<DirectoryHandle> {
    path = this.canonical(path); await this.hook?.("opendir", path);
    const names = this.directoryNames ?? Object.keys(this.files); let index = 0;
    return { read: async () => { await this.hook?.("dirread", path); return names[index++] ?? null; },
      close: async () => { await this.hook?.("dirclose", path); this.directoryClosed++; } };
  }
}
