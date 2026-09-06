import { directory, health, mountId, readOnlyMount, regular, sha256, TOTAL, unchanged } from "./validation.js";
import { rejected, type FileHandle, type FileSystem, type Metadata } from "./types.js";
export interface ReadOwner {
  readonly fs: FileSystem;
  guard(): void;
  io<T>(operation: () => Promise<T>, adopt?: (value: T) => void): Promise<T>;
  resource(value: { close(): Promise<void> }): void;
  allocate(size: number): Buffer;
  wipe(buffer: Buffer): void;
}
type HeldDirectory = { file: FileHandle; path: string; before: Metadata };
export async function readStage(owner: ReadOwner, names: Map<string, number>, hash: string) {
  const fs = owner.fs, f = fs.flags;
  if (fs.platform !== "linux" || f.readOnly !== 0 ||
    [f.directory, f.noFollow, f.nonblock].some(value => !Number.isSafeInteger(value) || value <= 0)) throw rejected();
  const fileFlags = f.readOnly | f.noFollow | f.nonblock;
  const dirs: HeldDirectory[] = [];
  for (const name of ["/", "apex", "runtime"]) {
    const path = name === "/" ? "/" : `/proc/self/fd/${dirs.at(-1)!.file.fd}/${name}`;
    const before = await owner.io(() => fs.lstat(path)); directory(before, name === "runtime");
    const file = await owner.io(() => fs.open(path, fileFlags | f.directory), value => owner.resource(value));
    const opened = await owner.io(() => file.stat()); unchanged(before, opened);
    dirs.push({ file, path, before });
  }
  const stage = dirs[2].file;
  const stageMount = await getMount(stage);
  await verifyMount();
  const entries = await owner.io(() => fs.opendir(`/proc/self/fd/${stage.fd}`), value => owner.resource(value));
  const seen = new Set<string>();
  for (let index = 0; ; index++) {
    const name = await owner.io(() => entries.read());
    if (name === null) break;
    if (index >= 50 || name.length > 69 || !names.has(name) || seen.has(name)) throw rejected();
    seen.add(name);
  }
  if (seen.size !== names.size) throw rejected();
  const files: Record<string, Buffer> = Object.create(null), hashes: Record<string, string> = Object.create(null);
  let total = 0;
  const heldFiles: HeldDirectory[] = [];
  for (const name of [...names.keys()].sort()) {
    const path = `/proc/self/fd/${stage.fd}/${name}`, cap = names.get(name)!;
    const before = await owner.io(() => fs.lstat(path)); regular(before, cap);
    total += Number(before.size);
    if (total > TOTAL) throw rejected();
    const file = await owner.io(() => fs.open(path, fileFlags), value => owner.resource(value));
    const opened = await owner.io(() => file.stat()); regular(opened, cap); unchanged(before, opened);
    if (await getMount(file) !== stageMount) throw rejected();
    const bytes = await readBytes(file, Number(opened.size));
    if (BigInt(bytes.length) !== opened.size || name === "instance-proof" && bytes.length !== 32) throw rejected();
    if (name === "health-token") health(bytes);
    unchanged(opened, await owner.io(() => file.stat()));
    unchanged(opened, await owner.io(() => fs.lstat(path)));
    heldFiles.push({ file, path, before });
    files[name] = bytes; hashes[name] = sha256(bytes); owner.guard();
  }
  if (sha256(JSON.stringify(hashes)) !== hash) throw rejected();
  // Recheck the whole held set after the final read, not each file in isolation.
  for (const held of [...heldFiles, ...dirs].reverse()) {
    unchanged(held.before, await owner.io(() => held.file.stat()));
    unchanged(held.before, await owner.io(() => fs.lstat(held.path)));
  }
  await verifyMount(); owner.guard();
  return Object.freeze(files);

  async function readBytes(file: FileHandle, cap: number): Promise<Buffer> {
    const bytes = owner.allocate(cap + 1); let size = 0;
    while (size <= cap) {
      const count = await owner.io(() => file.read(bytes, size, bytes.length - size));
      if (!Number.isSafeInteger(count) || count < 0 || count > bytes.length - size) throw rejected();
      if (count === 0) return bytes.subarray(0, size);
      size += count;
    }
    throw rejected();
  }
  async function proc(path: string, cap: number): Promise<Buffer> {
    const file = await owner.io(() => fs.open(path, fileFlags), value => owner.resource(value));
    return readBytes(file, cap);
  }
  async function getMount(file: FileHandle): Promise<string> {
    const bytes = await proc(`/proc/self/fdinfo/${file.fd}`, 4096);
    try { return mountId(bytes); } finally { owner.wipe(bytes); }
  }
  async function verifyMount(): Promise<void> {
    const bytes = await proc("/proc/self/mountinfo", 1048576);
    try { readOnlyMount(bytes, stageMount); } finally { owner.wipe(bytes); }
  }
}
