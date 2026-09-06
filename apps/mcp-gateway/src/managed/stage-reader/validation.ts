import { createHash } from "node:crypto";
import { types } from "node:util";
import { rejected, type ManagedStageLoadOptions, type Metadata } from "./types.js";

export const ROOT = "/apex/runtime";
export const TOTAL = 4 * 1024 * 1024;
export const ROLES = Object.freeze(["health-token", "governance-ca", "governance-cert", "governance-key",
  "governance-token", "evidence-ca", "evidence-cert", "evidence-key", "evidence-token", "inbound-jwks",
  "workload-ca", "workload-cert", "workload-key"]);
export const sha256 = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");
export function data(value: unknown, key: string, optional = false): unknown {
  if (!value || typeof value !== "object" || types.isProxy(value)) throw rejected();
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor && optional) return undefined;
  if (!descriptor || !("value" in descriptor)) throw rejected();
  return descriptor.value;
}
export function options(value: ManagedStageLoadOptions) {
  const hash = data(value, "expectedManifestSha256"), refs = data(value, "toolSecretReferences");
  const fatal = data(value, "onFatal"), clock = data(value, "monotonicNowNs", true);
  if (typeof hash !== "string" || !/^[a-f0-9]{64}$/.test(hash) || typeof fatal !== "function" ||
    clock !== undefined && typeof clock !== "function" || !Array.isArray(refs) || types.isProxy(refs)) throw rejected();
  const count = data(refs, "length");
  if (typeof count !== "number" || !Number.isInteger(count) || count > 32) throw rejected();
  const names = new Map<string, number>([
    ["runtime-revision.json", 262144], ["launch-context.json", 16384],
    ["authority-profile.json", 262144], ["tool-bindings.json", 262144], ["instance-proof", 32],
    ...ROLES.map(name => [name, name === "health-token" ? 43 : 65536] as [string, number]),
  ]);
  for (let i = 0; i < count; i++) {
    const ref = data(refs, String(i));
    if (typeof ref !== "string" || ref.length > 256 || !ref.startsWith("secret://") ||
      !/^[A-Za-z0-9]/.test(ref.slice(9)) || ref.slice(9).split("/").some(part =>
        !/^[A-Za-z0-9_.:-]{1,256}$/.test(part) || part === "." || part.includes(".."))) throw rejected();
    const name = `tool-${sha256(ref)}`;
    if (names.has(name)) throw rejected();
    names.set(name, 65536);
  }
  return { hash, names, fatal: () => { fatal.call(value); },
    clock: clock === undefined ? undefined : () => clock.call(value) as bigint };
}
const fields = ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"] as const;
export function unchanged(a: Metadata, b: Metadata): void {
  if (fields.some(key => typeof a[key] !== "bigint" || a[key] !== b[key])) throw rejected();
}
export function directory(info: Metadata, stage: boolean): void {
  if ((info.mode & 0o170000n) !== 0o40000n || (stage ?
    info.mode !== 0o40500n || info.uid !== 10001n || info.gid !== 10001n :
    info.uid !== 0n || info.gid !== 0n || (info.mode & 0o22n) !== 0n)) throw rejected();
}
export function regular(info: Metadata, cap: number): void {
  if (info.mode !== 0o100400n || info.uid !== 10001n || info.gid !== 10001n ||
    info.nlink !== 1n || info.size < 1n || info.size > BigInt(cap)) throw rejected();
}
export function health(bytes: Buffer): void {
  if (bytes.length !== 43) throw rejected();
  for (const byte of bytes) if (!(byte >= 65 && byte <= 90 || byte >= 97 && byte <= 122 ||
    byte >= 48 && byte <= 57 || byte === 45 || byte === 95)) throw rejected();
  if (!Buffer.from("AEIMQUYcgkosw048", "ascii").includes(bytes[42])) throw rejected();
}
export function mountId(bytes: Buffer): string {
  const rows = bytes.toString("ascii").split("\n").filter(row => row.startsWith("mnt_id:"));
  if (rows.length !== 1) throw rejected();
  const match = /^mnt_id:\s+([1-9][0-9]{0,19})$/.exec(rows[0]);
  if (!match) throw rejected();
  return match[1];
}
function mountPath(value: string): string {
  if (value.length > 16384 || /\\(?!040|011|012|134)/.test(value)) throw rejected();
  return value.replace(/\\(040|011|012|134)/g, (_, octal: string) => String.fromCharCode(parseInt(octal, 8)));
}
export function readOnlyMount(bytes: Buffer, id: string): void {
  const rows = bytes.toString("utf8").split("\n");
  if (rows.length > 8192 || rows.pop() !== "") throw rejected();
  let matched = false;
  for (const row of rows) {
    if (row.length > 32768) throw rejected();
    const parts = row.split(" "), separator = parts.indexOf("-");
    if (parts.length < 10 || separator < 6 || separator !== parts.length - 4 ||
      !/^[1-9][0-9]{0,19}$/.test(parts[0])) throw rejected();
    const point = mountPath(parts[4]);
    if (point.startsWith(`${ROOT}/`)) throw rejected();
    if (parts[0] === id) {
      if (matched || point !== ROOT || !parts[5].split(",").includes("ro") || parts[5].split(",").includes("rw")) throw rejected();
      matched = true;
    } else if (point === ROOT) throw rejected();
  }
  if (!matched) throw rejected();
}
