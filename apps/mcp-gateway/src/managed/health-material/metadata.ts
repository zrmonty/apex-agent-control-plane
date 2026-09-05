import { rejected } from "./binding.js";
import type { Metadata } from "./types.js";

const fields = ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeNs", "ctimeNs"] as const;
export function regular(value: Metadata, cap: number): void {
  if (!value || fields.some(key => typeof value[key] !== "bigint" || value[key] < 0n) ||
    value.mode !== 0o100400n || value.uid !== 10001n || value.gid !== 10001n || value.nlink !== 1n ||
    value.size < 1n || value.size > BigInt(cap)) throw rejected();
}
export function unchanged(before: Metadata, after: Metadata): void {
  if (fields.some(key => before[key] !== after[key])) throw rejected();
}
export function directory(value: Metadata): void {
  if (!value || typeof value.mode !== "bigint" || (value.mode & 0o170000n) !== 0o40000n) throw rejected();
}
