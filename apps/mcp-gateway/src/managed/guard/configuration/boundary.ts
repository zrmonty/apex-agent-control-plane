import { types } from "node:util";
import { record } from "../../call-preparation/boundary.js";
export const refused = () => new Error("guard configuration refused safely");
export function requireValue(value: unknown): asserts value { if (!value) throw refused(); }
export function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const result = record(value, keys); requireValue(Object.keys(result).length === keys.length); return result;
}
const prototype = Object.getPrototypeOf(Uint8Array.prototype);
const lengthOf = Object.getOwnPropertyDescriptor(prototype, "byteLength")!.get!;
const bufferOf = Object.getOwnPropertyDescriptor(prototype, "buffer")!.get!;
export function capture(value: Uint8Array): Buffer {
  requireValue(!types.isProxy(value) && types.isUint8Array(value));
  const length: number = lengthOf.call(value);
  requireValue(length > 0 && length <= 262144 && !types.isSharedArrayBuffer(bufferOf.call(value)));
  const copy = Buffer.alloc(length); Uint8Array.prototype.set.call(copy, value); return copy;
}
export function uuid(value: unknown): string {
  requireValue(typeof value === "string" && value.length === 36 &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)); return value;
}
export function hash(value: unknown): string {
  requireValue(typeof value === "string" && value.length === 64 && /^[a-f0-9]{64}$/.test(value)); return value;
}
export const MAX_TIME = 9223372036854775807n;
export function timestamp(value: unknown): bigint {
  requireValue(typeof value === "string" && value.length <= 19 && /^[1-9][0-9]*$/.test(value));
  const result = BigInt(value); requireValue(result <= MAX_TIME); return result;
}
export function integer(value: unknown, min: number, max: number): number {
  requireValue(typeof value === "number" && Number.isInteger(value) && value >= min && value <= max); return value;
}
