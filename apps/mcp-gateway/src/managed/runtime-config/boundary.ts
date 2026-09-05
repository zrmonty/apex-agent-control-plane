import { types } from "node:util";
import { ScalarType, type DescMessage } from "@bufbuild/protobuf";
import { GatewayError } from "../../contracts.js";

export function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "managed runtime configuration rejected safely");
}

export function requireValue(condition: unknown): asserts condition {
  if (!condition) throw rejected();
}

/** Inspect descriptors before any read/coercion. In particular, a Proxy can
 * intercept getPrototypeOf/ownKeys, so reject it before either operation.
 * JSON input accepts only plain data; generated messages additionally use bigint
 * and absent optional messages. Neither path invokes a getter or toJSON hook.
 * Charge every occurrence, including keys and syntax, before the codec can
 * stringify an amplified shared graph. Count escaped UTF-8 without allocating
 * the serialized text or a UTF-8 buffer. The codec still checks final ProtoJSON.
 */
export function assertDataTree(input: unknown, generated: boolean): void {
  let nodes = 0;
  let remainingBytes = 262144;
  const active = new Set<object>();
  function charge(bytes: number): void {
    requireValue(bytes <= remainingBytes);
    remainingBytes -= bytes;
  }
  function stringBytes(value: string): void {
    charge(2); // Opening and closing quotes.
    requireValue(value.length <= remainingBytes); // Each UTF-16 unit needs >=1 byte.
    for (let index = 0; index < value.length; index++) {
      const code = value.charCodeAt(index);
      if (code === 34 || code === 92) charge(2); // Quote/backslash escapes.
      else if (code < 32) charge(code === 8 || code === 9 || code === 10 || code === 12 || code === 13 ? 2 : 6);
      else if (code < 128) charge(1);
      else if (code < 2048) charge(2);
      else if (code >= 0xd800 && code <= 0xdbff) {
        const low = value.charCodeAt(++index);
        requireValue(low >= 0xdc00 && low <= 0xdfff);
        charge(4);
      } else {
        requireValue(code < 0xdc00 || code > 0xdfff);
        charge(3);
      }
    }
  }
  function visit(value: unknown, depth: number): void {
    requireValue(++nodes <= 8193 && depth <= 64);
    if (typeof value === "string") return stringBytes(value);
    if (value === null) return charge(4);
    if (typeof value === "boolean") return charge(value ? 4 : 5);
    if (typeof value === "number") {
      requireValue(Number.isFinite(value));
      return charge(`${value}`.length); // Primitive conversion, <=24 bytes; no hooks.
    }
    // Generated uint64 values become quoted decimals. Bound before conversion;
    // absent messages are conservatively charged as null, though omitted later.
    if (generated && value === undefined) return charge(4);
    if (generated && typeof value === "bigint") {
      requireValue(value >= 0n && value <= (1n << 64n) - 1n);
      return charge(`${value}`.length + 2);
    }
    requireValue(typeof value === "object" && !types.isProxy(value));
    requireValue(!active.has(value));
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    requireValue(array ? prototype === Array.prototype : prototype === Object.prototype || prototype === null);
    active.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    requireValue(keys.length <= 8193);
    if (array) requireValue(keys.length === value.length + 1);
    const entries = keys.length - (array ? 1 : 0);
    charge(2 + Math.max(0, entries - 1)); // Braces/brackets and commas.
    for (const key of keys) {
      requireValue(typeof key === "string");
      if (array && key === "length") continue;
      requireValue(!["__proto__", "prototype", "constructor", "toJSON"].includes(key));
      if (array) requireValue(/^(0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length);
      const descriptor = descriptors[key];
      requireValue("value" in descriptor && descriptor.enumerable);
      if (!array) { stringBytes(key); charge(1); } // Key and colon, never array indices.
      visit(descriptor.value, depth + 1);
    }
    active.delete(value);
  }
  visit(input, 0);
}

/** The descriptor, not a handwritten wire model, defines allowed properties and
 * scalar/enum types. Call only after assertDataTree has excluded active objects.
 * This contract has no maps/oneofs/bytes/floats; fail closed on such future shapes.
 */
export function assertMessage(schema: DescMessage, value: unknown): void {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value));
  const message = value as Record<string, unknown>;
  requireValue(message.$typeName === schema.typeName);
  const names = new Set(["$typeName", ...schema.fields.map(field => field.localName)]);
  requireValue(Object.keys(message).every(key => names.has(key)));
  for (const field of schema.fields) {
    requireValue(!field.oneof && field.fieldKind !== "map");
    const entry = message[field.localName];
    if (field.fieldKind === "message" && entry === undefined) continue;
    if (field.fieldKind === "list") requireValue(Array.isArray(entry));
    const entries: unknown[] = field.fieldKind === "list" ? entry as unknown[] : [entry];
    for (const item of entries) {
      if (field.message) assertMessage(field.message, item);
      else if (field.enum) requireValue(typeof item === "number" && field.enum.values.some(v => v.number === item));
      else {
        switch (field.scalar) {
          case ScalarType.STRING: requireValue(typeof item === "string"); break;
          case ScalarType.BOOL: requireValue(typeof item === "boolean"); break;
          case ScalarType.UINT64:
            requireValue(typeof item === "bigint" && item >= 0n && item <= (1n << 64n) - 1n); break;
          case ScalarType.UINT32:
            requireValue(typeof item === "number" && Number.isInteger(item) && item >= 0 && item <= 4294967295); break;
          case ScalarType.INT32:
            requireValue(typeof item === "number" && Number.isInteger(item) && item >= -2147483648 && item <= 2147483647); break;
          default: throw rejected();
        }
      }
    }
  }
}

export function freezeTree<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeTree(child);
    Object.freeze(value);
  }
  return value;
}

export function identifier(value: string, maximum = 128): boolean {
  return value.length <= maximum && /^[a-zA-Z0-9._:-]+$/.test(value) && !value.includes("..");
}

export function hash(value: string): boolean { return /^[0-9a-f]{64}$/.test(value); }

export function textBound(value: string, maximum = 512): void {
  requireValue(value.length > 0 && Buffer.byteLength(value) <= maximum && !/[\p{Cc}]/u.test(value));
}

export function reference(value: string, prefix: string): void {
  requireValue(value.startsWith(prefix) && value.length <= 512);
  const tail = value.slice(prefix.length);
  requireValue(/^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/.test(tail));
  requireValue(tail.split("/").every(part => part !== "" && part !== "." && part !== ".."));
}

export function httpsUrl(value: string): URL {
  textBound(value);
  requireValue(!/[\s\\]/u.test(value));
  const url = new URL(value);
  // Empty '?' and '#' also count as forbidden query/fragment, as in Rust Url.
  requireValue(url.protocol === "https:" && url.hostname && !url.username && !url.password);
  requireValue(!value.includes("?") && !value.includes("#"));
  return url;
}

export function unique<T>(values: readonly T[]): Set<T> {
  const result = new Set(values);
  requireValue(result.size === values.length);
  return result;
}
