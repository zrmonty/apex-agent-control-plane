import { types } from "node:util";
import { businessIdentifier } from "../authority/business-codec.js";

export const refused = () => new Error("managed call preparation refused safely");
/** Reject active containers before prototype/descriptor access; never call coercions. */
export function record(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || types.isProxy(value) || Array.isArray(value)) throw refused();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw refused();
  const keys = Reflect.ownKeys(value);
  if (keys.length > allowed.length) throw refused();
  for (const key of keys) {
    if (typeof key !== "string" || !allowed.includes(key)) throw refused();
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in descriptor) || !descriptor.enumerable) throw refused();
  }
  return value as Record<string, unknown>;
}
export function identifier(value: unknown): string {
  const text = businessIdentifier(value);
  // Reject terminal line breaks as well as any character outside the exact grammar.
  if (/[^A-Za-z0-9_.:-]/.test(text)) throw refused();
  return text;
}
/** Called only after the bounded passive tree check; never traverses caller hooks. */
export function frozenTree(value: unknown): void {
  if (value !== null && typeof value === "object") {
    if (!Object.isFrozen(value)) throw refused();
    for (const child of Object.values(value)) frozenTree(child);
  }
}
