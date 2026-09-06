import { refused } from "./keys.js";

/** JSON.parse's numeric result alone can round a noninteger into a valid second.
 * Inspect the original top-level NumericDate lexemes (Node24 reviver context).
 * Unrelated/nested claims retain the ordinary bounded JSON policy. */
export function exactNumericDates(bytes: Buffer): void {
  const lexemes = new WeakMap<object, Map<string, string>>();
  const parse = JSON.parse as (text: string, reviver: (this: object, key: string, value: unknown,
    context?: { source?: string }) => unknown) => Record<string, unknown>;
  const root = parse(bytes.toString("utf8"), function (key, value, context) {
    if (["exp", "nbf", "iat"].includes(key) && typeof value === "number") {
      if (!context?.source) throw refused();
      let fields = lexemes.get(this); if (!fields) { fields = new Map(); lexemes.set(this, fields); }
      fields.set(key, context.source);
    }
    return value;
  });
  for (const [field, source] of lexemes.get(root) ?? []) {
    const value = root[field];
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 253402300799) throw refused();
    const match = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(source);
    if (!match) throw refused();
    const digits = BigInt(match[2] + (match[3] ?? ""));
    if (digits === 0n) continue;
    const scale = (match[3]?.length ?? 0) - Number(match[4] ?? 0);
    // Original payload <=6144 bytes. Larger exponents cannot encode a nonzero
    // allowed NumericDate; bound the exponent BEFORE allocating a BigInt power.
    if (!Number.isSafeInteger(scale) || Math.abs(scale) > 6144 || match[1]) throw refused();
    const integer = BigInt(value);
    if (scale >= 0 ? digits !== integer * 10n ** BigInt(scale) : digits * 10n ** BigInt(-scale) !== integer) throw refused();
  }
}
