import { requireValue } from "./boundary.js";

/** Metadata only: no reference resolution, profile lookup or executable schema
 * enforcement. Scan before JSON.parse can collapse duplicate keys. These schema
 * strings are retained verbatim by the generated message and manifest digest.
 */
export function schemaJson(input: string): void {
  requireValue(input.length > 0 && Buffer.byteLength(input) <= 32768);
  let position = 0;
  let nodes = 0;
  function space(): void {
    while (position < input.length && " \t\r\n".includes(input[position])) position++;
  }
  function consume(character: string): void {
    space();
    requireValue(input[position++] === character);
  }
  function string(): string {
    requireValue(input[position] === '"');
    const start = position++;
    while (position < input.length) {
      const character = input[position++];
      if (character === '"') {
        const decoded: unknown = JSON.parse(input.slice(start, position));
        requireValue(typeof decoded === "string" && Buffer.from(decoded).toString("utf8") === decoded);
        return decoded;
      }
      if (character === "\\") position++;
    }
    requireValue(false);
  }
  function container(depth: number, object: boolean): void {
    const close = object ? "}" : "]";
    const keys = new Set<string>();
    position++;
    space();
    if (input[position] === close) { position++; return; }
    while (position < input.length) {
      if (object) {
        space();
        const key = string();
        requireValue(!keys.has(key) && !["$ref", "$dynamicRef", "$recursiveRef", "$id"].includes(key));
        keys.add(key);
        consume(":");
      }
      value(depth + 1);
      space();
      if (input[position] === close) { position++; return; }
      consume(",");
    }
    requireValue(false);
  }
  function value(depth: number): void {
    requireValue(depth <= 32 && ++nodes <= 2048);
    space();
    if (input[position] === "{") return container(depth, true);
    if (input[position] === "[") return container(depth, false);
    if (input[position] === '"') { string(); return; }
    const start = position;
    while (position < input.length && !' \t\r\n{}[]:,"'.includes(input[position])) position++;
    requireValue(position > start);
    const parsed: unknown = JSON.parse(input.slice(start, position));
    requireValue(parsed === null || typeof parsed === "boolean" || (typeof parsed === "number" && Number.isFinite(parsed)));
  }
  value(0);
  space();
  requireValue(position === input.length);
  const root: unknown = JSON.parse(input);
  requireValue(root !== null && typeof root === "object" && !Array.isArray(root));
  requireValue((root as Record<string, unknown>).type === "object");
}
