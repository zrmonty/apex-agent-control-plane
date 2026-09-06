const refused = () => new Error("managed MCP reply refused safely");

/** Original bounded UTF8 JSON, before duplicate object keys can be collapsed. */
export function parseWireJson(bytes: Uint8Array): unknown {
  try {
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 1_048_576) throw refused();
    const input = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    let position = 0, nodes = 0;
    const space = () => { while (position < input.length && " \t\r\n".includes(input[position])) position++; };
    const consume = (value: string) => { space(); if (input[position++] !== value) throw refused(); };
    const string = (): string => {
      if (input[position] !== '"') throw refused();
      const start = position++;
      while (position < input.length) {
        const character = input[position++];
        if (character === '"') {
          const value: unknown = JSON.parse(input.slice(start, position));
          if (typeof value !== "string" || Buffer.from(value).toString("utf8") !== value) throw refused();
          return value;
        }
        if (character === "\\") position++;
      }
      throw refused();
    };
    function value(depth: number): void {
      if (depth > 32 || ++nodes > 16_384) throw refused();
      space();
      if (input[position] === '"') { string(); return; }
      if (input[position] === "{" || input[position] === "[") {
        const object = input[position++] === "{", end = object ? "}" : "]", keys = new Set<string>();
        space(); if (input[position] === end) { position++; return; }
        while (position < input.length) {
          if (object) {
            space(); const key = string(); if (keys.has(key)) throw refused(); keys.add(key); consume(":");
          }
          value(depth + 1); space();
          if (input[position] === end) { position++; return; }
          consume(",");
        }
        throw refused();
      }
      const start = position;
      while (position < input.length && !' \t\r\n{}[]:,"'.includes(input[position])) position++;
      if (position === start) throw refused();
      const parsed: unknown = JSON.parse(input.slice(start, position));
      if (parsed !== null && typeof parsed !== "boolean" && (typeof parsed !== "number" || !Number.isFinite(parsed))) throw refused();
    }
    value(0); space(); if (position !== input.length) throw refused();
    return JSON.parse(input);
  } catch { throw refused(); }
}
