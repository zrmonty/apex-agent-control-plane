// Scan containers before JSON.parse can collapse keys. Only keys are decoded
// during this pass; JSON.parse validates the complete JSON grammar afterward.
// The caller bounds text bytes, and this pass bounds depth and aggregate entries.
export function parseUniqueJson(input, { maxDepth, maxFields }) {
  let position = 0;
  let fields = 0;
  function invalid() {
    throw new SyntaxError("Invalid JSON at position " + position);
  }
  function whitespace() {
    while (position < input.length && " \t\r\n".includes(input[position])) position++;
  }
  function consume(character) {
    whitespace();
    if (input[position] !== character) invalid();
    position++;
  }
  function stringToken() {
    if (input[position] !== '"') invalid();
    const start = position++;
    while (position < input.length) {
      const character = input[position++];
      if (character === '"') return input.slice(start, position);
      // Skip escaped quotes/backslashes without interpreting the escape here.
      if (character === "\\") position++;
    }
    invalid();
  }
  function container(depth, object) {
    const close = object ? "}" : "]";
    const keys = object ? new Set() : undefined;
    position++;
    whitespace();
    if (input[position] === close) {
      position++;
      return;
    }
    while (true) {
      if (++fields > maxFields) throw new Error("JSON field count limit exceeded");
      if (keys) {
        whitespace();
        // Decode escapes so e.g. "key" and "\u006bey" share an identity.
        const key = JSON.parse(stringToken());
        if (keys.has(key)) throw new Error("duplicate JSON field: " + key);
        keys.add(key);
        consume(":");
      }
      value(depth + 1);
      whitespace();
      if (input[position] === close) {
        position++;
        return;
      }
      consume(",");
    }
  }
  function value(depth) {
    if (depth > maxDepth) throw new Error("JSON depth limit exceeded");
    whitespace();
    switch (input[position]) {
      case "{":
        container(depth, true);
        return;
      case "[":
        container(depth, false);
        return;
      case '"':
        stringToken();
        return;
      default: {
        // Leave number/literal validation to JSON.parse; consume one token.
        const start = position;
        while (position < input.length && !' \t\r\n{}[]:,"'.includes(input[position])) position++;
        if (position === start) invalid();
      }
    }
  }
  value(0);
  whitespace();
  if (position !== input.length) invalid();
  return JSON.parse(input);
}
