import { parseWireJson } from "./json.js";

const refused = () => new Error("managed MCP reply refused safely");

/** Incremental bounded SSE. Cursors/retry values are metadata, never automatic
 * reconnection or permission to replay an uncertain business request. */
export class McpSseDecoder {
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });
  private bytes = 0;
  private events = 0;
  private line = "";
  private skipLf = false;
  private data: string[] = [];
  private eventName = "";
  private readonly fields = new Set<string>();
  private stopped = false;

  push(chunk: Uint8Array): unknown[] {
    try {
      if (this.stopped || !(chunk instanceof Uint8Array) || this.bytes + chunk.length > 1_048_576) throw refused();
      this.bytes += chunk.length;
      return this.consume(this.decoder.decode(chunk, { stream: true }));
    } catch { this.stopped = true; throw refused(); }
  }
  finish(): unknown[] {
    try {
      if (this.stopped) throw refused(); this.stopped = true;
      const result = this.consume(this.decoder.decode());
      // EOF does not dispatch an event without the required empty-line marker.
      this.line = ""; this.data = []; return result;
    } catch { this.stopped = true; throw refused(); }
  }
  private consume(text: string): unknown[] {
    const messages: unknown[] = [];
    for (const character of text) {
      if (this.skipLf) {
        this.skipLf = false;
        if (character === "\n") continue;
      }
      // CR itself terminates a line. Only suppress a possible following LF;
      // never wait for it or EOF before dispatching a complete open-stream event.
      if (character === "\r") { this.endLine(messages); this.skipLf = true; }
      else if (character === "\n") this.endLine(messages);
      else this.line += character;
    }
    return messages;
  }
  private endLine(messages: unknown[]): void {
    const line = this.line; this.line = "";
    if (!line) {
      if (this.data.length) {
        if (++this.events > 128 || !["", "message"].includes(this.eventName)) throw refused();
        messages.push(parseWireJson(Buffer.from(this.data.join("\n"))));
      }
      this.data = []; this.eventName = ""; this.fields.clear(); return;
    }
    if (line.startsWith(":")) return;
    const colon = line.indexOf(":"), name = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1); if (value.startsWith(" ")) value = value.slice(1);
    if (name === "data") { this.data.push(value); return; }
    if (this.fields.has(name)) throw refused(); this.fields.add(name);
    if (name === "event") { if (value.length > 32) throw refused(); this.eventName = value; }
    else if (name === "id") { if (!/^[\x21-\x7e]{1,256}$/.test(value)) throw refused(); }
    else if (name === "retry") { if (!/^[0-9]{1,6}$/.test(value)) throw refused(); }
    else throw refused();
  }
}
