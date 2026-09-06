import type { OwnedHttpClient } from "../guard/http-owner.js";
import { OwnedMcpWire, type WireContext, type WireExchange } from "./client.js";
import { InitializeResultSchema, ListToolsResultSchema, LATEST_PROTOCOL_VERSION, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { isDeepStrictEqual, types } from "node:util";
export type ExpectedUpstreamTool = Readonly<{ name: string; inputSchema: unknown; outputSchema?: unknown }>;
const refused = () => new Error("managed MCP session refused safely");
export class OwnedMcpSession {
  private readonly wire: OwnedMcpWire;
  private readonly expected = new Map<string, ExpectedUpstreamTool>();
  private readonly active = new Set<WireExchange>();
  private phase: "new" | "initializing" | "initialized" | "discovering" | "ready" | "terminating" | "closed" = "new";
  private sessionId?: string;
  private protocolVersion?: string;
  private counter = 0n;
  private initializing?: Promise<void>;
  private discovering?: Promise<readonly Tool[]>;
  private closing?: Promise<void>;
  private terminating?: Promise<void>;
  private lastTime?: bigint;

  constructor(private readonly http: OwnedHttpClient, expected: readonly ExpectedUpstreamTool[],
    private readonly now: () => bigint = process.hrtime.bigint) {
    try {
      assertDataTree(expected, true);
      if (!Array.isArray(expected) || !expected.length || expected.length > 512 || typeof now !== "function") throw refused();
      for (const tool of expected) {
        if (typeof tool.name !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(tool.name) || this.expected.has(tool.name) ||
          !tool.inputSchema || typeof tool.inputSchema !== "object" || Array.isArray(tool.inputSchema) ||
          Object.keys(tool).some(key => !["name", "inputSchema", "outputSchema"].includes(key))) throw refused();
        this.expected.set(tool.name, freeze(JSON.parse(JSON.stringify(tool))));
      }
      this.wire = new OwnedMcpWire(http, now);
    } catch { throw refused(); }
  }

  initialize(context: WireContext): Promise<void> {
    if (this.phase === "closed") return Promise.reject(refused());
    if (this.initializing) return this.initializing;
    this.phase = "initializing";
    this.initializing = (async () => {
      try {
        const timing = this.timing(context);
        const exchange = this.wire.startRpc({ id: this.rootId(), method: "initialize", params: {
          protocolVersion: LATEST_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "apex-managed-gateway", version: "1" },
        } }, timing);
        const result = InitializeResultSchema.parse(await exchange.result), metadata = exchange.metadata();
        await exchange.closed; this.check(timing);
        if (!["2025-11-25", "2025-06-18", "2025-03-26"].includes(result.protocolVersion) || !result.capabilities.tools) throw refused();
        this.sessionId = metadata.sessionId; this.protocolVersion = result.protocolVersion;
        const notification = this.http.start({ ...timing, method: "POST", sessionId: this.sessionId, protocolVersion: this.protocolVersion,
          body: Buffer.from('{"jsonrpc":"2.0","method":"notifications/initialized"}') });
        try {
          const response = await notification.result;
          this.session(response.sessionId);
          if (![202, 204].includes(response.status)) throw refused();
          for await (const bytes of response.body) if (bytes.length) throw refused();
        } finally { notification.cancel(); await notification.closed; }
        this.check(timing); this.phase = "initialized";
      } catch { void this.close(); throw refused(); }
    })();
    return this.initializing;
  }

  discover(context: WireContext): Promise<readonly Tool[]> {
    if (this.discovering) return this.discovering;
    if (!["initialized", "ready"].includes(this.phase) || this.active.size) return Promise.reject(refused());
    this.phase = "discovering";
    this.discovering = (async () => {
      try {
        const timing = this.timing(context), tools: Tool[] = [], names = new Set<string>(), cursors = new Set<string>();
        let cursor: string | undefined;
        for (let page = 0; page < 8; page++) {
          const exchange = this.wire.startRpc({ id: this.rootId(), method: "tools/list", params: cursor ? { cursor } : undefined,
            sessionId: this.sessionId, protocolVersion: this.protocolVersion }, timing);
          const result = ListToolsResultSchema.parse(await exchange.result); this.session(exchange.metadata().sessionId);
          await exchange.closed; this.check(timing);
          if (tools.length + result.tools.length > 512) throw refused();
          for (const tool of result.tools) {
            if (names.has(tool.name)) throw refused(); names.add(tool.name); tools.push(tool);
          }
          cursor = result.nextCursor;
          if (cursor === undefined) break;
          if (!/^[\x21-\x7e]{1,256}$/.test(cursor) || cursors.has(cursor) || page === 7) throw refused(); cursors.add(cursor);
        }
        for (const expected of this.expected.values()) {
          const actual = tools.find(tool => tool.name === expected.name);
          if (!actual || !isDeepStrictEqual(actual.inputSchema, expected.inputSchema) ||
            !isDeepStrictEqual(actual.outputSchema, expected.outputSchema)) throw refused();
        }
        this.check(timing); this.phase = "ready"; return freeze(tools);
      } catch { void this.close(); throw refused(); }
      finally { this.discovering = undefined; }
    })();
    return this.discovering;
  }

  call(id: string, tool: string, input: Record<string, unknown>, context: WireContext): WireExchange {
    try {
      if (this.phase !== "ready" || !this.expected.has(tool) ||
        typeof id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) throw refused();
      const timing = this.timing(context);
      const exchange = this.wire.startRpc({ id, method: "tools/call", params: { name: tool, arguments: input },
        sessionId: this.sessionId, protocolVersion: this.protocolVersion }, timing);
      this.active.add(exchange); void exchange.closed.then(() => this.active.delete(exchange), () => {});
      const result = exchange.result.then(value => {
        this.session(exchange.metadata().sessionId); this.check(timing); return value;
      }).catch(() => { throw refused(); });
      return Object.freeze({ ...exchange, result });
    } catch { throw refused(); }
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.phase = "closed"; this.closing = this.wire.close(); return this.closing;
  }
  terminate(context: WireContext): Promise<void> {
    if (this.terminating) return this.terminating;
    if (!["initialized", "ready"].includes(this.phase) || this.active.size) return Promise.reject(refused());
    this.phase = "terminating";
    this.terminating = (async () => {
      try {
        const timing = this.timing(context);
        if (this.sessionId === undefined) return;
        const exchange = this.http.start({ ...timing, method: "DELETE", sessionId: this.sessionId, protocolVersion: this.protocolVersion });
        try {
          const response = await exchange.result; this.session(response.sessionId);
          if (![200, 202, 204].includes(response.status)) throw refused();
          for await (const bytes of response.body) if (bytes.length) throw refused();
          this.check(timing);
        } finally { exchange.cancel(); await exchange.closed; }
        this.check(timing);
      } catch { throw refused(); }
      finally { await this.close(); }
    })();
    return this.terminating;
  }
  private session(value: string | undefined): void {
    if (value !== undefined && value !== this.sessionId) { void this.close(); throw refused(); }
  }
  private rootId(): string {
    if (++this.counter > 18_446_744_073_709_551_615n) throw refused(); return `root:${this.counter}`;
  }
  private timing(context: WireContext): WireContext {
    const start = context.startedAtMonotonicNs, deadline = context.deadlineMonotonicNs, gate = context.beforeWrite;
    if (typeof gate !== "function") throw refused();
    const timing = Object.freeze({ startedAtMonotonicNs: start, deadlineMonotonicNs: deadline, beforeWrite: () => {
      this.check(timing); const result = gate();
      if (result !== undefined) {
        // Contain the native Promise before a post-gate stop/clock check can
        // discard it. Never await or accept an async gate as authorization.
        if (types.isPromise(result)) void Promise.prototype.then.call(result, undefined, () => {});
        throw refused();
      }
      this.check(timing);
    } });
    this.check(timing); return timing;
  }
  private check(context: WireContext): void {
    let now: bigint;
    try {
      now = this.now();
      if (typeof now !== "bigint" || now < 0n || (this.lastTime !== undefined && now < this.lastTime)) throw refused();
      this.lastTime = now;
    } catch { void this.close(); throw refused(); }
    if (this.phase === "closed" || typeof context.startedAtMonotonicNs !== "bigint" || context.startedAtMonotonicNs < 0n || context.startedAtMonotonicNs > now ||
      typeof context.deadlineMonotonicNs !== "bigint" || now >= context.deadlineMonotonicNs) throw refused();
  }
}

function freeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child); Object.freeze(value);
  }
  return value;
}
