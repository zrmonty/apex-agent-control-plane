import type { OwnedHttpClient, OwnedHttpRequest } from "../guard/http-owner.js";
import { readMcpReply, type McpRequestMethod } from "./reply.js";
import { CallToolRequestSchema, InitializeRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { assertDataTree } from "../runtime-config/boundary.js";
export type WireContext = Pick<OwnedHttpRequest, "startedAtMonotonicNs" | "deadlineMonotonicNs" | "beforeWrite">;
export type WireRpc = Readonly<{ id: string; method: McpRequestMethod; params?: Record<string, unknown>;
  sessionId?: string; protocolVersion?: string }>;
export type WireExchange = Readonly<{ result: Promise<unknown>; closed: Promise<void>; cancel(): void;
  metadata(): Readonly<{ sessionId?: string }> }>;
const refused = () => new Error("managed MCP exchange refused safely");

/** Explicit RPC-ID ownership, no implicit session initialization or replay.
 * The later managed call owner supplies actual grant/admission authorization. */
export class OwnedMcpWire {
  private stopped = false;
  private readonly activeIds = new Set<string>();
  private closing?: Promise<void>;
  private lastTime?: bigint;
  constructor(private readonly http: Pick<OwnedHttpClient, "start" | "close">,
    private readonly now: () => bigint = process.hrtime.bigint) {
    if (typeof now !== "function") throw refused();
  }
  startRpc(request: WireRpc, context: WireContext): WireExchange {
    try {
      if (this.stopped) throw refused();
      assertDataTree(request, true);
      if (Object.keys(request).some(key => !["id", "method", "params", "sessionId", "protocolVersion"].includes(key)) ||
        typeof request.id !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(request.id) ||
        (request.protocolVersion !== undefined && !["2025-11-25", "2025-06-18", "2025-03-26"].includes(request.protocolVersion))) throw refused();
      if (request.params !== undefined) assertDataTree(request.params, false);
      const id = request.id, method = request.method;
      const payload = { jsonrpc: "2.0", id, method, params: request.params };
      const schema = method === "tools/call" ? CallToolRequestSchema : method === "tools/list" ? ListToolsRequestSchema
        : method === "initialize" ? InitializeRequestSchema : undefined;
      if (!schema) throw refused(); schema.parse(payload);
      const body = Buffer.from(JSON.stringify(payload)); if (body.length > 262_144) throw refused();
      const started = context.startedAtMonotonicNs, deadline = context.deadlineMonotonicNs;
      if (typeof deadline !== "bigint" || this.sample() >= deadline) throw refused();
      if (this.activeIds.has(id) || this.activeIds.size >= 128) throw refused();
      this.activeIds.add(id);
      let exchange;
      try {
        exchange = this.http.start({ method: "POST", body, sessionId: request.sessionId, protocolVersion: request.protocolVersion,
          startedAtMonotonicNs: started, deadlineMonotonicNs: deadline, beforeWrite: context.beforeWrite });
      } catch { this.activeIds.delete(id); throw refused(); }
      // Same ID remains occupied after logical cancellation until the exact
      // underlying physical group closes. No hidden retry or replacement ID.
      void exchange.closed.then(() => this.activeIds.delete(id), () => {});
      let cancelled = false;
      let metadata: Readonly<{ sessionId?: string }> | undefined;
      const cancel = () => { cancelled = true; exchange.cancel(); };
      const result = (async () => {
        try {
          const response = await exchange.result;
          const value = await readMcpReply(response, id, method);
          // Charge parsing/schema-validation time even after the native body has
          // completed and its reporting timer can no longer fire.
          if (cancelled || this.stopped || this.sample() >= deadline) throw refused();
          metadata = Object.freeze({ sessionId: response.sessionId });
          return value;
        } catch { throw refused(); } finally { exchange.cancel(); }
      })();
      return Object.freeze({ result, closed: exchange.closed, cancel, metadata: () => {
        if (!metadata || cancelled || this.stopped) throw refused(); return metadata;
      } });
    } catch { throw refused(); }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stopped = true; this.closing = this.http.close(); return this.closing;
  }
  private sample(): bigint {
    try {
      const value = this.now();
      if (typeof value !== "bigint" || value < 0n || (this.lastTime !== undefined && value < this.lastTime)) throw refused();
      this.lastTime = value; return value;
    } catch { void this.close(); throw refused(); }
  }
}
