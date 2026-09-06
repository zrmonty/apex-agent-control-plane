import type { OwnedHttpResponse } from "../guard/http-owner.js";
import { CallToolResultSchema, InitializeResultSchema, ListToolsResultSchema,
  ProgressNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { parseWireJson } from "./json.js";
import { McpSseDecoder } from "./sse.js";

const refused = () => new Error("managed MCP reply refused safely");
export type McpRequestMethod = "initialize" | "tools/list" | "tools/call";

export async function readMcpReply(response: OwnedHttpResponse, id: string,
  method: McpRequestMethod): Promise<unknown> {
  try {
    if (typeof id !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(id) || response.status !== 200) throw refused();
    const mime = /^(application\/json|text\/event-stream)(?:;\s*charset=utf-8)?$/i.exec(response.contentType);
    if (!mime) throw refused();
    const isSse = mime[1].toLowerCase() === "text/event-stream";
    const decoder = isSse ? new McpSseDecoder() : undefined;
    const chunks: Uint8Array[] = []; let bytes = 0, messages = 0;
    const inspect = (raw: unknown): { result: unknown } | undefined => {
      if (++messages > 128 || !raw || typeof raw !== "object" || Array.isArray(raw)) throw refused();
      const value = raw as Record<string, unknown>;
      if (value.jsonrpc !== "2.0") throw refused();
      if ("method" in value) {
        if (!isSse || Object.keys(value).some(key => !["jsonrpc", "method", "params"].includes(key)) ||
          value.method !== "notifications/progress") throw refused();
        const progress = ProgressNotificationSchema.parse(value);
        if (progress.params.progressToken !== id || !Number.isFinite(progress.params.progress) || progress.params.progress < 0 ||
          (progress.params.total !== undefined && (!Number.isFinite(progress.params.total) || progress.params.total < progress.params.progress)) ||
          (progress.params.message !== undefined && progress.params.message.length > 256)) throw refused();
        return undefined; // No timeout reset, external side effect or remote log.
      }
      if (value.id !== id || !Object.hasOwn(value, "result") ||
        Object.keys(value).some(key => !["jsonrpc", "id", "result"].includes(key))) throw refused();
      const schema = method === "initialize" ? InitializeResultSchema : method === "tools/list" ? ListToolsResultSchema
        : method === "tools/call" ? CallToolResultSchema : undefined;
      if (!schema) throw refused();
      return { result: schema.parse(value.result) };
    };
    const inspectAll = (values: unknown[]): { result: unknown } | undefined => {
      let selected: { result: unknown } | undefined;
      for (const value of values) {
        if (selected) throw refused();
        selected = inspect(value);
      }
      return selected;
    };
    for await (const chunk of response.body) {
      if (!(chunk instanceof Uint8Array) || (bytes += chunk.length) > 1_048_576) throw refused();
      if (decoder) {
        const result = inspectAll(decoder.push(chunk));
        if (result) return result.result;
      } else chunks.push(Buffer.from(chunk));
    }
    const result = decoder ? inspectAll(decoder.finish()) : inspect(parseWireJson(Buffer.concat(chunks, bytes)));
    if (!result) throw refused();
    return result.result;
  } catch { throw refused(); }
}
