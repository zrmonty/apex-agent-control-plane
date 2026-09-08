import { isJSONRPCRequest, isJSONRPCResultResponse, isJSONRPCErrorResponse } from "@modelcontextprotocol/sdk/types.js";
import type { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { cancellation } from "./control.js";
import { refused } from "./request.js";

/**
 * SDK 1.30's cancellation handler ignores falsy IDs. Give its protocol layer
 * nonempty, injective IDs while the HTTP transport keeps the exact wire IDs.
 * JSON encoding distinguishes numeric 0 from string "0" without reserving any
 * caller-visible ID. No SDK private state or cancellation handler is replaced.
 */
export function preserveRequestIds(transport: StreamableHTTPServerTransport): void {
  const receive = transport.onmessage, send = transport.send.bind(transport);
  const closeStream = transport.closeSSEStream.bind(transport);
  transport.onmessage = (message, extra) => {
    if (isJSONRPCRequest(message)) {
      receive?.({ ...message, id: JSON.stringify(message.id) }, extra);
      return;
    }
    const cancelled = cancellation(message);
    if (cancelled) {
      receive?.({ ...cancelled, jsonrpc: "2.0", params: { ...cancelled.params,
        requestId: JSON.stringify(cancelled.params!.requestId) } }, extra);
      return;
    }
    receive?.(message, extra);
  };
  transport.send = (message, options) => send(
    (isJSONRPCResultResponse(message) || isJSONRPCErrorResponse(message)) && message.id !== undefined ?
      { ...message, id: wireId(message.id) } : message,
    options?.relatedRequestId === undefined ? options : { ...options, relatedRequestId: wireId(options.relatedRequestId) },
  );
  transport.closeSSEStream = id => closeStream(wireId(id));
}

function wireId(id: string | number): string | number {
  if (typeof id !== "string") throw refused();
  let value: unknown;
  try { value = JSON.parse(id); } catch { throw refused(); }
  if (typeof value === "string" || typeof value === "number" && Number.isSafeInteger(value)) return value;
  throw refused();
}
