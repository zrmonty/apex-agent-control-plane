import { create, type DescMethod, type MessageInitShape, type MessageShape } from "@bufbuild/protobuf";
import { decodeStrict, encodeJson, McpProxyService } from "@apex/contracts";

// Memory-only browser session context, not provider credentials or RPC authority.
export type SessionProof = Readonly<{ subject: string; csrfToken: string }>;
export type ClientErrorCode = "unauthenticated" | "forbidden" | "conflict" | "rate-limited"
  | "unavailable" | "invalid-request" | "invalid-response" | "cancelled" | "session-changed";

export class ApiError extends Error {
  constructor(readonly code: ClientErrorCode) { super(code); this.name = "ApiError"; }
}

export function createManagementClient(
  currentSession: () => SessionProof | undefined,
  onUnauthorized: (session: SessionProof) => void,
) {
  return {
    async call<M extends DescMethod>(
      method: M, input: MessageInitShape<M["input"]>, signal?: AbortSignal,
    ): Promise<MessageShape<M["output"]>> {
      const session = currentSession();
      if (!session) throw new ApiError("unauthenticated");
      if (signal?.aborted) throw new ApiError("cancelled");
      const deadline = performance.now() + 45_000;
      if (!McpProxyService.methods.includes(method)) throw new ApiError("invalid-request");
      let body: string;
      try { body = JSON.stringify(encodeJson(method.input, create(method.input, input))); }
      catch { throw new ApiError("invalid-request"); }

      const controller = new AbortController();
      let stoppedCode: "cancelled" | "unavailable" | undefined;
      let notifiedUnauthorized = false;
      const check = () => {
        // A timely 401 callback may intentionally clear this same identity.
        if (!notifiedUnauthorized && currentSession() !== session) throw new ApiError("session-changed");
        if (stoppedCode) throw new ApiError(stoppedCode);
        if (signal?.aborted) throw new ApiError("cancelled");
        if (performance.now() >= deadline) throw new ApiError("unavailable");
      };
      let rejectStop!: (error: ApiError) => void;
      const stopped = new Promise<never>((_, reject) => { rejectStop = reject; });
      const stop = (code: "cancelled" | "unavailable") => {
        if (stoppedCode) return;
        stoppedCode = code;
        rejectStop(new ApiError(code));
        controller.abort();
      };
      const cancel = () => stop("cancelled");
      signal?.addEventListener("abort", cancel, { once: true });
      const timer = setTimeout(() => stop("unavailable"), Math.max(0, deadline - performance.now()));
      type Outcome = { ok: true; value: MessageShape<M["output"]> } | { ok: false; code: ClientErrorCode };
      try {
        const result = await Promise.race([stopped, (async (): Promise<Outcome> => {
          check();
          let response: Response;
          try {
            response = await fetch(`/api/apex/v1/McpProxyService/${method.name}`, {
              method: "POST", body, credentials: "same-origin", mode: "same-origin",
              cache: "no-store", redirect: "error", referrerPolicy: "no-referrer",
              headers: { "content-type": "application/json", accept: "application/json", "x-apex-csrf": session.csrfToken },
              signal: controller.signal,
            });
          } catch {
            check();
            throw new ApiError("unavailable");
          }
          try {
            check();
            if (response.status !== 200) return { ok: false, code: statusCode(response.status) };
            const bytes = await readJsonResponse(response, controller.signal, check);
            check();
            let value: MessageShape<M["output"]>;
            try { value = decodeStrict<M["output"]>(method.output, bytes); }
            catch { check(); throw new ApiError("invalid-response"); }
            check();
            return { ok: true, value };
          } finally {
            discardResponse(response);
          }
        })()]);
        // Work can finish before a queued abort, deadline or identity change.
        // Fence delivery (including 401 notification) after the race settles.
        check();
        if (!result.ok) {
          if (result.code === "unauthenticated") {
            notifiedUnauthorized = true;
            try { onUnauthorized(session); }
            catch { throw new ApiError("unavailable"); }
          }
          check();
          throw new ApiError(result.code);
        }
        return result.value;
      } catch (error) {
        check();
        throw new ApiError(error instanceof ApiError ? error.code : "unavailable");
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener("abort", cancel);
        controller.abort();
      }
    },
  };
}

function statusCode(status: number): ClientErrorCode {
  switch (status) {
    case 401: return "unauthenticated";
    case 403: return "forbidden";
    case 409: return "conflict";
    case 429: return "rate-limited";
    case 400: case 413: return "invalid-request";
    default: return "unavailable";
  }
}

// Bound bytes before generated parsing; response Content-Length is only a hint.
async function readJsonResponse(response: Response, signal: AbortSignal, check: () => void): Promise<string> {
  const limit = 256 * 1024;
  const mediaType = response.headers.get("content-type")?.trim() ?? "";
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(mediaType)
    || Number(response.headers.get("content-length") ?? 0) > limit || !response.body) {
    throw new ApiError("invalid-response");
  }
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let bytes = 0, text = "";
    for (;;) {
      check();
      const { done, value } = await reader.read();
      check();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) throw new ApiError("invalid-response");
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    check();
    return text;
  } catch {
    check();
    throw new ApiError("invalid-response");
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel();
    reader.releaseLock();
  }
}

function discardResponse(response: Response): void {
  try {
    // Discard the native stream without reading bytes or invoking an overridden
    // body accessor. Error details and response accessors are not trusted data.
    const getter = Object.getOwnPropertyDescriptor(Response.prototype, "body")?.get;
    const body = getter?.call(response) as ReadableStream<Uint8Array> | null | undefined;
    if (body && !body.locked) void body.cancel().catch(() => {});
  } catch {
    // Cleanup must not replace a sanitized result with an arbitrary exception.
  }
}
