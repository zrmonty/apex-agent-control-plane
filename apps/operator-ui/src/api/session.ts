import { ApiError, type ClientErrorCode, type SessionProof } from "./client";

// Memory-only display context; capabilities never grant management authority.
export interface OperatorSession extends SessionProof {
  readonly scopes: readonly Readonly<{ workspaceId: string; namespaceId: string }>[];
  readonly capabilities: Readonly<{
    runtimeReadiness: "unknown";
    approvals: boolean;
    traces: boolean;
  }>;
}

const deadlineMs = 45_000;
const responseLimit = 128 * 1024;

export async function getSession(signal?: AbortSignal): Promise<OperatorSession | undefined> {
  return request<OperatorSession | undefined>("/api/session", {
    method: "GET", headers: { accept: "application/json" },
  }, signal, async (response, transportSignal, check) => {
    if (response.status === 401) return undefined;
    if (response.status !== 200) throw new ApiError(statusCode(response.status));
    return readSession(response, transportSignal, check);
  });
}

export async function logoutSession(session: OperatorSession, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) throw new ApiError("cancelled");
  if (!isCsrfToken(session.csrfToken)) throw new ApiError("invalid-request");
  await request<void>("/auth/logout", {
    method: "POST", headers: { accept: "application/json", "x-apex-csrf": session.csrfToken },
  }, signal, response => {
    if (response.status !== 204 && response.status !== 401) {
      throw new ApiError(statusCode(response.status));
    }
  });
}

// Race the entire operation, not just fetch: a peer can stall after headers.
async function request<T>(
  path: "/api/session" | "/auth/logout",
  init: Pick<RequestInit, "method" | "headers">,
  signal: AbortSignal | undefined,
  receive: (response: Response, transportSignal: AbortSignal, check: () => void) => T | Promise<T>,
): Promise<T> {
  if (signal?.aborted) throw new ApiError("cancelled");
  const controller = new AbortController();
  const deadline = performance.now() + deadlineMs;
  let stoppedCode: "cancelled" | "unavailable" | undefined;
  let rejectStop!: (error: ApiError) => void;
  const stopped = new Promise<never>((_, reject) => { rejectStop = reject; });
  const stop = (code: "cancelled" | "unavailable") => {
    if (stoppedCode) return;
    stoppedCode = code;
    rejectStop(new ApiError(code));
    controller.abort();
  };
  const cancel = () => stop("cancelled");
  const check = () => {
    if (stoppedCode) throw new ApiError(stoppedCode);
    if (signal?.aborted) throw new ApiError("cancelled");
    // The event loop may delay the timer past the deadline.
    if (performance.now() >= deadline) throw new ApiError("unavailable");
  };
  signal?.addEventListener("abort", cancel, { once: true });
  const timer = setTimeout(() => stop("unavailable"), deadlineMs);
  try {
    const result = await Promise.race([stopped, (async () => {
      check();
      let response: Response;
      try {
        response = await fetch(path, {
          ...init, credentials: "same-origin", mode: "same-origin", cache: "no-store",
          redirect: "error", referrerPolicy: "no-referrer", signal: controller.signal,
        });
      } catch {
        check();
        throw new ApiError("unavailable");
      }
      try {
        // Even a late 401 must not acknowledge logout or clear newer UI state.
        check();
        const value = await receive(response, controller.signal, check);
        check();
        return value;
      } finally {
        // Includes late responses from a transport that ignored cancellation.
        if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
      }
    })()]);
    check();
    return result;
  } catch (error) {
    check();
    throw new ApiError(error instanceof ApiError ? error.code : "unavailable");
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
    controller.abort();
  }
}

function statusCode(status: number): ClientErrorCode {
  switch (status) {
    case 400: case 413: return "invalid-request";
    case 403: return "forbidden";
    case 409: return "conflict";
    case 429: return "rate-limited";
    default: return "unavailable";
  }
}

async function readSession(response: Response, signal: AbortSignal, check: () => void): Promise<OperatorSession> {
  const mediaType = response.headers.get("content-type")?.trim() ?? "";
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?$/i.test(mediaType)
    || Number(response.headers.get("content-length") ?? 0) > responseLimit || !response.body) {
    throw new ApiError("invalid-response");
  }
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let bytes = 0;
    let text = "";
    for (;;) {
      check();
      const { done, value } = await reader.read();
      check();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > responseLimit) throw new ApiError("invalid-response");
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    check();
    const value: unknown = JSON.parse(text);
    const session = validateSession(value);
    check();
    return session;
  } catch {
    check();
    throw new ApiError("invalid-response");
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel();
    reader.releaseLock();
  }
}

function exactObject(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)
    || Object.keys(value).length !== keys.length
    || !keys.every(key => Object.prototype.hasOwnProperty.call(value, key))) {
    throw new ApiError("invalid-response");
  }
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256
    && !value.includes("..") && !/[^A-Za-z0-9._:-]/.test(value);
}

function isCsrfToken(value: unknown): value is string {
  // 32 bytes use 43 unpadded characters; the last character's low two bits are zero.
  return typeof value === "string" && value.length === 43
    && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value);
}

function validateSession(value: unknown): OperatorSession {
  exactObject(value, ["subject", "scopes", "csrfToken", "capabilities"]);
  const { subject, csrfToken, scopes, capabilities } = value;
  const prefix = "operator:keycloak:";
  if (typeof subject !== "string" || subject.length > 512 || subject.length <= prefix.length
    || !subject.startsWith(prefix) || /[^\x20-\x7e]/.test(subject)
    || !isCsrfToken(csrfToken) || !Array.isArray(scopes) || scopes.length > 256) {
    throw new ApiError("invalid-response");
  }
  exactObject(capabilities, ["runtimeReadiness", "approvals", "traces"]);
  if (capabilities.runtimeReadiness !== "unknown" || typeof capabilities.approvals !== "boolean"
    || typeof capabilities.traces !== "boolean") {
    throw new ApiError("invalid-response");
  }
  const seen = new Set<string>();
  const choices = scopes.map((scope: unknown) => {
    exactObject(scope, ["workspaceId", "namespaceId"]);
    const { workspaceId, namespaceId } = scope;
    if (!isIdentifier(workspaceId) || !isIdentifier(namespaceId)) throw new ApiError("invalid-response");
    // Neither identifier can contain the separator.
    const key = `${workspaceId}/${namespaceId}`;
    if (seen.has(key)) throw new ApiError("invalid-response");
    seen.add(key);
    return Object.freeze({ workspaceId, namespaceId });
  });
  return Object.freeze({
    subject, csrfToken, scopes: Object.freeze(choices),
    capabilities: Object.freeze({
      runtimeReadiness: "unknown", approvals: capabilities.approvals, traces: capabilities.traces,
    }),
  });
}
