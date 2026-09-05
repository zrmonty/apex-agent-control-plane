import type { QueryClient } from "@tanstack/react-query";
import { ApiError, createManagementClient, type SessionProof } from "./client";
import { getSession, logoutSession, type OperatorSession } from "./session";
import type { OperatorScope, SessionContextValue, SessionPhase } from "./session-context";

// One in-memory owner per mounted application. Generation/proof identity fences
// late requests even when an external transport ignores AbortSignal.
export function createSessionStore(queryClient: QueryClient) {
  let generation = 0;
  let proof: SessionProof | undefined;
  let request: AbortController | undefined;
  let logoutProof: OperatorSession | undefined;
  let state: SessionContextValue;
  const listeners = new Set<() => void>();
  function publish(phase: SessionPhase, session?: OperatorSession, scope?: OperatorScope) {
    proof = phase === "ready" && session && scope
      ? Object.freeze({ subject: session.subject, csrfToken: session.csrfToken }) : undefined;
    const capturedGeneration = generation;
    const capturedProof = proof;
    // A retained context must not acquire a later principal's proof when its
    // delayed onMutate/mutationFn eventually invokes the client.
    const isCurrent = () => generation === capturedGeneration && state === snapshot;
    const client = createManagementClient(() => {
      if (!isCurrent()) throw new ApiError("session-changed");
      return capturedProof;
    }, rejected => {
      if (!isCurrent() || proof !== rejected) return;
      logoutProof = undefined;
      invalidate("anonymous");
    });
    const snapshot: SessionContextValue = {
      phase, session, scope, client, reload, logout, selectScope, isCurrent,
      queryPrefix: session && scope
        ? Object.freeze(["mcp", session.subject, scope.workspaceId, scope.namespaceId, generation]) : undefined,
    };
    state = snapshot;
    for (const notify of listeners) notify();
  }

  function invalidate(phase: SessionPhase) {
    generation++;
    proof = undefined;
    request?.abort();
    request = undefined;
    // Query cancellation and cache removal are synchronous; no observer can
    // inherit prior tenant data. In-flight mutations are also result-fenced by
    // the client proof, not merely removed from the visible mutation cache.
    queryClient.clear();
    publish(phase);
  }

  async function reload() {
    logoutProof = undefined;
    invalidate("loading");
    const current = generation;
    const controller = new AbortController();
    request = controller;
    try {
      const session = await getSession(controller.signal);
      if (generation !== current) return;
      publish(session ? "ready" : "anonymous", session, session?.scopes[0]);
    } catch {
      if (generation === current) publish("unavailable");
    } finally {
      if (generation === current) request = undefined;
    }
  }

  async function logout() {
    if (state.phase === "signing-out") return;
    const session = state.session ?? logoutProof;
    if (!session) return;
    logoutProof = session;
    invalidate("signing-out");
    const current = generation;
    const controller = new AbortController();
    request = controller;
    try {
      await logoutSession(session, controller.signal);
      if (generation !== current) return;
      logoutProof = undefined;
      publish("anonymous");
    } catch {
      if (generation === current) publish("logout-unconfirmed");
    } finally {
      if (generation === current) request = undefined;
    }
  }

  function selectScope(choice: OperatorScope) {
    const session = state.session;
    if (state.phase !== "ready" || !session) throw new ApiError("unauthenticated");
    const scope = session.scopes.find(candidate => candidate.workspaceId === choice.workspaceId
      && candidate.namespaceId === choice.namespaceId);
    if (!scope) throw new ApiError("forbidden");
    if (state.scope === scope) return;
    invalidate("loading");
    publish("ready", session, scope);
  }

  publish("loading");
  return {
    snapshot: () => state,
    subscribe(notify: () => void) { listeners.add(notify); return () => { listeners.delete(notify); }; },
    reload,
    dispose() { logoutProof = undefined; invalidate("loading"); },
  };
}
