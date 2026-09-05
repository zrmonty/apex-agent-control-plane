import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { createManagementClient } from "./client";
import type { OperatorSession } from "./session";
import { createSessionStore } from "./session-store";

export type OperatorScope = OperatorSession["scopes"][number];
export type SessionPhase = "loading" | "anonymous" | "ready" | "unavailable" | "signing-out" | "logout-unconfirmed";
export interface SessionContextValue {
  phase: SessionPhase;
  session?: OperatorSession;
  scope?: OperatorScope;
  queryPrefix?: readonly unknown[];
  client: ReturnType<typeof createManagementClient>;
  isCurrent(): boolean;
  reload(): Promise<void>;
  logout(): Promise<void>;
  selectScope(scope: OperatorScope): void;
}

const SessionContext = createContext<SessionContextValue | undefined>(undefined);

export function SessionProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [store] = useState(() => createSessionStore(queryClient));
  const value = useSyncExternalStore(store.subscribe, store.snapshot);
  useEffect(() => {
    void store.reload();
    return store.dispose;
  }, [store]);
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useOperatorSession(): SessionContextValue {
  const context = useContext(SessionContext);
  if (!context) throw new Error("SessionProvider is required");
  return context;
}

export function SessionGate({ children }: { children: ReactNode }) {
  const context = useOperatorSession();
  if (context.phase === "ready" && context.scope) return <>{children}</>;
  const busy = context.phase === "loading" || context.phase === "signing-out";
  return <main id="main-content" className="session-screen">
    <section aria-labelledby="session-heading">
      <h1 id="session-heading">Apex control plane</h1>
      {busy ? <p role="status">{context.phase === "loading" ? "Checking your session…" : "Signing out…"}</p>
        : context.phase === "anonymous" ? <>
          <p>Sign in to manage your authorized MCP proxies.</p>
          <a className="primary-button" href="/auth/login">Sign in</a>
        </> : context.phase === "logout-unconfirmed" ? <>
          <p role="alert">Sign-out not confirmed. Management is disabled in this tab.</p>
          <p>The server could still hold your session. Retry sign-out before leaving a shared device.</p>
          <button className="primary-button" onClick={() => void context.logout()}>Retry sign-out</button>
        </> : context.phase === "ready" ? <>
          <p role="alert">No authorized scopes.</p>
          <p>Ask your administrator for access to a workspace and namespace.</p>
          <button className="secondary-button" onClick={() => void context.logout()}>Sign out</button>
        </> : <>
          <p role="alert">Session unavailable. The control plane could not verify your access.</p>
          <button className="primary-button" onClick={() => void context.reload()}>Retry</button>
        </>}
    </section>
  </main>;
}
