import { CreateProxyRequestSchema } from "@apex/contracts";
import { create } from "@bufbuild/protobuf";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError } from "../../api/client";
import { useOperatorSession } from "../../api/session-context";
import { requestId, useProxyApi } from "./api";

export function NewProxyWizard() {
  const { queryPrefix } = useOperatorSession();
  return <CreateDraft key={JSON.stringify(queryPrefix)} />;
}
function CreateDraft() {
  const { scope, queryPrefix, isCurrent } = useOperatorSession();
  const api = useProxyApi();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const attempt = useRef<ReturnType<typeof makeRequest> | undefined>(undefined);
  const active = useRef<AbortController | undefined>(undefined);
  useEffect(() => () => active.current?.abort(), []);

  function makeRequest() {
    if (!scope) throw new ApiError("unauthenticated");
    return create(CreateProxyRequestSchema, { ...scope, requestId: requestId(), proxyId: requestId(),
      displayName: name.trim(), slug: slug.trim() });
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (active.current || !scope || !queryPrefix) return;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true); setMessage("");
    try {
      const input = attempt.current ??= makeRequest();
      const result = await api.createProxy(input, controller.signal);
      if (!isCurrent() || controller.signal.aborted) return;
      if (!result.proxy || result.proxy.proxyId !== input.proxyId || result.proxy.workspaceId !== input.workspaceId
        || result.proxy.namespaceId !== input.namespaceId) throw new ApiError("invalid-response");
      await queryClient.invalidateQueries({ queryKey: queryPrefix });
      if (isCurrent() && !controller.signal.aborted) await navigate({ to: "/mcp-proxies/$proxyId", params: { proxyId: input.proxyId } });
    } catch (error) {
      if (isCurrent() && !controller.signal.aborted) setMessage(error instanceof ApiError && error.code === "forbidden"
        ? "Access denied for this scope. Ask your administrator to verify your permissions."
        : error instanceof ApiError && error.code === "conflict"
          ? "The draft conflicts with current server state. Check the inventory before retrying."
          : "The control plane could not confirm draft creation. Retry with the same request, or check the inventory before starting again.");
    } finally {
      if (isCurrent() && !controller.signal.aborted) setBusy(false);
      if (active.current === controller) active.current = undefined;
    }
  }
  return <main id="main-content" className="proxy-page wizard-page">
    <header className="app-header"><div className="crumb"><Link to="/mcp-proxies">MCP proxies</Link><span>/</span><strong>New proxy</strong></div><Link to="/mcp-proxies">Cancel</Link></header>
    <div className="wizard-heading"><div><h1>New MCP proxy</h1><p>Create a persistent identity in {scope?.workspaceId} / {scope?.namespaceId}. Nothing is published or deployed by this step.</p></div></div>
    <form className="wizard-card" onSubmit={event => void submit(event)}>
      <h2>Proxy identity</h2><p>Start with a name and stable slug. Runtime configuration and deployment are separate steps.</p>
      <div className="form-grid">
        <label className="form-field"><span>Display name</span><input required maxLength={128} value={name} disabled={busy || Boolean(attempt.current)} onChange={event => setName(event.target.value)} /></label>
        <label className="form-field"><span>Stable slug</span><input required maxLength={128} pattern="[a-z0-9]+(-[a-z0-9]+)*" value={slug} disabled={busy || Boolean(attempt.current)} onChange={event => setSlug(event.target.value)} aria-describedby="slug-help" /></label>
      </div>
      <p id="slug-help">Use lowercase letters, numbers and hyphens. The server validates uniqueness within this scope.</p>
      {message && <p role="alert">{message}</p>}
      {busy && <p role="status">Saving the draft identity…</p>}
      <div className="wizard-actions"><Link className="secondary-button" to="/mcp-proxies">Back to proxies</Link>
        <button className="primary-button" type="submit" disabled={busy || !name.trim() || !slug.trim()}>{attempt.current ? "Retry create draft" : "Create draft"}</button></div>
      {attempt.current && <p>Retry keeps the same proxy identity, configuration and UUIDv7 request ID.</p>}
    </form>
  </main>;
}
