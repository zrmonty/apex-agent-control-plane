import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, InitializeRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { ManagedIngressOptions } from "../ingress.js";
import { authenticateInbound, buildBearerChallenge, type InboundIdentity } from "../auth.js";
import { buildManagedToolCatalog } from "../http-server.js";
import { inspect, metadataResponse, readBody, respond, refused } from "./request.js";
import { assertRuntimeMaterialsStage } from "../bootstrap/runtime-materials.js";
import { snapshot, consistent } from "../call-preparation/timing.js";
import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { CompiledExecution } from "../compiled-executor.js";
import { abortable, requestContext, type RequestContext } from "./context.js";
import type { IngressLimits } from "./limits.js";
import { ownExecution } from "./execution.js";
import { cancellation } from "./control.js";
import { preserveRequestIds } from "./sdk-request-ids.js";

type Session = { identity: InboundIdentity; generation: bigint; instance: string;
  mcp: Server; transport: StreamableHTTPServerTransport; executions: Set<CompiledExecution>;
  requests: number; controls: number; ids: Set<string>; expiry: bigint; timer?: ReturnType<typeof setTimeout>; cleanup?: ReturnType<typeof setTimeout>;
  closing: boolean; physical: boolean; closed: Promise<void>; resolveClosed(): void };

export class Sessions {
  private readonly sessions = new Map<string, Session>();
  private stopped = false;
  private last?: ClockSnapshot;
  private readonly requests = new Set<RequestContext>();
  private readonly controlRequests = new Set<RequestContext>();
  private readonly verifications = new Set<Promise<InboundIdentity>>();
  private readonly controlVerifications = new Set<Promise<InboundIdentity>>();
  constructor(private readonly options: ManagedIngressOptions, private readonly limits: IngressLimits) {}
  async handle(req: IncomingMessage, res: ServerResponse) {
    let context: RequestContext | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let bodyTimer: ReturnType<typeof setTimeout> | undefined;
    let usedSession: Session | undefined;
    let createdSession: Session | undefined;
    let rpcId: string | undefined;
    try {
      if (this.stopped) throw refused();
      const original = this.sample();
      const { config, binding } = this.options.stage.documents;
      const checked = inspect(req, config);
      if (checked.metadata) { metadataResponse(res, config); return; }
      if (!this.options.isAdmitting()) { respond(res, 503, { error: "request rejected safely" }); return; }
      // POST cannot be classified until its bounded body is read. At saturation,
      // lend only a control slot, and refuse non-control bodies before SDK dispatch.
      const control = req.method === "DELETE" || this.requests.size >= this.limits.requests ||
        this.verifications.size >= this.limits.requests;
      if (control && (!checked.sessionId || req.method !== "POST" && req.method !== "DELETE" ||
        this.controlRequests.size >= this.limits.controlRequests || this.controlVerifications.size >= this.limits.controlRequests)) {
        respond(res, 503, { error: "capacity unavailable" }); return;
      }
      context = { control, original, deadline: original.monotonicNs + BigInt(this.limits.requestMs) * 1000000n, headers: checked.headers,
        controller: new AbortController(), executions: new Set() };
      (control ? this.controlRequests : this.requests).add(context);
      const ctx = context;
      const abort = () => { ctx.controller.abort(); for (const job of ctx.executions) job.cancel(); };
      res.once("close", abort); req.once("aborted", abort);
      timer = setTimeout(() => { abort(); res.destroy(); }, this.limits.requestMs);
      bodyTimer = setTimeout(() => { abort(); req.destroy(); }, this.limits.bodyMs);
      let identity: InboundIdentity;
      try { identity = await this.authenticate(ctx); }
      catch {
        respond(res, 401, { error: "unauthorized" }, { "www-authenticate": buildBearerChallenge(
          new URL("/.well-known/oauth-protected-resource", config.resourceUrl).href) }); return;
      }
      this.guard(ctx);
      const body = await abortable(readBody(req), ctx.controller.signal);
      clearTimeout(bodyTimer);
      this.guard(ctx);
      const isControl = req.method === "DELETE" || req.method === "POST" && cancellation(body) !== undefined;
      if (ctx.control && !isControl) { respond(res, 503, { error: "capacity unavailable" }); return; }
      let session: Session;
      if (checked.sessionId) {
        const existing = this.sessions.get(checked.sessionId);
        if (!existing || existing.closing || existing.identity.subject !== identity.subject || existing.identity.proxyId !== identity.proxyId ||
          existing.expiry <= this.sample().monotonicNs || existing.generation !== binding.generation || existing.instance !== binding.processInstanceId) {
          respond(res, 404, { error: "session not found" }); return;
        }
        session = existing;
      } else {
        const parsed = InitializeRequestSchema.safeParse(body);
        if (!parsed.success || parsed.data.params.protocolVersion !== config.spec!.ingress!.protocolRevision) throw refused();
        if (this.sessions.size >= this.limits.sessions) { respond(res, 503, { error: "capacity unavailable" }); return; }
        const mcp = new Server({ name: "apex-managed-mcp-proxy", version: "0.1.0" }, { capabilities: { tools: {} } });
        const id = randomUUID();
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => id });
        let resolveClosed!: () => void;
        const closed = new Promise<void>(yes => { resolveClosed = yes; });
        session = { identity, generation: binding.generation, instance: binding.processInstanceId, mcp, transport,
          executions: new Set(), requests: 0, controls: 0, ids: new Set(), expiry: original.monotonicNs + BigInt(this.limits.sessionMs) * 1000000n,
          closing: false, physical: false, closed, resolveClosed };
        this.sessions.set(id, session);
        createdSession = session;
        const owned = session;
        owned.timer = setTimeout(() => { void this.closeSession(owned); }, this.limits.sessionMs);
        mcp.onclose = () => { void this.closeSession(owned); };
        mcp.setRequestHandler(ListToolsRequestSchema, async (_request, extra) => {
          const cancellation = this.bindCancellation(owned, extra);
          try { await this.dispatchIdentity(owned); return { tools: buildManagedToolCatalog(config) }; }
          catch { throw refused(); }
          finally { cancellation.detach(); }
        });
        mcp.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
          const cancellation = this.bindCancellation(owned, extra);
          try {
            const caller = await this.dispatchIdentity(owned), ctx = cancellation.ctx;
            if (extra.signal.aborted || [...this.sessions.values()].reduce((count, s) => count + s.executions.size, 0) >=
              this.limits.executions) throw refused();
            const raw = this.options.executor.start(caller, request.params.name, request.params.arguments ?? {}, ctx.original, ctx.deadline);
            const job = ownExecution(raw, this.limits.cleanupMs, owner => {
              owned.executions.delete(owner); ctx.executions.delete(owner);
              this.finish(owned);
            }, this.options.onFatal);
            owned.executions.add(job); ctx.executions.add(job);
            if (extra.signal.aborted || ctx.controller.signal.aborted || owned.closing) job.cancel();
            const output = await abortable(job.result, ctx.controller.signal);
            this.guard(ctx); if (owned.closing || extra.signal.aborted) throw refused();
            return { ...output, content: [...output.content] };
          } catch { return { isError: true, content: [{ type: "text", text: "managed request rejected safely" }] }; }
          finally { cancellation.detach(); }
        });
        await mcp.connect(transport);
        preserveRequestIds(transport);
      }
      if (isControl && !ctx.control) {
        if (this.controlRequests.size >= this.limits.controlRequests) { respond(res, 503, { error: "capacity unavailable" }); return; }
        this.requests.delete(ctx); this.controlRequests.add(ctx); ctx.control = true;
      }
      if (isControl ? session.controls >= this.limits.sessionControlRequests : session.requests >= this.limits.sessionRequests) {
        respond(res, 503, { error: "capacity unavailable" }); return;
      }
      usedSession = session;
      if (isControl) session.controls++; else session.requests++;
      if (req.method === "POST") {
        if (!body || typeof body !== "object" || Array.isArray(body)) throw refused();
        if (Object.hasOwn(body, "id")) {
          const id = (body as { id: unknown }).id;
          if (!(typeof id === "string" && id.length > 0 && id.length <= 128) &&
            !(typeof id === "number" && Number.isSafeInteger(id))) throw refused();
          const key = JSON.stringify(id);
          if (session.ids.has(key)) throw refused();
          rpcId = key; session.ids.add(key);
        }
      }
      this.guard(ctx);
      await requestContext.run(ctx, () => abortable(session.transport.handleRequest(req, res, body), ctx.controller.signal));
    } catch { respond(res, 400, { error: "request rejected safely" }); }
    finally {
      clearTimeout(timer); clearTimeout(bodyTimer);
      if (createdSession && (!createdSession.transport.sessionId || res.statusCode >= 400 || context?.controller.signal.aborted &&
        !res.writableFinished)) void this.closeSession(createdSession);
      if (context) { this.requests.delete(context); this.controlRequests.delete(context); }
      if (usedSession) { if (context?.control) usedSession.controls--; else usedSession.requests--; }
      if (usedSession && rpcId !== undefined) {
        const owner = usedSession, id = rpcId;
        // A reused ID must never orphan physical work still owned by the earlier request.
        void Promise.all([...(context?.executions ?? [])].map(job => job.closed)).then(() => owner.ids.delete(id), () => {});
      }
    }
  }
  check() {
    if (this.stopped) return;
    const at = this.sample();
    for (const session of this.sessions.values()) if (session.expiry <= at.monotonicNs) void this.closeSession(session);
  }
  private sample() {
    assertRuntimeMaterialsStage(this.options.materials, this.options.stage);
    const at = snapshot(this.options.clock.now());
    if (this.last) consistent(this.last, at); this.last = at;
    if (at.unixUs >= this.options.materials.notAfterUnixUs) throw refused();
    return at;
  }
  private guard(ctx: RequestContext) {
    if (this.stopped || ctx.controller.signal.aborted || !this.options.isAdmitting() ||
      this.sample().monotonicNs >= ctx.deadline) throw refused();
  }
  private async dispatchIdentity(session: Session) {
    const ctx = requestContext.getStore(); if (!ctx || session.closing) throw refused(); this.guard(ctx);
    const identity = await this.authenticate(ctx);
    this.guard(ctx);
    if (session.closing || identity.subject !== session.identity.subject || identity.proxyId !== session.identity.proxyId) throw refused();
    return identity;
  }
  private bindCancellation(session: Session, extra: { signal: AbortSignal; requestId: string | number }) {
    const ctx = requestContext.getStore(); if (!ctx) throw refused();
    const cancel = () => {
      session.transport.closeSSEStream(extra.requestId);
      ctx.controller.abort();
      for (const job of ctx.executions) job.cancel();
    };
    extra.signal.addEventListener("abort", cancel, { once: true });
    if (extra.signal.aborted) cancel();
    return { ctx, detach: () => extra.signal.removeEventListener("abort", cancel) };
  }
  private authenticate(ctx: RequestContext) {
    this.guard(ctx);
    const owners = ctx.control ? this.controlVerifications : this.verifications;
    if (owners.size >= (ctx.control ? this.limits.controlRequests : this.limits.requests)) throw refused();
    // Publish ownership before entering the supplied verifier: it can reenter cancel().
    const pending = Promise.resolve().then(() => {
      this.guard(ctx);
      return authenticateInbound(ctx.headers, this.options.stage.documents.config, this.options.verifier);
    });
    owners.add(pending);
    // An aborted wait is not verifier settlement. Retain the permit and join it on shutdown.
    void pending.then(() => owners.delete(pending), () => owners.delete(pending));
    return abortable(pending, ctx.controller.signal);
  }
  private closeSession(session: Session) {
    if (!session.closing) {
      session.closing = true;
      clearTimeout(session.timer);
      session.cleanup = setTimeout(this.options.onFatal, this.limits.cleanupMs);
      for (const job of session.executions) job.cancel();
      void session.mcp.close().then(() => { session.physical = true; this.finish(session); }, () => this.options.onFatal());
    }
    return session.closed;
  }
  private finish(session: Session) {
    if (!session.closing || !session.physical || session.executions.size) return;
    clearTimeout(session.cleanup);
    for (const [id, entry] of this.sessions) if (entry === session) this.sessions.delete(id);
    session.resolveClosed();
  }
  async close() {
    this.stopped = true;
    for (const ctx of [...this.requests, ...this.controlRequests]) ctx.controller.abort();
    await Promise.all([
      ...[...this.sessions.values()].map(session => this.closeSession(session)),
      Promise.allSettled([...this.verifications, ...this.controlVerifications]),
    ]);
  }
}
