import { randomUUID } from "node:crypto";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import {
  CallToolRequestSchema,
  InitializeRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { Server as McpProtocolServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { GatewayError } from "../contracts.js";
import {
  authenticateInbound,
  buildBearerChallenge,
  normalizeHeaderValues,
  readHeaderValues,
  type HeaderValues,
  type InboundTokenVerifier,
} from "./auth.js";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import { runtimeSpec } from "./runtime-types.js";
import { assertExecutableRuntimeConfiguration } from "./executable-capabilities.js";
import {
  buildProtectedResourceMetadata,
  validateHttpIngressRequest,
  type HttpIngressRequest,
} from "./http.js";

const MAX_BODY_BYTES = 1_048_576;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;|$)/i;

export interface ManagedCallExecutor {
  execute(toolAlias: string, input: unknown, headers: HeaderValues): Promise<unknown>;
  close(): Promise<void>;
}

export type ManagedHttpServerOptions = Readonly<{
  config: ReadonlyRuntimeConfiguration;
  verifier: InboundTokenVerifier;
  executor: ManagedCallExecutor;
  host?: string;
  port?: number;
}>;

export type ManagedHttpAddress = Readonly<{
  host: string;
  port: number;
}>;

type ManagedSession = Readonly<{
  mcp: McpProtocolServer;
  transport: StreamableHTTPServerTransport;
}>;

export class ManagedHttpServer {
  private readonly sessions = new Map<string, ManagedSession>();
  private readonly managedTools: Tool[];
  private server: Server | undefined;
  private closePromise: Promise<void> | undefined;

  constructor(private readonly options: ManagedHttpServerOptions) {
    this.managedTools = buildManagedToolCatalog(options.config);
  }

  async start(): Promise<ManagedHttpAddress> {
    if (this.server !== undefined) {
      return this.address();
    }
    const host = this.options.host ?? "127.0.0.1";
    const port = this.options.port ?? 8080;
    if (host.length === 0 || !Number.isSafeInteger(port) || port < 0 || port > 65_535) {
      throw new GatewayError("INVALID_INPUT", "managed HTTP listener configuration rejected safely");
    }
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => {
        server.off("listening", onListening);
        reject(new GatewayError("GOVERNANCE_UNAVAILABLE", "managed HTTP listener failed safely"));
        void error;
      };
      const onListening = () => {
        server.off("error", onError);
        resolve();
      };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(port, host);
    });
    this.server = server;
    return this.address();
  }

  async close(): Promise<void> {
    if (this.closePromise !== undefined) {
      return this.closePromise;
    }
    this.closePromise = (async () => {
      const server = this.server;
      this.server = undefined;
      const serverClosed = server === undefined
        ? Promise.resolve()
        : new Promise<void>((resolve) => server.close(() => resolve()));
      const sessions = [...this.sessions.values()];
      this.sessions.clear();
      await Promise.allSettled(sessions.map(async (session) => session.mcp.close()));
      try {
        await this.options.executor.close();
      } finally {
        await serverClosed;
      }
    })();
    return this.closePromise;
  }

  private address(): ManagedHttpAddress {
    const address = this.server?.address();
    if (address === null || address === undefined || typeof address === "string") {
      throw new GatewayError("GOVERNANCE_UNAVAILABLE", "managed HTTP listener is unavailable safely");
    }
    const info = address as AddressInfo;
    return { host: info.address, port: info.port };
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const headers = nodeHeaders(request.headers);
    try {
      const body = await readBody(request);
      if (isProtectedResourceMetadataRequest(request, headers, this.options.config)) {
        respondJson(response, 200, buildProtectedResourceMetadata(this.options.config));
        return;
      }
      const method = request.method;
      if (method !== "GET" && method !== "POST") {
        throw new GatewayError("INVALID_INPUT", "HTTP ingress request rejected safely");
      }
      if (method === "POST" && !hasJsonContentType(headers)) {
        throw new GatewayError("INVALID_INPUT", "HTTP ingress content type rejected safely");
      }
      const url = requestUrl(request, headers);
      const ingressRequest: HttpIngressRequest = {
        method,
        url,
        headers,
        bodyBytes: body.bytes,
      };
      const validated = validateHttpIngressRequest(ingressRequest, this.options.config);
      try {
        await authenticateInbound(headers, this.options.config, this.options.verifier);
      } catch (error: unknown) {
        if (error instanceof GatewayError && error.code === "INVALID_INPUT") {
          respondUnauthorized(response, this.options.config);
          return;
        }
        throw error;
      }
      if (validated.sessionId !== undefined) {
        const session = this.sessions.get(validated.sessionId);
        if (session === undefined) {
          respondJson(response, 404, { error: "session not found" });
          return;
        }
        await session.transport.handleRequest(request as IncomingMessage & { auth?: never }, response, body.value);
        return;
      }
      const initialize = InitializeRequestSchema.safeParse(body.value);
      if (!initialize.success || initialize.data.params.protocolVersion !== runtimeSpec(this.options.config).ingress!.protocolRevision) {
        throw new GatewayError("INVALID_INPUT", "HTTP ingress protocol rejected safely");
      }
      const session = await this.createSession();
      await session.transport.handleRequest(request as IncomingMessage & { auth?: never }, response, body.value);
      const sessionId = session.transport.sessionId;
      if (sessionId !== undefined) {
        this.sessions.set(sessionId, session);
      }
    } catch (error: unknown) {
      const code = error instanceof GatewayError ? error.code : "ADAPTER_FAILED";
      const status = code === "GOVERNANCE_UNAVAILABLE" ? 503 : 400;
      respondJson(response, status, { error: "request rejected safely" });
    }
  }

  private async createSession(): Promise<ManagedSession> {
    const mcp = createManagedMcpServer(this.options.executor, this.managedTools);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: randomUUID,
    });
    await mcp.connect(transport);
    transport.onclose = () => {
      const sessionId = transport.sessionId;
      if (sessionId !== undefined) {
        this.sessions.delete(sessionId);
      }
      void mcp.close().catch(() => undefined);
    };
    return { mcp, transport };
  }
}

function createManagedMcpServer(
  executor: ManagedCallExecutor,
  managedTools: readonly Tool[],
): McpProtocolServer {
  const server = new McpProtocolServer(
    { name: "apex-managed-mcp-proxy", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: managedTools,
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    try {
      const output = await executor.execute(
        request.params.name,
        request.params.arguments ?? {},
        sdkHeaders(extra.requestInfo?.headers),
      );
      return successResult(output);
    } catch (error: unknown) {
      if (error instanceof GatewayError) {
        return errorResult(error.code);
      }
      return errorResult("ADAPTER_FAILED");
    }
  });
  return server;
}

export function buildManagedToolCatalog(config: ReadonlyRuntimeConfiguration): Tool[] {
  assertExecutableRuntimeConfiguration(config);
  const tools = runtimeSpec(config).exposedTools.map(tool => {
    const schema = config.toolSchemas.find(value => value.upstreamId === tool.upstreamId && value.toolName === tool.toolName)!;
    return { name: tool.alias, description: `Governed managed tool ${tool.alias}`,
      inputSchema: JSON.parse(schema.inputSchemaJson) as Tool["inputSchema"],
      outputSchema: JSON.parse(schema.outputSchemaJson) as Tool["outputSchema"] };
  });
  Object.freeze(tools);
  return tools;
}

function successResult(output: unknown): CallToolResult {
  if (isRecord(output)) {
    return { content: [{ type: "text", text: "managed tool completed" }], structuredContent: output };
  }
  return { content: [{ type: "text", text: JSON.stringify(output) ?? "null" }] };
}

function errorResult(code: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: `${code}: request rejected safely` }] };
}

function nodeHeaders(headers: IncomingHttpHeaders): HeaderValues {
  return normalizeHeaderValues(headers);
}

function sdkHeaders(headers: Record<string, string | string[] | undefined> | undefined): HeaderValues {
  if (headers === undefined) {
    return {};
  }
  return normalizeHeaderValues(headers);
}

function requestUrl(request: IncomingMessage, headers: HeaderValues): string {
  const host = singleHeader(headers, "host");
  if (host === undefined || request.url === undefined) {
    throw new GatewayError("INVALID_INPUT", "HTTP ingress request rejected safely");
  }
  return `https://${host}${request.url}`;
}

function isProtectedResourceMetadataRequest(
  request: IncomingMessage,
  headers: HeaderValues,
  config: ReadonlyRuntimeConfiguration,
): boolean {
  if (request.method !== "GET") {
    return false;
  }
  try {
    const target = new URL(requestUrl(request, headers));
    const metadata = buildProtectedResourceMetadata(config);
    return target.toString() === metadataUrl(metadata.resource);
  } catch {
    return false;
  }
}

async function readBody(request: IncomingMessage): Promise<Readonly<{ bytes: number; value?: unknown }>> {
  if (request.method === "GET") {
    return { bytes: 0 };
  }
  const chunks: Buffer[] = [];
  let bytes = 0;
  return new Promise((resolve, reject) => {
    request.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.byteLength;
      if (bytes > MAX_BODY_BYTES) {
        reject(new GatewayError("INVALID_INPUT", "HTTP ingress request exceeded its safe bound"));
        request.destroy();
        return;
      }
      chunks.push(buffer);
    });
    request.on("end", () => {
      if (bytes === 0) {
        resolve({ bytes });
        return;
      }
      try {
        resolve({ bytes, value: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
      } catch {
        reject(new GatewayError("INVALID_INPUT", "HTTP ingress JSON rejected safely"));
      }
    });
    request.on("error", () => reject(new GatewayError("ADAPTER_FAILED", "HTTP ingress failed safely")));
    request.on("aborted", () => reject(new GatewayError("ADAPTER_FAILED", "HTTP ingress aborted safely")));
  });
}

function hasJsonContentType(headers: HeaderValues): boolean {
  const contentType = singleHeader(headers, "content-type");
  return contentType !== undefined && JSON_CONTENT_TYPE.test(contentType);
}

function singleHeader(headers: HeaderValues, name: string): string | undefined {
  const values = readHeaderValues(headers, name);
  return values.length === 1 && values[0].length > 0 ? values[0] : undefined;
}

function metadataUrl(resource: string): string {
  const endpoint = new URL(resource);
  return new URL("/.well-known/oauth-protected-resource", endpoint.origin).toString();
}

function respondJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const serialized = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(serialized, "utf8"),
    ...headers,
  });
  response.end(serialized);
}

function respondUnauthorized(response: ServerResponse, config: ReadonlyRuntimeConfiguration): void {
  const metadata = buildProtectedResourceMetadata(config);
  respondJson(response, 401, { error: "unauthorized" }, {
    "www-authenticate": buildBearerChallenge(metadataUrl(metadata.resource)),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
