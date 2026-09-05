import { createHash, randomUUID } from "node:crypto";

import { GatewayError } from "../contracts.js";
import { McpProxyTransport } from "@apex/contracts";
import type { ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import { runtimeSpec, upstreamGrant, type RuntimeTool as ExposedTool, type RuntimeUpstream as UpstreamConfig } from "./runtime-types.js";
import { validateHttpsDestination } from "./network.js";

const MAX_DISCOVERY_BYTES = 1_048_576;
const MAX_DISCOVERED_TOOLS = 512;
const TOOL_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export type QuarantinedToolCatalog = Readonly<{
  upstreamId: string;
  schemaHash: string;
  tools: readonly unknown[];
}>;

export interface UpstreamSession {
  discover(): Promise<QuarantinedToolCatalog>;
  call(tool: ExposedTool, input: unknown): Promise<unknown>;
  close(): Promise<void>;
}

export interface UpstreamTransport {
  discover(upstream: UpstreamConfig): Promise<unknown>;
  call(upstream: UpstreamConfig, toolName: string, input: unknown): Promise<unknown>;
  close(upstream: UpstreamConfig): Promise<void>;
}

export type ExposedToolIndexes = Readonly<{
  byAlias: ReadonlyMap<string, ExposedTool>;
  byUpstream: ReadonlyMap<string, readonly ExposedTool[]>;
}>;

export function compileExposedToolIndexes(config: ReadonlyRuntimeConfiguration): ExposedToolIndexes {
  const byAlias = new Map<string, ExposedTool>();
  const byUpstream = new Map<string, ExposedTool[]>();
  for (const tool of runtimeSpec(config).exposedTools) {
    byAlias.set(tool.alias, tool);
    const tools = byUpstream.get(tool.upstreamId);
    if (tools === undefined) {
      byUpstream.set(tool.upstreamId, [tool]);
    } else {
      tools.push(tool);
    }
  }
  return {
    byAlias,
    byUpstream: new Map(
      [...byUpstream.entries()].map(([upstreamId, tools]) => [upstreamId, Object.freeze(tools.slice())]),
    ),
  };
}

export function createUpstreamSessions(
  config: ReadonlyRuntimeConfiguration,
  transport: UpstreamTransport,
): ReadonlyMap<string, UpstreamSession> {
  const sessions = new Map<string, UpstreamSession>();
  const indexes = compileExposedToolIndexes(config);
  for (const upstream of runtimeSpec(config).upstreams) {
    const exposedTools = indexes.byUpstream.get(upstream.upstreamId) ?? [];
    sessions.set(upstream.upstreamId, new ManagedUpstreamSession(config, upstream, exposedTools, transport));
  }
  return sessions;
}

class ManagedUpstreamSession implements UpstreamSession {
  private readonly sessionId = randomUUID();
  private discoveredNames: ReadonlySet<string> | undefined;
  private closed = false;
  private readonly exposedToolNamesByAlias: ReadonlyMap<string, string>;

  constructor(
    private readonly config: ReadonlyRuntimeConfiguration,
    private readonly upstream: UpstreamConfig,
    exposedTools: readonly ExposedTool[],
    private readonly transport: UpstreamTransport,
  ) {
    this.exposedToolNamesByAlias = new Map(exposedTools.map((tool) => [tool.alias, tool.toolName]));
  }

  async discover(): Promise<QuarantinedToolCatalog> {
    this.ensureOpen();
    this.validateDestination();
    const raw = await this.transport.discover(this.upstream);
    const quarantined = quarantineCatalog(this.upstream.upstreamId, raw);
    this.discoveredNames = new Set(extractToolNames(quarantined.tools));
    return quarantined;
  }

  async call(tool: ExposedTool, input: unknown): Promise<unknown> {
    this.ensureOpen();
    const exposedToolName = this.exposedToolNamesByAlias.get(tool.alias);
    if (exposedToolName !== tool.toolName || tool.upstreamId !== this.upstream.upstreamId) {
      throw new GatewayError("INVALID_INPUT", "upstream tool is not explicitly exposed");
    }
    if (this.discoveredNames === undefined || !this.discoveredNames.has(tool.toolName)) {
      throw new GatewayError("INVALID_INPUT", "upstream tool is not discovered");
    }
    this.validateDestination();
    return this.transport.call(this.upstream, tool.toolName, input);
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    await this.transport.close(this.upstream);
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new GatewayError("INVALID_INPUT", "upstream session is closed");
    }
  }

  private validateDestination(): void {
    if (this.upstream.transport !== McpProxyTransport.STREAMABLE_HTTP) {
      throw new GatewayError("INVALID_INPUT", "upstream transport rejected safely");
    }
    const endpoint = this.upstream.endpointOrCommandRef;
    const grant = upstreamGrant(this.config, this.upstream);
    validateHttpsDestination(endpoint, [grant.host]);
  }

  // Keeps the per-session state observable in a debugger without exposing credentials.
  get identity(): string {
    return this.sessionId;
  }
}

function quarantineCatalog(upstreamId: string, raw: unknown): QuarantinedToolCatalog {
  const snapshot = cloneJsonWithinLimit(raw);
  if (!isRecord(snapshot) || !Array.isArray(snapshot.tools) || snapshot.tools.length > MAX_DISCOVERED_TOOLS) {
    throw new GatewayError("INVALID_INPUT", "upstream discovery was rejected safely");
  }
  const tools = Object.freeze(snapshot.tools.slice()) as readonly unknown[];
  return Object.freeze({
    upstreamId,
    schemaHash: sha256(canonicalJson(tools)),
    tools,
  });
}

function extractToolNames(tools: readonly unknown[]): readonly string[] {
  const names: string[] = [];
  for (const tool of tools) {
    const name = typeof tool === "string" ? tool : isRecord(tool) && typeof tool.name === "string" ? tool.name : undefined;
    if (name !== undefined && TOOL_NAME_PATTERN.test(name)) {
      names.push(name);
    }
  }
  return names;
}

function cloneJsonWithinLimit(value: unknown): unknown {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new GatewayError("INVALID_INPUT", "upstream discovery was rejected safely");
  }
  if (serialized === undefined || Buffer.byteLength(serialized, "utf8") > MAX_DISCOVERY_BYTES) {
    throw new GatewayError("INVALID_INPUT", "upstream discovery exceeded its safe bound");
  }
  try {
    return JSON.parse(serialized);
  } catch {
    throw new GatewayError("INVALID_INPUT", "upstream discovery was rejected safely");
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
