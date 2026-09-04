import { createHash, randomUUID } from "node:crypto";

import { GatewayError } from "../contracts.js";
import type { ExposedTool, ProxyRevisionConfig, UpstreamConfig } from "./config.js";
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

export function createUpstreamSessions(
  config: ProxyRevisionConfig,
  transport: UpstreamTransport,
): ReadonlyMap<string, UpstreamSession> {
  const sessions = new Map<string, UpstreamSession>();
  for (const upstream of config.upstreams) {
    const exposedTools = config.exposedTools.filter((tool) => tool.upstreamId === upstream.upstreamId);
    sessions.set(upstream.upstreamId, new ManagedUpstreamSession(upstream, exposedTools, transport));
  }
  return sessions;
}

class ManagedUpstreamSession implements UpstreamSession {
  private readonly sessionId = randomUUID();
  private discoveredNames: ReadonlySet<string> | undefined;
  private closed = false;

  constructor(
    private readonly upstream: UpstreamConfig,
    private readonly exposedTools: readonly ExposedTool[],
    private readonly transport: UpstreamTransport,
  ) {}

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
    const allowed = this.exposedTools.some(
      (candidate) => candidate.alias === tool.alias && candidate.toolName === tool.toolName,
    );
    if (!allowed || tool.upstreamId !== this.upstream.upstreamId) {
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
    if (this.upstream.transport !== "streamable-http") {
      return;
    }
    const endpoint = this.upstream.endpointOrCommandRef;
    let hostname: string;
    try {
      hostname = new URL(endpoint).hostname;
    } catch {
      throw new GatewayError("INVALID_INPUT", "upstream destination rejected safely");
    }
    validateHttpsDestination(endpoint, [hostname]);
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
