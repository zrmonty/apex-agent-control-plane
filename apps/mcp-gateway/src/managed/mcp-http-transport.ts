import { lookup } from "node:dns/promises";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StreamableHTTPClientTransport,
  type StreamableHTTPClientTransportOptions,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import { GatewayError } from "../contracts.js";
import {
  createOutboundCredentialProvider,
  type OutboundCredentialProvider,
  type SecretCredentialResolver,
} from "./auth.js";
import type { UpstreamConfig } from "./config.js";
import { validateHttpsDestination, validateResolvedAddresses } from "./network.js";
import type { UpstreamTransport } from "./upstream.js";

const MAX_REQUEST_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 300_000;
const DEFAULT_ADDRESS_CACHE_TTL_MS = 1_000;
const MAX_ADDRESS_CACHE_TTL_MS = 10_000;

type ResolveAddresses = (hostname: string) => Promise<readonly string[]>;

export type McpHttpUpstreamTransportOptions = Readonly<{
  fetch?: FetchLike;
  resolveAddresses?: ResolveAddresses;
  timeoutMs?: number;
  maxResponseBytes?: number;
  addressCacheTtlMs?: number;
  now?: () => number;
}>;

type ClientSession = Readonly<{
  client: Client;
  transport: StreamableHTTPClientTransport;
}>;

type AddressCacheEntry = Readonly<{
  addresses?: readonly string[];
  expiresAt?: number;
  pending?: Promise<readonly string[]>;
}>;

export class McpHttpUpstreamTransport implements UpstreamTransport {
  private readonly sessions = new Map<string, ClientSession>();
  private readonly opening = new Map<string, Promise<ClientSession>>();
  private readonly fetchImpl: FetchLike;
  private readonly resolveAddresses: ResolveAddresses;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly addressCacheTtlMs: number;
  private readonly now: () => number;
  private readonly addressCache = new Map<string, AddressCacheEntry>();

  constructor(
    private readonly credentials: OutboundCredentialProvider,
    options: McpHttpUpstreamTransportOptions = {},
  ) {
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.resolveAddresses = options.resolveAddresses ?? resolvePublicAddresses;
    this.timeoutMs = boundedOption(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
    this.maxResponseBytes = boundedOption(options.maxResponseBytes ?? MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES);
    this.addressCacheTtlMs = boundedOption(
      options.addressCacheTtlMs ?? DEFAULT_ADDRESS_CACHE_TTL_MS,
      MAX_ADDRESS_CACHE_TTL_MS,
    );
    this.now = options.now ?? Date.now;
  }

  static fromSecretResolver(
    resolver: SecretCredentialResolver,
    options?: McpHttpUpstreamTransportOptions,
  ): McpHttpUpstreamTransport {
    return new McpHttpUpstreamTransport(createOutboundCredentialProvider(resolver), options);
  }

  async discover(upstream: UpstreamConfig): Promise<unknown> {
    const session = await this.clientFor(upstream);
    try {
      return await session.client.listTools();
    } catch (error: unknown) {
      await this.closeFailedSession(upstream, session);
      throw toAdapterError(error);
    }
  }

  async call(upstream: UpstreamConfig, toolName: string, input: unknown): Promise<unknown> {
    if (!isRecord(input)) {
      throw new GatewayError("INVALID_INPUT", "managed proxy input rejected safely");
    }
    const session = await this.clientFor(upstream);
    try {
      return await session.client.callTool({ name: toolName, arguments: input });
    } catch (error: unknown) {
      await this.closeFailedSession(upstream, session);
      throw toAdapterError(error);
    }
  }

  async close(upstream: UpstreamConfig): Promise<void> {
    const session = this.sessions.get(upstream.upstreamId);
    if (session === undefined) {
      return;
    }
    this.sessions.delete(upstream.upstreamId);
    try {
      await session.client.close();
    } catch (error: unknown) {
      throw toAdapterError(error);
    }
  }

  private async clientFor(upstream: UpstreamConfig): Promise<ClientSession> {
    if (upstream.transport !== "streamable-http") {
      throw new GatewayError("ADAPTER_FAILED", "stdio upstream transport is unavailable safely");
    }
    const existing = this.sessions.get(upstream.upstreamId);
    if (existing !== undefined) {
      return existing;
    }
    const pending = this.opening.get(upstream.upstreamId);
    if (pending !== undefined) {
      return pending;
    }
    const opening = this.open(upstream);
    this.opening.set(upstream.upstreamId, opening);
    try {
      const session = await opening;
      this.sessions.set(upstream.upstreamId, session);
      return session;
    } finally {
      this.opening.delete(upstream.upstreamId);
    }
  }

  private async open(upstream: UpstreamConfig): Promise<ClientSession> {
    let endpoint: URL;
    try {
      endpoint = new URL(upstream.endpointOrCommandRef);
    } catch {
      throw new GatewayError("INVALID_INPUT", "upstream destination rejected safely");
    }
    const validated = validateHttpsDestination(endpoint.toString(), [endpoint.hostname]);
    await this.resolveValidatedAddresses(validated.hostname).catch((error: unknown) => {
      if (error instanceof GatewayError) {
        throw error;
      }
      throw new GatewayError("ADAPTER_FAILED", "upstream destination is unavailable safely");
    });

    const credential = upstream.credentialRef === undefined
      ? undefined
      : await this.credentials.resolve(upstream.credentialRef);
    const transportOptions: StreamableHTTPClientTransportOptions = {
      fetch: this.fetchFor(validated.hostname),
      requestInit: credential === undefined
        ? undefined
        : { headers: { authorization: `Bearer ${credential}` } },
    };
    const transport = new StreamableHTTPClientTransport(validated, transportOptions);
    const client = new Client({ name: "apex-managed-mcp-proxy", version: "0.1.0" });
    try {
      await client.connect(transport);
    } catch (error: unknown) {
      await transport.close().catch(() => undefined);
      throw toAdapterError(error);
    }
    return { client, transport };
  }

  private fetchFor(hostname: string): FetchLike {
    return async (url, init = {}) => {
      const endpoint = validateHttpsDestination(String(url), [hostname]);
      await this.resolveValidatedAddresses(endpoint.hostname).catch((error: unknown) => {
        if (error instanceof GatewayError) {
          throw error;
        }
        throw new GatewayError("ADAPTER_FAILED", "upstream destination is unavailable safely");
      });
      enforceRequestSize(init.body);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const signal = init.signal;
      const abort = () => controller.abort(signal?.reason);
      signal?.addEventListener("abort", abort, { once: true });
      try {
        const response = await this.fetchImpl(url, {
          ...init,
          redirect: "error",
          signal: controller.signal,
        });
        return limitResponse(response, this.maxResponseBytes);
      } catch (error: unknown) {
        throw toAdapterError(error);
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
      }
    };
  }

  private async closeFailedSession(upstream: UpstreamConfig, session: ClientSession): Promise<void> {
    if (this.sessions.get(upstream.upstreamId) !== session) {
      return;
    }
    this.sessions.delete(upstream.upstreamId);
    await session.client.close().catch(() => undefined);
  }

  private async resolveValidatedAddresses(hostname: string): Promise<readonly string[]> {
    const now = this.now();
    const cached = this.addressCache.get(hostname);
    if (cached?.addresses !== undefined && cached.expiresAt !== undefined && cached.expiresAt > now) {
      return cached.addresses;
    }
    if (cached?.pending !== undefined) {
      return cached.pending;
    }

    const pending = this.resolveAddresses(hostname).then((addresses) => {
      validateResolvedAddresses(hostname, addresses);
      const safeAddresses = Object.freeze([...addresses]);
      this.addressCache.set(hostname, {
        addresses: safeAddresses,
        expiresAt: this.now() + this.addressCacheTtlMs,
      });
      return safeAddresses;
    });
    this.addressCache.set(hostname, { pending });
    pending.catch(() => {
      if (this.addressCache.get(hostname)?.pending === pending) {
        this.addressCache.delete(hostname);
      }
    });
    return pending;
  }
}

async function resolvePublicAddresses(hostname: string): Promise<readonly string[]> {
  const records = await lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

function enforceRequestSize(body: BodyInit | null | undefined): void {
  if (typeof body === "string" && Buffer.byteLength(body, "utf8") > MAX_REQUEST_BYTES) {
    throw new GatewayError("INVALID_INPUT", "upstream request exceeded its safe bound");
  }
  if (body instanceof Uint8Array && body.byteLength > MAX_REQUEST_BYTES) {
    throw new GatewayError("INVALID_INPUT", "upstream request exceeded its safe bound");
  }
}

function limitResponse(response: Response, maxBytes: number): Response {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > maxBytes) {
      throw new GatewayError("ADAPTER_FAILED", "upstream response exceeded its safe bound");
    }
  }
  if (response.status >= 300 && response.status < 400) {
    throw new GatewayError("ADAPTER_FAILED", "upstream redirect rejected safely");
  }
  if (response.body === null) {
    return response;
  }
  let totalBytes = 0;
  const limitedBody = response.body.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        totalBytes += chunk.byteLength;
        if (totalBytes > maxBytes) {
          controller.error(new GatewayError("ADAPTER_FAILED", "upstream response exceeded its safe bound"));
          return;
        }
        controller.enqueue(chunk);
      },
    }),
  );
  return new Response(limitedBody, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

function boundedOption(value: number, max: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new GatewayError("INVALID_INPUT", "upstream transport limits rejected safely");
  }
  return value;
}

function toAdapterError(error: unknown): GatewayError {
  if (error instanceof GatewayError) {
    return error;
  }
  return new GatewayError("ADAPTER_FAILED", "managed proxy upstream failed safely");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
