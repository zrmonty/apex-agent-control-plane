/** @deprecated Dormant CLI component fixture only. Production startup and the
 * active managed chain use runtime-config.ts and generated nested types. This
 * legacy parser is never a fallback for a supplied generated configuration. */
import { z } from "zod";

import { GatewayError } from "../contracts.js";

const MAX_IDENTIFIER_LENGTH = 128;
const MAX_ENDPOINT_LENGTH = 512;
const MAX_UPSTREAMS = 64;
const MAX_EXPOSED_TOOLS = 256;
const MAX_CLI_PROFILES = 32;
const MAX_AUTH_BINDINGS = 32;
const MAX_ORIGINS = 32;
const MAX_SECRET_REFS = 32;
const MAX_ARGV = 64;
const MAX_ARG_SCHEMA_FIELDS = 64;
const MAX_ENVIRONMENT_NAMES = 64;
const MAX_EXIT_CODES = 32;
const MAX_TIMEOUT_MS = 300_000;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_MEMORY_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_PID_LIMIT = 1_024;
const identifier = z
  .string()
  .min(1)
  .max(MAX_IDENTIFIER_LENGTH)
  .regex(/^[a-z0-9][a-z0-9._:-]*$/);
const uuidV7 = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const configHash = z.string().regex(/^[0-9a-f]{64}$/);
const imageDigest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const capabilityName = z.string().min(1).max(64).regex(/^[A-Z0-9_-]+$/);
const secretRef = z
  .string()
  .min("secret://".length + 1)
  .max(MAX_ENDPOINT_LENGTH)
  .regex(/^secret:\/\/[A-Za-z0-9][A-Za-z0-9._:/-]*$/);
const safeReference = z
  .string()
  .min(1)
  .max(MAX_ENDPOINT_LENGTH)
  .refine((value) => !value.includes("..") && !/[\u0000-\u001f\u007f]/.test(value));
const boundedText = z
  .string()
  .min(1)
  .max(MAX_ENDPOINT_LENGTH)
  .refine((value) => !/[\u0000-\u001f\u007f]/.test(value));
const origin = z
  .string()
  .url()
  .max(MAX_ENDPOINT_LENGTH)
  .refine((value) => value.startsWith("https://"));
const fixedArgv = z
  .array(z.string().max(256).refine((value) => !/[\u0000-\u001f\u007f]/.test(value)))
  .max(MAX_ARGV);
const secretRefs = z.array(secretRef).max(MAX_SECRET_REFS);

const ingressSchema = z
  .object({
    transport: z.enum(["stdio", "streamable-http"]),
    endpoint: origin.optional(),
    allowedOrigins: z.array(origin).max(MAX_ORIGINS),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.transport === "streamable-http" && value.endpoint === undefined) {
      context.addIssue({ code: "custom", path: ["endpoint"], message: "endpoint required" });
    }
    if (value.transport === "stdio" && value.endpoint !== undefined) {
      context.addIssue({ code: "custom", path: ["endpoint"], message: "endpoint forbidden" });
    }
  });

const upstreamSchema = z
  .object({
    upstreamId: identifier,
    transport: z.enum(["stdio", "streamable-http"]),
    endpointOrCommandRef: safeReference,
    credentialRef: secretRef.optional(),
  })
  .strict();

const exposedToolSchema = z
  .object({
    upstreamId: identifier,
    toolName: boundedText,
    alias: identifier,
    classification: z.enum(["read", "business-write", "high-impact"]),
  })
  .strict();

const argvFieldSchema = z
  .object({ name: identifier, required: z.boolean() })
  .strict();
const argvSchema = z
  .object({ fields: z.array(argvFieldSchema).max(MAX_ARG_SCHEMA_FIELDS) })
  .strict();

const cliProfileSchema = z
  .object({
    profileId: identifier,
    executableRef: safeReference,
    executableDigest: imageDigest,
    fixedArgv,
    argvSchema,
    environmentAllowlist: z.array(identifier).max(MAX_ENVIRONMENT_NAMES),
    secretRefs,
    workingDirectory: z
      .string()
      .regex(/^\/tmp\/[a-z0-9][a-z0-9._/-]*$/)
      .max(MAX_ENDPOINT_LENGTH),
    filesystemPolicy: z.literal("read-only"),
    networkPolicy: z.literal("declared-egress"),
    shell: z.literal(false),
    timeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS),
    maxOutputBytes: z.number().int().min(1).max(MAX_OUTPUT_BYTES),
    allowedExitCodes: z.array(z.number().int().min(0).max(255)).max(MAX_EXIT_CODES),
  })
  .strict()
  .refine((value) => new Set(value.argvSchema.fields.map((field) => field.name)).size === value.argvSchema.fields.length);

const authBindingSchema = z
  .object({
    bindingId: identifier,
    direction: z.enum(["inbound", "outbound"]),
    credentialRef: secretRef.optional(),
    audience: identifier.optional(),
    issuer: origin.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.direction === "outbound" && value.credentialRef === undefined) {
      context.addIssue({ code: "custom", path: ["credentialRef"], message: "credential required" });
    }
    if (value.direction === "inbound" && value.credentialRef !== undefined) {
      context.addIssue({ code: "custom", path: ["credentialRef"], message: "inbound credential forbidden" });
    }
  });

const governanceSchema = z
  .object({
    policyId: identifier,
    approvalMode: z.enum(["none", "operator", "dual-operator"]),
    classification: z.enum(["public", "internal", "confidential", "restricted"]),
  })
  .strict();

const runtimeSchema = z
  .object({
    imageDigest,
    cpuMillis: z.number().int().min(1).max(4_000),
    memoryBytes: z.number().int().min(16 * 1024 * 1024).max(MAX_MEMORY_BYTES),
    pidLimit: z.number().int().min(16).max(MAX_PID_LIMIT),
    readOnlyRootfs: z.literal(true),
    networkMode: z.enum(["isolated", "declared-egress"]),
    noNewPrivileges: z.literal(true),
    droppedCapabilities: z.array(capabilityName).min(1).max(64),
  })
  .strict()
  .refine((value) => value.droppedCapabilities.includes("ALL"));

const proxyRevisionConfigSchema = z
  .object({
    proxyId: uuidV7,
    revisionId: uuidV7,
    configHash,
    ingress: ingressSchema,
    upstreams: z.array(upstreamSchema).min(1).max(MAX_UPSTREAMS),
    exposedTools: z.array(exposedToolSchema).min(1).max(MAX_EXPOSED_TOOLS),
    cliProfiles: z.array(cliProfileSchema).max(MAX_CLI_PROFILES),
    authBindings: z.array(authBindingSchema).min(1).max(MAX_AUTH_BINDINGS),
    governance: governanceSchema,
    runtime: runtimeSchema,
  })
  .strict()
  .superRefine((value, context) => {
    addDuplicateIssues(value, context);
    const upstreamIds = new Set(value.upstreams.map((upstream) => upstream.upstreamId));
    value.exposedTools.forEach((tool, index) => {
      if (!upstreamIds.has(tool.upstreamId)) {
        context.addIssue({ code: "custom", path: ["exposedTools", index, "upstreamId"], message: "unknown upstream" });
      }
    });
    const inboundBindings = value.authBindings.filter((binding) => binding.direction === "inbound");
    if (inboundBindings.length !== 1) {
      context.addIssue({ code: "custom", path: ["authBindings"], message: "exactly one inbound binding required" });
    }
  });

export type ProxyRevisionConfig = Readonly<{
  proxyId: string;
  revisionId: string;
  configHash: string;
  ingress: Readonly<{
    transport: "stdio" | "streamable-http";
    endpoint?: string;
    allowedOrigins: readonly string[];
  }>;
  upstreams: readonly Readonly<{
    upstreamId: string;
    transport: "stdio" | "streamable-http";
    endpointOrCommandRef: string;
    credentialRef?: string;
  }>[];
  exposedTools: readonly Readonly<{
    upstreamId: string;
    toolName: string;
    alias: string;
    classification: "read" | "business-write" | "high-impact";
  }>[];
  cliProfiles: readonly Readonly<{
    profileId: string;
    executableRef: string;
    executableDigest: string;
    fixedArgv: readonly string[];
    argvSchema: Readonly<{ fields: readonly Readonly<{ name: string; required: boolean }>[] }>;
    environmentAllowlist: readonly string[];
    secretRefs: readonly string[];
    workingDirectory: string;
    filesystemPolicy: "read-only";
    networkPolicy: "declared-egress";
    shell: false;
    timeoutMs: number;
    maxOutputBytes: number;
    allowedExitCodes: readonly number[];
  }>[];
  authBindings: readonly Readonly<{
    bindingId: string;
    direction: "inbound" | "outbound";
    credentialRef?: string;
    audience?: string;
    issuer?: string;
  }>[];
  governance: Readonly<{
    policyId: string;
    approvalMode: "none" | "operator" | "dual-operator";
    classification: "public" | "internal" | "confidential" | "restricted";
  }>;
  runtime: Readonly<{
    imageDigest: string;
    cpuMillis: number;
    memoryBytes: number;
    pidLimit: number;
    readOnlyRootfs: true;
    networkMode: "isolated" | "declared-egress";
    noNewPrivileges: true;
    droppedCapabilities: readonly string[];
  }>;
}>;

export type UpstreamConfig = ProxyRevisionConfig["upstreams"][number];
export type ExposedTool = ProxyRevisionConfig["exposedTools"][number];

export function parseProxyRevisionConfig(input: unknown): ProxyRevisionConfig {
  try {
    const parsed = proxyRevisionConfigSchema.parse(input) as ProxyRevisionConfig;
    return deepFreeze(parsed);
  } catch {
    throw new GatewayError("INVALID_INPUT", "managed proxy configuration rejected safely");
  }
}

function addDuplicateIssues(
  value: z.infer<typeof proxyRevisionConfigSchema>,
  context: z.RefinementCtx,
): void {
  addDuplicateIssue(value.upstreams.map((item) => item.upstreamId), context, ["upstreams"]);
  addDuplicateIssue(value.exposedTools.map((item) => item.alias), context, ["exposedTools"]);
  addDuplicateIssue(value.cliProfiles.map((item) => item.profileId), context, ["cliProfiles"]);
  addDuplicateIssue(value.authBindings.map((item) => item.bindingId), context, ["authBindings"]);
}

function addDuplicateIssue(
  values: readonly string[],
  context: z.RefinementCtx,
  path: readonly (string | number)[],
): void {
  if (new Set(values).size !== values.length) {
    context.addIssue({ code: "custom", path: [...path], message: "duplicate identity" });
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}
