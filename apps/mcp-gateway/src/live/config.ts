import { GatewayError } from "../contracts.js";

export type LiveGrpcConfig = {
  readonly endpoint: string;
  readonly caFile: string;
  readonly clientCertFile: string;
  readonly clientKeyFile: string;
  readonly tokenFile: string;
};

export type LiveConfig = {
  readonly governance: LiveGrpcConfig;
  readonly events: LiveGrpcConfig;
  readonly trustedSecretBase: string;
};

const GOVERNANCE_FIELDS = [
  "APEX_MCP_GOVERNANCE_ENDPOINT",
  "APEX_MCP_GOVERNANCE_CA_FILE",
  "APEX_MCP_GOVERNANCE_CLIENT_CERT_FILE",
  "APEX_MCP_GOVERNANCE_CLIENT_KEY_FILE",
  "APEX_MCP_GOVERNANCE_TOKEN_FILE",
] as const;
const EVENT_FIELDS = [
  "APEX_MCP_EVENT_ENDPOINT",
  "APEX_MCP_EVENT_CA_FILE",
  "APEX_MCP_EVENT_CLIENT_CERT_FILE",
  "APEX_MCP_EVENT_CLIENT_KEY_FILE",
  "APEX_MCP_EVENT_TOKEN_FILE",
] as const;

export function loadLiveConfig(env: NodeJS.ProcessEnv): LiveConfig {
  const trustedSecretBase = required(env, "APEX_MCP_TRUSTED_SECRET_BASE");
  return {
    trustedSecretBase,
    governance: loadGrpcConfig(env, GOVERNANCE_FIELDS),
    events: loadGrpcConfig(env, EVENT_FIELDS),
  };
}

function loadGrpcConfig(
  env: NodeJS.ProcessEnv,
  fields: readonly [string, string, string, string, string],
): LiveGrpcConfig {
  const values = fields.map((field) => required(env, field));
  const [endpoint, caFile, clientCertFile, clientKeyFile, tokenFile] = values;
  return { endpoint, caFile, clientCertFile, clientKeyFile, tokenFile };
}

function required(env: NodeJS.ProcessEnv, field: string): string {
  const value = env[field];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
  }
  return value.trim();
}
