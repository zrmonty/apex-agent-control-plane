import grpc from "@grpc/grpc-js";
import protoLoader from "@grpc/proto-loader";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { GatewayError } from "../contracts.js";
import type { ClientMaterial } from "./secrets.js";

export type DynamicGrpcClient = {
  readonly close: () => void;
  readonly [method: string]: unknown;
};

type UnaryMethod = (
  request: unknown,
  metadata: grpc.Metadata,
  options: grpc.CallOptions,
  callback: (error: grpc.ServiceError | null, response: unknown) => void,
) => void;

type DynamicClientConstructor = new (
  target: string,
  credentials: grpc.ChannelCredentials,
) => DynamicGrpcClient;

export function createGrpcClient(
  protoFile: string,
  serviceName: string,
  endpoint: string,
  material: ClientMaterial,
): DynamicGrpcClient {
  const packageDefinition = protoLoader.loadSync(protoFile, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    oneofs: true,
  });
  const loaded = grpc.loadPackageDefinition(packageDefinition) as unknown as {
    apex: { v1: Record<string, unknown> };
  };
  const constructor = loaded.apex.v1[serviceName] as DynamicClientConstructor | undefined;
  if (constructor === undefined) {
    throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
  }
  return new constructor(
    normalizeTarget(endpoint),
    grpc.credentials.createSsl(material.ca, material.clientKey, material.clientCert),
  );
}

export async function unaryCall(
  client: DynamicGrpcClient,
  methodName: string,
  request: unknown,
  token: string,
  timeoutMs: number,
  failureCode: "GOVERNANCE_UNAVAILABLE" | "EVENT_ADMISSION_FAILED",
): Promise<unknown> {
  const method = client[methodName];
  if (typeof method !== "function") {
    throw new GatewayError(failureCode, "request rejected safely");
  }
  const metadata = new grpc.Metadata();
  metadata.set("authorization", `Bearer ${token}`);
  const deadline = new Date(Date.now() + timeoutMs);
  return new Promise((resolve, reject) => {
    (method as UnaryMethod).call(
      client,
      request,
      metadata,
        { deadline },
      (error, response) => {
        if (error !== null) {
          if (process.env.APEX_MCP_DEBUG_LIVE_ERRORS === "1") {
            console.error(`mcp live ${failureCode} grpc-status-${error.code}`);
          }
          const explanation =
            process.env.APEX_MCP_DEBUG_LIVE_ERRORS === "1"
              ? `grpc-status-${error.code}`
              : "request rejected safely";
          reject(new GatewayError(failureCode, explanation));
          return;
        }
        resolve(response);
      },
    );
  });
}

export function protoPath(name: "governance.proto" | "event.proto"): string {
  const current = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(current, "../../../../contracts/proto/apex/v1", name);
}

function normalizeTarget(endpoint: string): string {
  const value = endpoint.trim();
  if (!value.includes("://")) {
    return value;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
  }
  if (!/^https?:$/.test(parsed.protocol) || parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
  }
  return parsed.host;
}
