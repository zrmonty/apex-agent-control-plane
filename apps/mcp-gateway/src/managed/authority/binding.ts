import { GatewayError } from "../../contracts.js";
import type { DeploymentBinding, GrantReply } from "./types.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const SCOPE = /^[A-Za-z0-9_.:-]{1,256}$/;
const KEYS = ["installationId", "workspaceId", "namespaceId", "proxyId", "revisionId",
  "generation", "fencingToken", "processInstanceId", "configHash", "launchContextHash"] as const;
export const MAX_GRANT_US = 10_000_000n;
export function uint64(value: unknown): value is bigint {
  return typeof value === "bigint" && value > 0n && value <= 18_446_744_073_709_551_615n;
}
export function nonce(value: unknown): value is string { return typeof value === "string" && HASH.test(value); }
export function immutableBinding(value: DeploymentBinding): DeploymentBinding {
  try {
    if (!value || Object.keys(value).length !== KEYS.length || KEYS.some(k => !Object.hasOwn(value, k)) ||
      ![value.installationId, value.proxyId, value.revisionId, value.processInstanceId].every(v => typeof v === "string" && UUID.test(v)) ||
      ![value.workspaceId, value.namespaceId].every(v => typeof v === "string" && SCOPE.test(v) && !v.includes("..")) ||
      ![value.configHash, value.launchContextHash].every(nonce) ||
      !uint64(value.generation) || !uint64(value.fencingToken)) throw new Error();
    return Object.freeze({ ...value });
  } catch { throw new GatewayError("INVALID_INPUT", "deployment grant binding rejected safely"); }
}
export function validReply(reply: GrantReply, binding: DeploymentBinding, expectedNonce: string, sequence: bigint): boolean {
  try {
    const actual = immutableBinding(reply.binding);
    return KEYS.every(k => actual[k] === binding[k]) && reply.nonce === expectedNonce &&
      uint64(reply.renewalSequence) && reply.renewalSequence === sequence &&
      typeof reply.decisionId === "string" && UUID.test(reply.decisionId) && uint64(reply.epoch) &&
      ["prepare", "serve", "closed"].includes(reply.mode) && typeof reply.validForUs === "bigint" &&
      reply.validForUs > 0n && reply.validForUs <= MAX_GRANT_US;
  } catch { return false; }
}
