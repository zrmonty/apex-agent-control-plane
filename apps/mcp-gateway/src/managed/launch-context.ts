/** Pure metadata/cross-binding boundary, not an authenticated launch owner.
 * Callers can compute a self-consistent digest. Task 7 must establish trusted
 * provenance, current fence/lease, approved image/profile and actual material;
 * Tasks 8/13 still own operational enforcement. This module performs no I/O. */
import { createHash } from "node:crypto";
import {
  RuntimeConfigurationSchema, RuntimeLaunchContextSchema, RuntimeMaterialRole,
  decodeStrict, encodeJson, type RuntimeConfiguration, type RuntimeLaunchContext,
} from "@apex/contracts";
import type { JsonObject, JsonValue } from "@bufbuild/protobuf";
import { GatewayError } from "../contracts.js";
import { parseRuntimeConfiguration, type DeepReadonly, type ReadonlyRuntimeConfiguration } from "./runtime-config.js";
import {
  assertDataTree, assertMessage, freezeTree, hash, identifier, reference, requireValue,
} from "./runtime-config/boundary.js";

export type ReadonlyRuntimeLaunchContext = DeepReadonly<RuntimeLaunchContext>;
const MAX_LAUNCH_BYTES = 16 * 1024;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Keep original text for duplicate/alias detection. The supplied config is
 * defensively revalidated; neither its type nor a valid hash confers trust. */
export function parseRuntimeLaunchContext(input: unknown, config: ReadonlyRuntimeConfiguration): ReadonlyRuntimeLaunchContext {
  try {
    if (typeof input === "string") {
      requireValue(input.length <= MAX_LAUNCH_BYTES && Buffer.byteLength(input, "utf8") <= MAX_LAUNCH_BYTES);
    }
    // Also validates raw UTF-16. For objects this bounds shared-graph expansion
    // to the existing conservative 256 KiB ceiling before any codec allocation.
    assertDataTree(input, false);
    assertDataTree(config, true);
    assertMessage(RuntimeConfigurationSchema, config);
    const strictConfig = parseRuntimeConfiguration(encodeJson(RuntimeConfigurationSchema, config as RuntimeConfiguration));
    const context = decodeStrict(RuntimeLaunchContextSchema, input as JsonValue | string);
    const digest = launchContextHash(context); // Includes decoded Unicode and encoded-size checks.
    validateMetadata(context, strictConfig);
    requireValue(digest === context.launchContextHash);
    return freezeTree(context);
  } catch {
    throw rejected();
  }
}

/** Hash generated ProtoJSON, omitting only its own digest. This checks safe
 * generated shape/size, not metadata validity or authority. Array order matters. */
export function launchContextHash(context: ReadonlyRuntimeLaunchContext): string {
  try {
    assertDataTree(context, true);
    assertMessage(RuntimeLaunchContextSchema, context);
    const json = encodeJson(RuntimeLaunchContextSchema, context as RuntimeLaunchContext) as JsonObject;
    requireValue(Buffer.byteLength(JSON.stringify(json), "utf8") <= MAX_LAUNCH_BYTES);
    delete json.launchContextHash;
    return createHash("sha256").update(sortedJson(json), "utf8").digest("hex");
  } catch {
    throw rejected();
  }
}

function validateMetadata(context: RuntimeLaunchContext, config: ReadonlyRuntimeConfiguration): void {
  requireValue(context.schemaVersion === 1);
  const target = context.target;
  requireValue(target && target.generation > 0n && target.fencingToken > 0n);
  requireValue(target.workspaceId === config.workspaceId && target.namespaceId === config.namespaceId);
  requireValue(target.proxyId === config.proxyId && target.revisionId === config.revisionId);
  requireValue(target.generation === config.generation);
  requireValue(hash(context.configHash) && context.configHash === config.configHash);
  requireValue(hash(context.runtimeManifestHash) && context.runtimeManifestHash === config.runtimeManifestHash);
  requireValue(hash(context.launchContextHash) && context.imageRef === config.imageRef);
  requireValue(UUID_V7.test(context.processInstanceId));
  requireValue(identifier(context.authorityProfileRef, 128) && identifier(context.authorityProfileVersion, 128));
  const health = context.health;
  requireValue(health && health.port === 8081);
  reference(health.credentialRef, "secret://");
  requireValue(context.materials.length >= 1 && context.materials.length <= 13);
  const roles = new Set<RuntimeMaterialRole>();
  const revisionSecrets = new Set(config.secretRefs);
  for (const material of context.materials) {
    // Known enum membership was checked by the generated descriptor boundary.
    requireValue(material.role !== RuntimeMaterialRole.UNSPECIFIED && !roles.has(material.role));
    roles.add(material.role);
    reference(material.reference, "secret://");
    requireValue(identifier(material.version, 128) && !revisionSecrets.has(material.reference));
    if (material.role === RuntimeMaterialRole.HEALTH_TOKEN) requireValue(material.reference === health.credentialRef);
    else requireValue(material.reference !== health.credentialRef);
  }
  requireValue(roles.has(RuntimeMaterialRole.HEALTH_TOKEN));
  // Other role completeness/sharing policy belongs to the trusted profile owner.
}

/** Same recursive bytewise key ordering as the runtime manifest boundary.
 * Generated fields have ASCII keys; strings remain opaque JSON string values. */
function sortedJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return `{${keys.map(key => `${JSON.stringify(key)}:${sortedJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "managed launch context rejected safely");
}
