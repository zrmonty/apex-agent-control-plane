import type { LoadedManagedStage } from "../stage-reader.js";
import type { SealedStageSelection } from "./environment.js";
import { types } from "node:util";
import { createHash } from "node:crypto";
import { record } from "../call-preparation/boundary.js";
import { assertDataTree, freezeTree } from "../runtime-config/boundary.js";
import { parseRuntimeConfiguration, type DeepReadonly } from "../runtime-config.js";
import { parseRuntimeLaunchContext } from "../launch-context.js";
import { immutableBinding } from "../authority/binding.js";
import { options as stageOptions } from "../stage-reader/validation.js";
import { parseWireJson } from "../upstream-wire/json.js";
import { parseManagedIngressProfile } from "./ingress-profile.js";

const refused = () => new Error("managed stage documents rejected");
const prototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLength = Object.getOwnPropertyDescriptor(prototype, "byteLength")!.get!;
const backingBuffer = Object.getOwnPropertyDescriptor(prototype, "buffer")!.get!;
function requireValue(value: unknown): asserts value { if (!value) throw refused(); }
function exact(value: unknown, keys: readonly string[]) {
  const result = record(value, keys); requireValue(Object.keys(result).length === keys.length); return result;
}
function identifier(value: unknown): string {
  requireValue(typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(value) && !value.includes("..")); return value;
}
function metadataBytes(value: unknown, cap: number): Buffer {
  requireValue(!types.isProxy(value) && types.isUint8Array(value));
  const length: number = byteLength.call(value);
  requireValue(length >= 1 && length <= cap && !types.isSharedArrayBuffer(backingBuffer.call(value)));
  const copy = Buffer.alloc(length); Uint8Array.prototype.set.call(copy, value); return copy;
}
function text(bytes: Buffer): string { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }

/** Consistency of reader-owned documents only. This cannot authenticate a caller-
 * supplied LoadedManagedStage; the production root must own the actual reader.
 * No secret-content read, I/O, credential factory or authority is performed here. */
export function parseManagedStageDocuments(stage: Pick<LoadedManagedStage, "files" | "manifestSha256">, selection: SealedStageSelection) {
  try {
    assertDataTree(selection, false);
    exact(selection, ["installationId", "expectedManifestSha256", "toolSecretReferences"]);
    const inventory = stageOptions({ ...selection, onFatal() {} }).names;
    const loaded = record(stage, ["files", "manifestSha256", "dispose"]);
    requireValue(loaded.manifestSha256 === selection.expectedManifestSha256);
    const files = exact(loaded.files, [...inventory.keys()]);
    const config = parseRuntimeConfiguration(text(metadataBytes(files["runtime-revision.json"], 262144)));
    const launch = parseRuntimeLaunchContext(text(metadataBytes(files["launch-context.json"], 16384)), config);
    const target = launch.target!;
    const binding = immutableBinding({ installationId: selection.installationId,
      workspaceId: target.workspaceId, namespaceId: target.namespaceId, proxyId: target.proxyId, revisionId: target.revisionId,
      generation: target.generation, fencingToken: target.fencingToken, processInstanceId: launch.processInstanceId,
      configHash: launch.configHash, launchContextHash: launch.launchContextHash });
    requireValue(JSON.stringify([...config.secretRefs].sort()) === JSON.stringify([...selection.toolSecretReferences].sort()));
    const authority = parseManagedIngressProfile(metadataBytes(files["authority-profile.json"], 16384), { config, launch, binding });
    const toolsBytes = metadataBytes(files["tool-bindings.json"], 65536), raw = parseWireJson(toolsBytes);
    // This file is emitted by the agent's compact serializer, never user edited.
    // Requiring that form also rejects float/exponent spellings of schema_version.
    requireValue(JSON.stringify(raw) === text(toolsBytes)); assertDataTree(raw, false);
    const t = exact(raw, ["schema_version", "catalog_version", "installation_id", "workspace_id", "namespace_id",
      "proxy_id", "revision_id", "config_hash", "host_policy_version", "deployment_bindings_version", "entries"]);
    requireValue(t.schema_version === 1 && t.installation_id === binding.installationId && t.workspace_id === binding.workspaceId &&
      t.namespace_id === binding.namespaceId && t.proxy_id === binding.proxyId && t.revision_id === binding.revisionId &&
      t.config_hash === binding.configHash && t.host_policy_version === authority.profile.host_policy_version &&
      Array.isArray(t.entries) && t.entries.length === config.secretRefs.length);
    const remaining = new Set(config.secretRefs);
    const entries = t.entries.map(value => {
      const entry = exact(value, ["reference", "version", "filename"]);
      requireValue(typeof entry.reference === "string" && remaining.delete(entry.reference));
      const filename = `tool-${createHash("sha256").update(entry.reference).digest("hex")}`;
      requireValue(entry.filename === filename && Object.hasOwn(files, filename));
      return { reference: entry.reference, version: identifier(entry.version), filename };
    });
    requireValue(remaining.size === 0);
    const tools = { schema_version: 1 as const, catalog_version: identifier(t.catalog_version), installation_id: binding.installationId,
      workspace_id: binding.workspaceId, namespace_id: binding.namespaceId, proxy_id: binding.proxyId, revision_id: binding.revisionId,
      config_hash: binding.configHash, host_policy_version: authority.profile.host_policy_version,
      deployment_bindings_version: identifier(t.deployment_bindings_version), entries };
    const result = { config, launch, binding, authority, tools };
    return freezeTree(result) as DeepReadonly<typeof result>;
  } catch { throw refused(); }
}
export type ManagedStageDocuments = ReturnType<typeof parseManagedStageDocuments>;
