/** Generated runtime contract boundary; integration remains owned by startup.
 * Keep original JSON text until decoding so duplicate keys remain observable.
 * A manifest digest establishes integrity, not publication or runtime authority.
 * configHash remains the immutable control-plane digest; runtimeManifestHash
 * binds the generated deployment fields and excludes only itself.
 */
import { createHash } from "node:crypto";
import { RuntimeConfigurationSchema, decodeStrict, encodeJson, type RuntimeConfiguration } from "@apex/contracts";
import type { JsonObject, JsonValue } from "@bufbuild/protobuf";

import { assertDataTree, assertMessage, freezeTree, rejected } from "./runtime-config/boundary.js";
import { validateMetadata } from "./runtime-config/validation.js";

/** Readonly view over generated types, without a second wire model. */
export type DeepReadonly<T> = T extends readonly (infer Element)[]
  ? readonly DeepReadonly<Element>[]
  : T extends object
    ? { readonly [Key in keyof T]: DeepReadonly<T[Key]> }
    : T;

export type ReadonlyRuntimeConfiguration = DeepReadonly<RuntimeConfiguration>;

/** Trusted provisioning must supply a published revision and approved catalog/
 * policy bindings. This pure consumer cannot establish that provenance, resolve
 * secrets, authorize profiles, or grant network/container privileges (Task 6+).
 * The generated decoder allocates a fresh message; no old runtime-model adapter.
 */
export function parseRuntimeConfiguration(input: unknown): ReadonlyRuntimeConfiguration {
  try {
    if (typeof input !== "string") assertDataTree(input, false);
    // Do not JSON.parse text first: decodeStrict must see duplicate/alias keys.
    const config = decodeStrict(RuntimeConfigurationSchema, input as JsonValue | string);
    validateMetadata(config);
    if (runtimeManifestHash(config) !== config.runtimeManifestHash) throw rejected();
    return freezeTree(config);
  } catch {
    throw rejected();
  }
}

/** Hash generated ProtoJSON, sorting object keys and excluding only its hash.
 * All boundary/encoding failures use the same static GatewayError.
 */
export function runtimeManifestHash(config: ReadonlyRuntimeConfiguration): string {
  try {
    assertDataTree(config, true);
    assertMessage(RuntimeConfigurationSchema, config);
    // The codec only reads this view. Its generated output is a separate JSON
    // tree; descriptor checks above prevent silently dropping hidden properties.
    const json = encodeJson(RuntimeConfigurationSchema, config as RuntimeConfiguration) as JsonObject;
    delete json.runtimeManifestHash;
    return createHash("sha256").update(sortedJson(json), "utf8").digest("hex");
  } catch {
    throw rejected();
  }
}

/** Emit sorted keys directly, so integer-looking object keys also stay sorted.
 * Generated field names are ASCII; UTF-8 comparison matches Rust string order.
 * Schema bodies remain untouched strings, not a second canonical JSON format.
 */
function sortedJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(sortedJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return `{${keys.map(key => `${JSON.stringify(key)}:${sortedJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
