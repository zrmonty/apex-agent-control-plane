import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { RuntimeConfigurationSchema, decodeStrict } from "@apex/contracts";
import { fromJson, toJson, type JsonObject, type JsonValue } from "@bufbuild/protobuf";

import { GatewayError } from "../../contracts.js";

const path = process.env.APEX_RUNTIME_FIXTURE_PATH;
assert.ok(path, "APEX_RUNTIME_FIXTURE_PATH must identify the actual Rust-exported artifact; no fallback fixture");
export const artifactPath = path;
export const artifactText = readFileSync(path, "utf8");
export const artifactSha256 = createHash("sha256").update(artifactText).digest("hex");
export const rustManifestHash = "db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da";

export function object(value: JsonValue | undefined): JsonObject {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value));
  return value;
}

export function source(): JsonObject {
  return object(JSON.parse(artifactText) as JsonValue);
}

export function message() {
  return decodeStrict(RuntimeConfigurationSchema, artifactText);
}

export function field(value: JsonValue, pointer: string): JsonValue {
  for (const part of pointer.split("/").slice(1)) {
    const next = Array.isArray(value) ? value[Number(part)] : object(value)[part];
    assert.notEqual(next, undefined, `fixture field missing: ${pointer}`);
    value = next;
  }
  return value;
}

export function setField(value: JsonObject, pointer: string, replacement: JsonValue | undefined): void {
  const parts = pointer.split("/").slice(1);
  const key = parts.pop();
  assert.notEqual(key, undefined);
  const parent = parts.length ? field(value, "/" + parts.join("/")) : value;
  if (Array.isArray(parent)) {
    assert.ok(replacement !== undefined, "use whole-array edits to remove entries");
    parent[Number(key)] = replacement;
  } else if (replacement === undefined) {
    delete object(parent)[key!];
  } else {
    object(parent)[key!] = replacement;
  }
}

export function leaves(value: JsonValue, pointer = ""): [string, JsonValue][] {
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, nested]) => leaves(nested, `${pointer}/${key}`));
  }
  return [[pointer, value]];
}

function sorted(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  }
  return value;
}

/** Independent Node reference, never the production hash under test. Generated
 * serialization ensures explicit defaults do not make malformed-config tests
 * pass accidentally because of a different digest representation.
 */
export function resign(value: JsonObject): JsonObject {
  const generated = object(toJson(RuntimeConfigurationSchema, fromJson(RuntimeConfigurationSchema, value)));
  delete generated.runtimeManifestHash;
  value.runtimeManifestHash = createHash("sha256").update(JSON.stringify(sorted(generated))).digest("hex");
  return value;
}

export function rejectsSafely(action: () => unknown, label = "invalid configuration"): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof GatewayError, label);
    assert.equal(error.code, "INVALID_INPUT", label);
    assert.equal(error.message, "INVALID_INPUT: managed runtime configuration rejected safely", label);
    assert.equal((error as Error & { cause?: unknown }).cause, undefined, label);
    assert.ok(!JSON.stringify(error).includes("SENSITIVE"), label);
    return true;
  }, label);
}

export function assertFrozen(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  assert.ok(Object.isFrozen(value));
  for (const child of Object.values(value)) assertFrozen(child);
}
