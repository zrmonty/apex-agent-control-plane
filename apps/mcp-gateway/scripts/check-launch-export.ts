/** Explicit local Task 1 parity gate. No producer authority or runtime effects.
 * Requires Rust's scoped export and the original runtime fixture independently.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { createHash } from "node:crypto";
import { fromJson, toJson, type JsonObject, type JsonValue } from "@bufbuild/protobuf";
import { RuntimeLaunchContextSchema } from "@apex/contracts";
import { parseRuntimeConfiguration } from "../src/managed/runtime-config.js";
import { parseRuntimeLaunchContext } from "../src/managed/launch-context.js";

const directory = process.env.APEX_LAUNCH_EXPORT_DIR;
const runtimePath = process.env.APEX_RUNTIME_FIXTURE_PATH;
assert.ok(directory && isAbsolute(directory), "absolute Rust launch export directory required");
assert.ok(runtimePath && isAbsolute(runtimePath), "original Rust runtime fixture required");
const config = parseRuntimeConfiguration(readFileSync(runtimePath, "utf8"));
const exportedConfig = parseRuntimeConfiguration(readFileSync(join(directory, "runtime-revision.json"), "utf8"));
assert.deepEqual(exportedConfig, config, "export retains the actual runtime artifact");
const text = readFileSync(join(directory, "launch-context.json"), "utf8");
const launch = parseRuntimeLaunchContext(text, config);
assert.equal(launch.target?.fencingToken, 9007199254740993n);
assert.equal(launch.target?.generation, config.generation);
assert.equal(launch.materials.length, 13);
assert.equal(new Set(launch.materials.map(m => m.role)).size, 13);
assert.equal(launch.health?.port, 8081);
assert.equal(launch.processInstanceId, "0191b7f1-7f2c-7c13-9a61-2f29f2be1003");

// Independent canonical digest: generated TS ProtoJSON and Node crypto, never
// the production launchContextHash function. Preserve bigint decimal strings.
function sort(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort((a, b) =>
      Buffer.compare(Buffer.from(a), Buffer.from(b))).map(key => [key, sort(value[key])]));
  }
  return value;
}
const generated = toJson(RuntimeLaunchContextSchema,
  fromJson(RuntimeLaunchContextSchema, JSON.parse(text))) as JsonObject;
delete generated.launchContextHash;
const digest = createHash("sha256").update(JSON.stringify(sort(generated))).digest("hex");
assert.equal(launch.launchContextHash, digest);
console.log("PASS Rust launch export: real TS parser, 13 roles, exact >2^53 fence, independent digest");
