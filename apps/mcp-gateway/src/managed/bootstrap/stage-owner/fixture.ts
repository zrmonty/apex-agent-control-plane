import { documentsFixture } from "../stage-documents-fixture.js";
import { deferred, FakeTime } from "../../stage-reader/fixture.js";
import type { LoadedManagedStage, ManagedStageLoadOptions } from "../../stage-reader.js";

export function ownerFixture() {
  const f = documentsFixture(), time = new FakeTime(), gate = {};
  const env = { NODE_ENV: "production", HOME: "/tmp/apex", APEX_MCP_PROFILE: "managed",
    APEX_MCP_GOVERNANCE_MODE: "live", APEX_RUNTIME_CONFIG_FILE: "/apex/runtime/runtime-revision.json",
    APEX_RUNTIME_LAUNCH_FILE: "/apex/runtime/launch-context.json", APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v1",
    APEX_INSTALLATION_ID: f.selection.installationId, APEX_STAGE_MANIFEST_SHA256: f.selection.expectedManifestSha256,
    APEX_TOOL_SECRET_REFERENCES: JSON.stringify(f.selection.toolSecretReferences) };
  const result = deferred<LoadedManagedStage>(), closed = deferred<void>();
  const counts = { loads: 0, cancels: 0, disposals: 0, fatals: 0 };
  let options: ManagedStageLoadOptions | undefined;
  const material = Object.freeze({ ...f.stage, dispose() {
    counts.disposals++;
    for (const bytes of Object.values(f.stage.files)) Uint8Array.prototype.fill.call(bytes, 0);
  } });
  const load = (input: ManagedStageLoadOptions) => {
    counts.loads++; options = input;
    return { result: result.promise, closed: closed.promise, cancel() { counts.cancels++; } };
  };
  return { ...f, env, time, gate, result, closed, counts, material, load,
    options: () => options!, onFatal() { counts.fatals++; } };
}
export const tick = () => new Promise<void>(resolve => setImmediate(resolve));
export const isStatic = (error: unknown) => error instanceof Error &&
  error.message === "managed stage bootstrap rejected" && error.cause === undefined;
