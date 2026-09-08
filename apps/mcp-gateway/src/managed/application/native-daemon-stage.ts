// Private unsigned fixture entrypoint: stage normally, export only fixed metadata.
import { nativeEnvironment } from "./native-stage.js";
import assert from "node:assert/strict";

const keys = ["NODE_ENV", "HOME", "APEX_MCP_PROFILE", "APEX_MCP_GOVERNANCE_MODE",
  "APEX_RUNTIME_CONFIG_FILE", "APEX_RUNTIME_LAUNCH_FILE", "APEX_MCP_MANAGED_BOOTSTRAP",
  "APEX_INSTALLATION_ID", "APEX_STAGE_MANIFEST_SHA256", "APEX_TOOL_SECRET_REFERENCES",
  "APEX_MCP_NETWORK_PROFILE", "APEX_MCP_GUARD_ADDRESS", "APEX_MCP_NETWORK_BINDING_SHA256"];
assert.deepEqual(Object.keys(nativeEnvironment).sort(), keys.sort());
assert.ok(Object.values(nativeEnvironment).every(value => typeof value === "string" && !value.includes("\n")));
// Token/private material stays inside the owned read-only stage, never in argv.
console.log(`owned daemon health environment ${JSON.stringify(nativeEnvironment)}`);
