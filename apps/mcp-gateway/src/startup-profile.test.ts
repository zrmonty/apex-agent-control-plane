import test from "node:test";
import assert from "node:assert/strict";
import { selectStartupProfile } from "./startup-profile.js";

const stage = (): NodeJS.ProcessEnv => ({ NODE_ENV: "production", HOME: "/tmp/apex", APEX_MCP_PROFILE: "managed",
  APEX_MCP_GOVERNANCE_MODE: "live", APEX_RUNTIME_CONFIG_FILE: "/apex/runtime/runtime-revision.json",
  APEX_RUNTIME_LAUNCH_FILE: "/apex/runtime/launch-context.json", APEX_MCP_MANAGED_BOOTSTRAP: "sealed-stage-v2",
  APEX_INSTALLATION_ID: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01", APEX_STAGE_MANIFEST_SHA256: "a".repeat(64),
  APEX_TOOL_SECRET_REFERENCES: "[]", APEX_MCP_NETWORK_PROFILE: "isolated-bridge-v1",
  APEX_MCP_GUARD_ADDRESS: "10.96.0.3", APEX_MCP_NETWORK_BINDING_SHA256: "b".repeat(64) });
const development = { NODE_ENV: "development", APEX_MCP_PROFILE: "development-standalone", APEX_MCP_GOVERNANCE_MODE: "local" };
const refused = /INVALID_INPUT: gateway process profile rejected safely/;

test("managed process selection requires the exact sealed isolated-network handoff, not legacy file metadata", () => {
  assert.equal(selectStartupProfile(stage()), "managed");
  for (const key of Object.keys(stage())) {
    const env = stage(); delete env[key]; assert.throws(() => selectStartupProfile(env), refused, key);
  }
  const old = stage(); old.APEX_MCP_MANAGED_BOOTSTRAP = "sealed-stage-v1";
  delete old.APEX_MCP_NETWORK_PROFILE; delete old.APEX_MCP_GUARD_ADDRESS; delete old.APEX_MCP_NETWORK_BINDING_SHA256;
  assert.throws(() => selectStartupProfile(old), refused);
  assert.throws(() => selectStartupProfile({ APEX_MCP_PROFILE: "managed", APEX_MCP_GOVERNANCE_MODE: "live",
    APEX_MCP_PROXY_REVISION_CONFIG_FILE: "SENSITIVE-legacy-file" }), refused);
});

test("managed selection cannot accept caller metadata, alternate paths or ambient transport overrides", () => {
  for (const key of ["APEX_MCP_PRINCIPAL", "APEX_MCP_LISTEN_HOST", "APEX_MCP_PROXY_REVISION_CONFIG_FILE",
    "APEX_MCP_PROXY_REVISION_CONFIG", "NODE_OPTIONS", "HTTPS_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED"]) {
    assert.throws(() => selectStartupProfile({ ...stage(), [key]: "" }), refused);
  }
  assert.throws(() => selectStartupProfile({ ...stage(), APEX_RUNTIME_CONFIG_FILE: "SENSITIVE-file" }), refused);
});

test("explicit development retains caller configuration but rejects every managed handoff selector", () => {
  assert.equal(selectStartupProfile({ ...development, APEX_MCP_PRINCIPAL: "spiffe://apex/agent/research" }), "development-standalone");
  const keys = Object.keys(stage()).filter(key => !["NODE_ENV", "HOME", "APEX_MCP_PROFILE", "APEX_MCP_GOVERNANCE_MODE"].includes(key));
  keys.push("APEX_MCP_PROXY_REVISION_CONFIG", "APEX_MCP_PROXY_REVISION_CONFIG_FILE", "APEX_MCP_LISTEN_HOST", "APEX_MCP_LISTEN_PORT");
  for (const key of keys) for (const value of [undefined, "", "SENSITIVE"]) {
    assert.throws(() => selectStartupProfile({ ...development, [key]: value }), refused, key);
    assert.throws(() => selectStartupProfile({ ...development, [key.toLowerCase()]: value }), refused, key);
  }
});
