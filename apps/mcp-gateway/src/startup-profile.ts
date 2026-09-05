import { GatewayError } from "./contracts.js";

/** Process selection only, before file or privileged dependency access. This
 * confers no publication, identity, catalog, policy or enforcement authority;
 * RuntimeConfiguration v1 and the managed factory remain separate boundaries. */
export function selectStartupProfile(env: NodeJS.ProcessEnv): "managed" | "development-standalone" {
  const profile = env.APEX_MCP_PROFILE ?? "managed";
  if (profile !== "managed" && profile !== "development-standalone") throw rejected();
  const file = env.APEX_MCP_PROXY_REVISION_CONFIG_FILE;
  const inline = env.APEX_MCP_PROXY_REVISION_CONFIG;
  if (profile === "development-standalone") {
    if (env.NODE_ENV !== "development" || file !== undefined || inline !== undefined) throw rejected();
  } else if (env.APEX_MCP_GOVERNANCE_MODE !== "live" || inline !== undefined || file === undefined || file.length === 0) {
    throw rejected();
  }
  return profile;
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "gateway process profile rejected safely");
}
