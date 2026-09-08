import { GatewayError } from "./contracts.js";
import { parseSealedStageEnvironment } from "./managed/bootstrap/environment.js";

/** Process selection only, before file or privileged dependency access. This
 * confers no publication, identity, catalog, policy or enforcement authority;
 * the actual sealed stage and managed application remain separate boundaries. */
export function selectStartupProfile(env: NodeJS.ProcessEnv): "managed" | "development-standalone" {
  const profile = env.APEX_MCP_PROFILE ?? "managed";
  if (profile !== "managed" && profile !== "development-standalone") throw rejected();
  if (profile === "development-standalone") {
    if (env.NODE_ENV !== "development" || Object.getOwnPropertyNames(env).some(key =>
      /^(?:APEX_RUNTIME_|APEX_STAGE_|APEX_TOOL_SECRET_REFERENCES$|APEX_INSTALLATION_ID$|APEX_MCP_(?:PROXY_REVISION_CONFIG|MANAGED_BOOTSTRAP|NETWORK_|GUARD_|LISTEN_))/i.test(key))) throw rejected();
  } else {
    try { if (!parseSealedStageEnvironment(env).network) throw rejected(); }
    catch { throw rejected(); }
  }
  return profile;
}

function rejected(): GatewayError {
  return new GatewayError("INVALID_INPUT", "gateway process profile rejected safely");
}
