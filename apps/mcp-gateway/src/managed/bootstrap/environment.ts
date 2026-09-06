import { types } from "node:util";
import { parseWireJson } from "../upstream-wire/json.js";

const fixed = Object.freeze({ NODE_ENV: "production", HOME: "/tmp/apex", APEX_MCP_PROFILE: "managed",
  APEX_MCP_GOVERNANCE_MODE: "live", APEX_RUNTIME_CONFIG_FILE: "/apex/runtime/runtime-revision.json",
  APEX_RUNTIME_LAUNCH_FILE: "/apex/runtime/launch-context.json" });
const keys = new Set([...Object.keys(fixed), "APEX_MCP_MANAGED_BOOTSTRAP", "APEX_INSTALLATION_ID", "APEX_STAGE_MANIFEST_SHA256", "APEX_TOOL_SECRET_REFERENCES"]);
const networkKeys = new Set(["APEX_MCP_NETWORK_PROFILE", "APEX_MCP_GUARD_ADDRESS", "APEX_MCP_NETWORK_BINDING_SHA256"]);
const forbidden = new Set(["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "OPENSSL_CONF", "OPENSSL_MODULES"]);
const refused = () => new Error("managed stage environment rejected");
export interface SealedStageSelection {
  readonly installationId: string;
  readonly expectedManifestSha256: string;
  readonly toolSecretReferences: readonly string[];
}
export interface SealedStageNetwork {
  readonly profile: "isolated-bridge-v1";
  readonly guardAddress: string;
  readonly guardPort: 18080;
  readonly gatewayAddress: string;
  readonly bindingSha256: string;
}
export interface ManagedBootstrapSelection extends SealedStageSelection {
  readonly network?: SealedStageNetwork;
}

/** Fixed agent-owned process metadata, not itself provenance or permission to
 * serve. No filesystem access, legacy fallback or arbitrary file paths. */
export function parseSealedStageEnvironment(env: NodeJS.ProcessEnv): ManagedBootstrapSelection {
  try {
    if (!env || typeof env !== "object" || types.isProxy(env) || Array.isArray(env)) throw refused();
    const names = Object.getOwnPropertyNames(env);
    if (names.length > 256 || Object.getOwnPropertySymbols(env).length) throw refused();
    const own = (key: string): string => {
      const descriptor = Object.getOwnPropertyDescriptor(env, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable || typeof descriptor.value !== "string") throw refused();
      return descriptor.value;
    };
    const mode = own("APEX_MCP_MANAGED_BOOTSTRAP");
    if (mode !== "sealed-stage-v1" && mode !== "sealed-stage-v2") throw refused();
    for (const key of names) {
      if ((key.toUpperCase().startsWith("APEX_") && !keys.has(key) &&
        !(mode === "sealed-stage-v2" && networkKeys.has(key))) || forbidden.has(key.toUpperCase())) throw refused();
    }
    const network = mode === "sealed-stage-v2" ? parseNetwork(own) : undefined;
    for (const [key, value] of Object.entries(fixed)) if (own(key) !== value) throw refused();
    const installationId = own("APEX_INSTALLATION_ID"), expectedManifestSha256 = own("APEX_STAGE_MANIFEST_SHA256");
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(installationId) ||
      !/^[0-9a-f]{64}$/.test(expectedManifestSha256)) throw refused();
    const raw = own("APEX_TOOL_SECRET_REFERENCES");
    // 32 bounded ASCII references plus brackets, separators and quotes.
    if (raw.length > 8289) throw refused();
    const refs = parseWireJson(Buffer.from(raw, "utf8"));
    if (!Array.isArray(refs) || refs.length > 32 || refs.some(ref => typeof ref !== "string" || ref.length > 256 ||
      !ref.startsWith("secret://") || !/^[A-Za-z0-9]/.test(ref.slice(9)) || ref.slice(9).split("/").some((part: string) =>
        !/^[A-Za-z0-9_.:-]{1,256}$/.test(part) || part === "." || part.includes("..")))) throw refused();
    if (new Set(refs).size !== refs.length || JSON.stringify([...refs].sort()) !== raw) throw refused();
    return Object.freeze({ installationId, expectedManifestSha256, toolSecretReferences: Object.freeze([...refs] as string[]),
      ...(network ? { network } : {}) });
  } catch { throw refused(); }
}

function parseNetwork(own: (key: string) => string): SealedStageNetwork {
  if (own("APEX_MCP_NETWORK_PROFILE") !== "isolated-bridge-v1") throw refused();
  const guardAddress = own("APEX_MCP_GUARD_ADDRESS"), bindingSha256 = own("APEX_MCP_NETWORK_BINDING_SHA256");
  if (guardAddress.length > 15 || bindingSha256.length !== 64 || !/^[0-9a-f]{64}$/.test(bindingSha256)) throw refused();
  const parts = guardAddress.split(".");
  if (parts.length !== 4 || parts.some(p => !/^(0|[1-9][0-9]{0,2})$/.test(p) || Number(p) > 255)) throw refused();
  const numbers = parts.map(Number), [a, b, , d] = numbers;
  if (numbers.join(".") !== guardAddress || d % 8 !== 3 ||
    !(a === 10 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168)) throw refused();
  numbers[3]--;
  return Object.freeze({ profile: "isolated-bridge-v1", guardAddress, guardPort: 18080,
    gatewayAddress: numbers.join("."), bindingSha256 });
}
