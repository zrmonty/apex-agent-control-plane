import { types } from "node:util";
import { hash, uuid } from "../configuration/boundary.js";
const refused = () => new Error("guard process refused safely");
const fixed = Object.freeze({ NODE_ENV: "production", HOME: "/tmp/apex", APEX_MCP_PROFILE: "guard",
  APEX_MCP_GUARD_BOOTSTRAP: "sealed-stage-v1" });
const keys = new Set([...Object.keys(fixed), "APEX_INSTALLATION_ID", "APEX_PROCESS_INSTANCE_ID",
  "APEX_STAGE_MANIFEST_SHA256", "APEX_NETWORK_BINDING_SHA256", "APEX_NETWORK_TOPOLOGY_SHA256"]);
const forbidden = new Set(["NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY", "OPENSSL_CONF", "OPENSSL_MODULES"]);

export function guardEnvironment(env: NodeJS.ProcessEnv) {
  try {
    if (!env || typeof env !== "object" || types.isProxy(env) || Array.isArray(env)) throw refused();
    const names = Reflect.ownKeys(env);
    if (names.length > 256) throw refused();
    let total = 0;
    for (const key of names) {
      if (typeof key !== "string" || key.length > 128 || (key.toUpperCase().startsWith("APEX_") && !keys.has(key)) ||
        (keys.has(key.toUpperCase()) && !keys.has(key)) ||
        forbidden.has(key.toUpperCase())) throw refused();
      const descriptor = Object.getOwnPropertyDescriptor(env, key)!;
      if (!("value" in descriptor) || !descriptor.enumerable || typeof descriptor.value !== "string") throw refused();
      total += key.length + descriptor.value.length;
      if (descriptor.value.length > 16384 || total > 65536) throw refused();
    }
    const own = (key: string): string => {
      const descriptor = Object.getOwnPropertyDescriptor(env, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable || typeof descriptor.value !== "string") throw refused();
      return descriptor.value;
    };
    for (const [key, value] of Object.entries(fixed)) if (own(key) !== value) throw refused();
    return Object.freeze({ manifest: hash(own("APEX_STAGE_MANIFEST_SHA256")), expected: Object.freeze({
      installationId: uuid(own("APEX_INSTALLATION_ID")), processInstanceId: uuid(own("APEX_PROCESS_INSTANCE_ID")),
      networkBindingSha256: hash(own("APEX_NETWORK_BINDING_SHA256")), networkTopologySha256: hash(own("APEX_NETWORK_TOPOLOGY_SHA256")),
    }) });
  } catch { throw refused(); }
}
