import { parseWireJson } from "../upstream-wire/json.js";
import { assertDataTree } from "../runtime-config/boundary.js";
import { capture, exact, hash, MAX_TIME, refused, requireValue, timestamp, uuid } from "./configuration/boundary.js";
import { topology } from "./configuration/topology.js";
import { routes } from "./configuration/routes.js";
export type GuardConfigurationExpectation = Readonly<{
  installationId: string; processInstanceId: string; networkBindingSha256: string; networkTopologySha256: string;
}>;
/** Pure consistency/policy compiler. Actual sealed stage and kernel ownership
 * must be established separately before these values can configure a listener. */
export function parseGuardConfiguration(bytes: Uint8Array, expected: GuardConfigurationExpectation, nowUnixUs: bigint) {
  try {
    const copy = capture(bytes), value = parseWireJson(copy);
    requireValue(JSON.stringify(value) === copy.toString("utf8"));
    assertDataTree(value, false); assertDataTree(expected, false);
    const e = exact(expected, ["installationId", "processInstanceId", "networkBindingSha256", "networkTopologySha256"]);
    const v = exact(value, ["schema_version", "profile", "installation_id", "process_instance_id", "network_binding_sha256",
      "network_topology_sha256", "not_before_unix_us", "not_after_unix_us", "topology", "routes"]);
    requireValue(v.schema_version === 1 && v.profile === "isolated-bridge-v1");
    const installationId = uuid(v.installation_id), processInstanceId = uuid(v.process_instance_id);
    const networkBindingSha256 = hash(v.network_binding_sha256), networkTopologySha256 = hash(v.network_topology_sha256);
    requireValue(installationId === uuid(e.installationId) && processInstanceId === uuid(e.processInstanceId) &&
      networkBindingSha256 === hash(e.networkBindingSha256) && networkTopologySha256 === hash(e.networkTopologySha256));
    const notBeforeUnixUs = timestamp(v.not_before_unix_us), notAfterUnixUs = timestamp(v.not_after_unix_us);
    requireValue(typeof nowUnixUs === "bigint" && nowUnixUs > 0n && nowUnixUs <= MAX_TIME &&
      notBeforeUnixUs < notAfterUnixUs && nowUnixUs >= notBeforeUnixUs && nowUnixUs < notAfterUnixUs);
    const network = topology(v.topology), policy = routes(v.routes, network.excluded);
    return Object.freeze({ installationId, processInstanceId, networkBindingSha256, networkTopologySha256,
      notBeforeUnixUs, notAfterUnixUs, addresses: network.addresses, policy });
  } catch { throw refused(); }
}
export type GuardConfiguration = ReturnType<typeof parseGuardConfiguration>;
