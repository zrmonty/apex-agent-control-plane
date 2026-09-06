import { readFileSync } from "node:fs";
import { toJson } from "@bufbuild/protobuf";
import { RuntimeConfigurationSchema, decodeStrict, type RuntimeConfiguration } from "@apex/contracts";
import { parseRuntimeConfiguration, runtimeManifestHash } from "../runtime-config.js";
import type { ClockSnapshot } from "../../telemetry/clock.js";
import type { DeploymentBinding } from "../authority/types.js";

// Existing checked-in contract fixture; local data only, not published authority.
const text = readFileSync(new URL("../../../../../contracts/fixtures/mcp-proxy/runtime-revision.json", import.meta.url), "utf8");
export function configuration(change?: (value: RuntimeConfiguration) => void) {
  const value = decodeStrict(RuntimeConfigurationSchema, text);
  value.generation = 9007199254740993n;
  change?.(value);
  value.runtimeManifestHash = runtimeManifestHash(value);
  return parseRuntimeConfiguration(toJson(RuntimeConfigurationSchema, value));
}
export function fixture() {
  const config = configuration();
  const binding: DeploymentBinding = Object.freeze({ installationId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
    workspaceId: config.workspaceId, namespaceId: config.namespaceId, proxyId: config.proxyId,
    revisionId: config.revisionId, generation: config.generation, fencingToken: 9007199254740995n,
    processInstanceId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04", configHash: config.configHash,
    launchContextHash: "c".repeat(64) });
  const original: ClockSnapshot = { monotonicNs: 9007199254740993n, unixUs: 9007199254740993n,
    source: "fixture stable microsecond anchor", resolutionNs: 1n, uncertaintyUs: 7n };
  let sample = { ...original };
  const clock = { now: () => ({ ...sample }) };
  const options = { config, binding, evidenceAgentId: "managed-evidence", dataClassification: "confidential", clock };
  return { options, original, identity: { subject: "spiffe://apex/agent/research", proxyId: config.proxyId, scopes: ["mcp:tools"] },
    deadline: original.monotonicNs + 120000000000n,
    sample(value: ClockSnapshot) { sample = value; },
    mutableConfig: () => structuredClone(config) as RuntimeConfiguration };
}
