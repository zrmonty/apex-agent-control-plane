export const now = 9007199254740993n;
export const expected = Object.freeze({ installationId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
  processInstanceId: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02", networkBindingSha256: "a".repeat(64),
  networkTopologySha256: "b".repeat(64) });
export function fixture() {
  return { schema_version: 1, profile: "isolated-bridge-v1", installation_id: expected.installationId,
    process_instance_id: expected.processInstanceId, network_binding_sha256: expected.networkBindingSha256,
    network_topology_sha256: expected.networkTopologySha256, not_before_unix_us: (now - 1n).toString(),
    not_after_unix_us: (now + 1000000n).toString(),
    topology: { internal_pool: "10.88.0.0/22", outer_subnet: "10.89.0.0/24", slot: 2, capacity: 128,
      outer_gateway: "10.89.0.1", edge_address: "10.89.0.2" },
    routes: [{ host: "api.example", port: 443, private_destination: false,
      declared_cidrs: ["8.8.8.0/24"], protected_cidrs: ["8.8.0.0/16"] }] };
}
