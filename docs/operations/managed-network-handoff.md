# Managed gateway network handoff

The gateway stage bootstrap recognizes two explicit agent handoffs. Neither is
permission to serve. Production network create/inspect and runtime activation
remain separate integration gates; the agent does not yet emit v2.

`sealed-stage-v1` keeps the existing exact ten fields and `{documents}` owner
shape. It rejects network-selection fields, including empty or undefined ones.
Do not retrofit a v1 staged container with ambient proxy variables.

`sealed-stage-v2` uses the same ten fields, changes
`APEX_MCP_MANAGED_BOOTSTRAP` to `sealed-stage-v2`, and requires:

| Fixed agent-owned field | Meaning |
| --- | --- |
| `APEX_MCP_NETWORK_PROFILE` | Exactly `isolated-bridge-v1` |
| `APEX_MCP_GUARD_ADDRESS` | Canonical private IPv4, internal /29 offset3 |
| `APEX_MCP_NETWORK_BINDING_SHA256` | Exact 64-character lowercase SHA-256 binding from durable agent allocation |

The captured network metadata has `profile`, `guardAddress`, fixed `guardPort`
18080, derived `gatewayAddress` at /29 offset2, and `bindingSha256`. It is deeply
immutable and exposed as `StageOwner.network` only for explicit v2. The owner
captures ENV before asynchronous stage reads; changing ENV later cannot swap the
address. There are no configurable ports, paths, proxy/DNS fallbacks or extra APEX
fields. RFC1918 ranges are 10/8, 172.16/12 and 192.168/16; IPv6 and numeric aliases
are not accepted by this initial handoff.

The gateway file inventory, manifest calculation and exact three-field document
join are unchanged. Network fields are not passed into the document parser or
reader. Existing stage FD, mount, byte-cap, original-deadline, material-disposal
and physical-close ownership rules apply to both versions.

This decoder validates shape and consistency only. Even an exact digest is not
provenance. The production root must use the actual protected stage owner, demand
v2 for networking, and depend on independently inspected physical confinement,
fresh workload proof, online admission, readiness and approved artifacts. Root
activation, Rust v2 emission/create/inspect, guard staging/start, lifecycle and
full end-to-end tracing are not completed by this handoff.
