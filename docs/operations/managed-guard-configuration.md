# Guard configuration contract

`parseGuardConfiguration(bytes, expected, nowUnixUs)` validates the key-free
configuration document read by the separate [guard stage loader](managed-guard-stage.md).
It performs no I/O or relay startup. The production producer and process
supervisor are separate requirements; this parser does not enable `Serving`.

The 1..262144-byte document uses compact UTF8 JSON, exact snake_case keys, no
duplicate fields, and schema_version1/profile`isolated-bridge-v1`. It carries
installation_id, process_instance_id, network_binding_sha256,
network_topology_sha256, not_before_unix_us, not_after_unix_us, topology and routes.
Times are canonical positive decimal strings through signed64-bit SQL range,
preserving individual microseconds above JavaScript's safe integer limit.
The supplied original wall-clock sample must fall in the half-open interval.
The process supervisor must enforce expiry continuously after parsing.

The separate expectation object has installationId, processInstanceId,
networkBindingSha256 and networkTopologySha256. UUIDs are canonical UUIDv7;
hashes are lowercase SHA256. Every field must match. The process root must obtain
these expectations and the expected stage manifest from the actual protected
launch. Matching user-supplied hashes alone proves no provenance or authority.

`topology` contains internal_pool, outer_subnet, slot, capacity, outer_gateway
and edge_address. It follows the protected network catalog's disjoint RFC1918
internal/22 through/29 and outer/24 geometry. Capacity1..128 must fit the internal
pool. The selected slot determines its/29 block, IPAMgateway+1, gateway workload+2,
guard internal+3 and guard outer at outerbase+16+slot. Outer gateway and edge must
be different reserved offsets1..15. Listener ports are fixed8080 ingress and
18080 egress. No caller-supplied address override or listener port is accepted.

`routes` contains1..66 unique DNS-host/port selectors. Each route contains host,
port, private_destination, declared_cidrs and protected_cidrs. Declared ranges
are0..64; protected ranges are1..32. This profile permits canonical IPv4 CIDRs
only. The existing egress compiler intersects the two permission sets and
excludes BOTH entire deployment pools, including other proxies' slots. Every
DNS answer must be permitted; a permitted first answer does not excuse a later
forbidden answer. Private destinations need explicit private declarations and
protected ranges; mixed public/private ranges refuse rather than broaden.

The producer must join routes to published upstreams and the protected governance
and evidence endpoints. When purposes share a host/port, intersect their effective
permissions before emitting one selector. Duplicates are rejected, never unioned.
No TLS keys, tokens, secret references, arbitrary commands, headers or environment
overrides belong in this schema. This is a closed schema, not a general secret
scanner. Physical topology must still be independently inspected before startup.
