# Managed guard stage data producer

Status: reviewed implementation committed in `71dc905` on 2026-09-06, after
baseline merge `fe8ce35`. See the [integration checkpoint](managed-runtime-checkpoint.md)
for publication status and the next execution boundary. This is continuation
Task 4U, not a new task in the 22-task parent roadmap.

Task4U adds a private Rust producer between the protected empty-network topology
owner and future paired staging. The opted-in provisioning branch still returns
`RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE` and remains NotServing. Producer refusal
also maps to that existing external error. No stage is written by this producer.

The production composition holds the current immutable metadata snapshot,
reconstructed `PreparedLaunch`, selected authority/tools, and original `Installed`
record. After `prepare_empty` and a fresh authority/metadata checkpoint, it reads
the protected `topology_history` and selects the original instance. The producer
requires validated `Observed` state with the full recorded ID, revalidates both
document and topology against the original record, and compares a freshly derived
topology with `matches_current`. Historical hashes and phase meanings do not change.
An Observed record is historical evidence; it is not current native inspection or
permission for a later effect.

Original launch, configuration, authority, and tool bytes must equal the genuinely
prepared selections. The existing publication and mount joins remain in provisioning.
Original configuration is decoded with the generated strict decoder, with byte
bounds checked first; its exact generated encoding and manifest must still match.
Schema 3 `managed_ingress`, installation, target, instance, and network profile
reference/version joins are required. Legacy schema 1 is not reinterpreted.

## Produced data

The result contains compact UTF-8 `guard-config.json`, one file SHA-256 map, the
SHA-256 of that exact compact map, the fixed environment below, and the selected
guard image catalog ID and immutable image reference. The complete JSON is capped
at 262144 bytes while serializing. The map has precisely this structure:

```json
{"guard-config.json":"<sha256 of exact guard-config.json bytes>"}
```

The guard image must match the selected protected network profile and image
catalog exactly. Selection does not verify a signature and has no fallback.

The DTO uses the unchanged TypeScript guard parser's snake-case schema. Both
microsecond times are canonical decimal strings through `9223372036854775807`.
They come from the **current held network catalog interval**, while binding and
topology hashes retain their original values. Currentness is half-open:
`not_before_unix_us <= now < not_after_unix_us`. These times bound network policy,
not a workload admission lease. Renewal does not rewrite a previously staged or
running guard's immutable expiry.

| Environment key | Exact value |
| --- | --- |
| `NODE_ENV` | `production` |
| `HOME` | `/tmp/apex` |
| `APEX_MCP_PROFILE` | `guard` |
| `APEX_MCP_GUARD_BOOTSTRAP` | `sealed-stage-v1` |
| `APEX_INSTALLATION_ID` | Original installation ID |
| `APEX_PROCESS_INSTANCE_ID` | Original process instance ID |
| `APEX_STAGE_MANIFEST_SHA256` | Digest of the exact one-file map |
| `APEX_NETWORK_BINDING_SHA256` | Original binding hash |
| `APEX_NETWORK_TOPOLOGY_SHA256` | Original topology hash |

## Route permissions

Every original published network selector requires an upstream-purpose protected
grant. Governance and evidence each require their own purpose-specific protected
grant matching the selected HTTPS authority endpoint; omitted HTTPS ports mean 443.
Unused protected grants are not emitted. At most 64 published selectors plus the
two authority selectors can contribute routes.

For an upstream selector, published and protected CIDR unions intersect. An empty
public declaration means the bounded protected upper limit; an empty private
declaration refuses. Authority purpose bounds come from their own protected grants.
All required purposes sharing a host/port intersect again. Neither first-match
selection nor a union across purposes is allowed. Empty intersections refuse.

The intersection implementation operates on sorted, reduced disjoint IPv4 intervals
with a linear two-pointer scan; it never allocates a Cartesian product. Results
encode canonical reduced CIDRs, at most 32 per route, identically in
`declared_cidrs` and `protected_cidrs`. Over-bound results refuse instead of widening.

Every purpose's effective set must be entirely RFC1918-private or entirely public
under the unchanged TS `runtime-config/network.ts` permitted-range rules. Mixed
sets and incompatible private flags refuse. IPv6, `/0`, noncanonical ranges,
effective special-use ranges, numeric DNS aliases, localhost/metadata/host aliases,
and public `.internal`/`.local` names refuse. Both complete deployment pools are
excluded, including all future slots. The producer performs no DNS lookup; the TS
guard independently checks every actual answer before pinning it.

## Verification and remaining boundary

Private Linux tests cover original joins, real protected Journal read/reopen,
Observed-only input, renewal/expiry and integer precision, route purpose coverage,
shared intersections, limits, forbidden destinations, deterministic output, and an
independent address-set oracle across 343 canonical prefix combinations. The
explicit fixture export runs the actual Rust producer. Its bytes and environment
pass the unchanged TS 4S configuration and 4T environment parsers, with exact
JSON round-trip/manifest assertions and selector/pin allow and deny probes.

The unchanged native 4P suite tests production empty-network behavior and the
DORMANT refusal for its missing upstream-purpose declaration. It is not a successful
native guard stage/create test. Successful producer-data acceptance is the separate
Rust-to-TS fixture. No TS consumer behavior changes in this task.

Future work must durably bind this data to signature verification, paired staging,
create/inspect/start ownership, and fresh effect authority. This result establishes
none of those steps, health, routing, admission, readiness, or Serving.
