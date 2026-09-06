# Protected managed network catalog

The agent supports the explicit `execution.network_profile` value
`isolated-bridge-v1`. Absence retains dormant provisioning and does not read the
network file. Explicit null or any other representation refuses. Changing the
fingerprinted agent configuration requires restart. **This setting does not yet
enable network creation, container start, routing or Serving.**

The opted-in loader reads only `network-catalog.json` from the protected deployment
directory. Existing descriptor-relative ownership, mode, link, ancestor and bounded
read checks apply. Original bytes are capped at262144 and join the metadata digest.
Missing, invalid or expired refresh invalidates the snapshot rather than keeping
old authority. The local clock independently checks the exact half-open integer
microsecond interval. No catalog content is accepted from an RPC.

## Schema1

The exact top-level fields are `schema_version`, `version`, `installation_id`,
`host_policy_version`, `valid_from_unix_us`, `expires_at_unix_us`, `capacity`,
`internal_pool`, `outer`, and `profiles`. All nested records require objects;
unknown/duplicate/positional fields, null, fractional integers and malformed UTF-8
refuse. Static errors do not retain parser diagnostics or input.

Installation is lowercase UUIDv7; version and host policy are bounded identifiers.
Times are positive u64 JSON integers no greater than i64MAX, with from < expiry.
Capacity is1..128 and cannot exceed the internal pool's available /29 blocks.
The internal pool is a canonical RFC1918 IPv4 CIDR with prefix22..29.

`outer` contains exactly `network_id`, `subnet`, `gateway`, `edge_address`.
The network ID is64 lowercase hex characters. Its subnet is a canonical RFC1918
/24, disjoint from the entire internal pool. Gateway and edge are distinct usable
addresses at offsets1..15. The outer fabric is protected and pre-existing. Future
engine inspection must verify its actual exact ID, bridge driver, subnet/gateway,
disabled IPv6 and installation/role labels; parsing does not adopt or own it.
It must never be removed as a per-proxy resource.

Slot n maps to internal base +8n (/29), gateway +2, guard +3, and outer base +16+n.
`candidate_addresses` is a pure calculation, **not a reservation or permission**.
A durable installation-wide allocator must retain slots across candidate,
predecessor, crash and uncertain cleanup before any stage/network effect.

## Profiles and endpoint bounds

`profiles` has1..32 exact records containing `reference`, `version`,
`guard_image_catalog_id`, `guard_image_ref`, and `grants`. Reference/version pairs
are unique. Every guard ID and immutable reference joins the existing protected
image catalog, including unselected profiles. Signature verification is separate
and still required before actual use.

Each profile has1..64 grants of exact shape `{purpose,host,port,cidrs}`. Purpose
is `governance`, `evidence` or `upstream`; governance and evidence must both appear.
Hosts are bounded canonical lowercase DNS labels, not IPs, URLs, wildcards or
localhost names. Decimal, octal and hexadecimal/mixed numeric-looking aliases
are refused lexically, including overflowing forms; validation performs no DNS.
Ports are1..65535. Each list contains1..32 unique canonical IPv4
CIDRs. Duplicate purpose/host/port grants refuse. Every complete CIDR range is
checked against both installation pools and0/8,127/8,169.254/16,224/3 exclusions.
RFC1918 service destinations outside the installation pools remain configurable.
This is an explicit protected upper bound, not a claim of general Internet safety.

The total original-byte cap still applies when individual collection maxima would
produce a larger document. IPv6 grants are unsupported in this profile. The later
guard must enforce actual IPv6/UDP/DNS confinement and intersect these grants with
published policy and every resolved address, retaining original TLS names.

## Integration limits

The loader joins installation, host policy, current interval and protected image
selection. Exact authority-profile network reference/version selection, published
upstream intersection, durable allocation, kernel topology inspection, guard
confinement, sealed-stage-v2 handoff, root readiness and lifecycle remain subsequent
gates. Nothing here authenticates catalog bytes merely because they hash correctly.
Existing staged-v1 containers remain dormant; no upgrade reinterprets their stage.

Tests cover original JSON, address arithmetic/exclusions, bounds, exact selection,
image joins and integer microseconds above2^53. Linux tests exercise the actual
protected deployment **refresh** loader, snapshot invalidation and filesystem
refusals using disposable roots. They use unused synthetic transport bytes and do
not prove TLS, initial engine opening, signature acceptance or Serving.
