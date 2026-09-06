# Binding staged documents before credential use

`parseManagedStageDocuments` joins the four metadata documents from an actual
owned stage-reader result. It performs no filesystem or network I/O and does not
interpret tokens, private keys, instance-proof bytes or upstream credentials.

The decoder first matches the reported manifest hash and exact 18–50 filename
inventory to the independent handoff selection. It then:

1. Revalidates the original published configuration and its manifest hash.
2. Revalidates the original launch and all of its configuration/hash bindings.
3. Constructs the exact deployment identity from that launch and the independent
   installation ID, preserving generation/fence as bigint.
4. Matches the explicit schema-3 authority profile to that deployment, including
   all 13 distinct role references and the launch's authority reference/version.
5. Matches `tool-bindings.json` scope, proxy, revision, configuration hash and
   host-policy version to the same deployment/profile. Its entries must match
   both published and handoff secret-reference sets exactly.

Each tool entry contains only `reference`, `version` and `filename`. The filename
must be exactly `tool-` followed by the lowercase SHA-256 of that reference, and
must exist in the held stage inventory. No caller-selected path is followed.
Duplicate, missing, extra or cross-scope entries are rejected. Catalog and
deployment-binding version fields remain bounded opaque identifiers; their
publication/provenance still comes from the protected agent and registration,
not from the decoder's lexical checks.

Metadata is copied through bounded native byte views before decoding. The tool
binding document must retain the agent's compact JSON serializer form, including
integer schema syntax. Original invalid UTF-8, duplicate keys, alternate object
shapes, active descriptors and oversized metadata fail with one static error.
The resulting configuration, launch, binding, authority and tool metadata are
defensive, deeply frozen copies. Secret-content buffers are not returned.

This decoder is deliberately not a capability factory. A caller can fabricate
a TypeScript `LoadedManagedStage` object and a matching claimed hash. Production
startup must directly own the real file-descriptor stage reader, its independently
supplied expected hash and original physical cleanup receipt. Never pass an HTTP
body, operator JSON or injected caller stage object into this trusted root path.
The root separately owns disposal of loaded bytes and all credential consumers.

Matching documents cannot prove actual TLS enrollment, a resolved network policy,
current runtime authority or readiness. Those gates must complete independently
before admitting traffic.
