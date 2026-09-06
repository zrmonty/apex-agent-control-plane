# Sealed stage bootstrap handoff

The runtime agent derives the gateway's expected stage identity from its sealed,
immutable installed journal. It does not ask the gateway to discover an expected
hash from the same files it is trying to authenticate.

Only the explicit schema-3 `managed_ingress` profile receives this handoff.
Schema-1 and schema-2 dormant environments remain unchanged. This implementation
does not start a container, attach a network, enable ingress or grant admission.

## Fixed process metadata

The existing six assignments remain exact:

```text
NODE_ENV=production
HOME=/tmp/apex
APEX_MCP_PROFILE=managed
APEX_MCP_GOVERNANCE_MODE=live
APEX_RUNTIME_CONFIG_FILE=/apex/runtime/runtime-revision.json
APEX_RUNTIME_LAUNCH_FILE=/apex/runtime/launch-context.json
```

Four additional assignments select the new bootstrap:

| Variable | Value and source |
| --- | --- |
| `APEX_MCP_MANAGED_BOOTSTRAP` | Literal `sealed-stage-v1` |
| `APEX_INSTALLATION_ID` | Exact original installation UUIDv7 |
| `APEX_STAGE_MANIFEST_SHA256` | SHA-256 of compact JSON of the sealed journal's sorted filename-to-SHA256 map |
| `APEX_TOOL_SECRET_REFERENCES` | Compact JSON array of the exact published references, sorted by ASCII bytes |

References identify credentials; they are not their contents. No token, private
key, instance proof or raw tool credential is copied into these assignments.
The manifest algorithm is the same one used for staged launch attestation.
The map includes `runtime-revision.json`, `launch-context.json`,
`authority-profile.json`, `tool-bindings.json`, `instance-proof`, all 13 fixed
deployment-role filenames, and one `tool-<sha256(reference)>` per published
reference. The complete inventory is 18–50 files.

The agent requires proof version 1, exactly that inventory, valid file hashes,
and matching SHA-256 digests for each of the four journal JSON documents. There
can be at most 32 unique references, each at most 256 ASCII characters. Existing
protected profile/publication selection and actual stage sealing remain the
prerequisites; this deterministic environment builder is not their replacement.

## Creation, adoption and inspection

Docker creation and inspection derive the same expected environment. Values
cannot be replaced by inherited image keys: other pinned image keys are still
explicitly unset through the environment-cleared command owner. Inspection checks
the exact set, including legitimate bare unset keys. Extra, duplicate, missing
or changed assignments fail the existing ownership check.

Restart/adoption reuses the original journal and sealed file map. A new operation
fence does not rewrite the launch identity or manufacture a new expected hash.
The handoff adds no new mutable file or journal schema field. Existing bounds,
deadlines, signature verification and dormant container constraints remain.

## Gateway boundary

`parseSealedStageEnvironment` returns only an immutable installation ID, expected
manifest hash and reference inventory. It opens no files and creates no clients.
It requires exact fixed values, canonical lowercase UUIDv7/hash, and canonical
sorted unique JSON references (maximum 8,289 characters). Getters, proxy objects,
inherited metadata and non-enumerable metadata are not trusted as assignments.

Legacy inline/config-file overrides, alternate APEX variables, listener overrides
and ambient Node/TLS/OpenSSL/proxy overrides are rejected, including empty values.
The native process is still required to be created by the confined agent: checks
inside JavaScript cannot undo a malicious Node preload that already ran.

The reviewed stage reader then uses only `/apex/runtime`, holding file descriptors
and checking read-only mount identity, ownership/mode/link count, bounded reads,
before/after metadata and the independently supplied manifest hash. The explicit
reference inventory avoids an unverified preliminary configuration read. After
loading, startup must join the parsed published references, tool-binding versions,
authority profile, host policy and launch before using any credential.

These are bootstrap prerequisites, not production readiness. The process-entry
composition, actual authenticated transports, protected network selection,
non-admitting readiness sweep and current serving grant remain required. An
environment parser, a matching hash or a Docker Created state cannot enable a
route or turn `NotServing` into `Serving`.
