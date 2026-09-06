# Managed evidence enrollment

Event-ingest has a distinct protected multi-workload credential mode. Set
`APEX_MANAGED_EVIDENCE_ENROLLMENT_FILE` to an absolute file path strictly below
the absolute `APEX_TRUSTED_SECRET_BASE`. Its presence selects this mode. Even an
empty simultaneous legacy setting is rejected: unset `APEX_FILE_BEARER_MODE`,
`APEX_BEARER_TOKEN_FILE`, `APEX_BEARER_AGENT_ID`, `APEX_BEARER_SUBJECT`,
`APEX_ALLOWED_SCOPES`, and `APEX_BEARER_CERT_SHA256`.

Without the new selector, the existing FileBearerResolver and its mandatory
`APEX_FILE_BEARER_MODE=single-agent-staging` acknowledgement remain unchanged.
Missing credentials never enable anonymous admission. Other ingest startup
validation retains its existing order, including NATS/durability construction
before credential construction. TLS remains mandatory with actual client
certificate verification; enrollment cannot substitute metadata for a TLS peer.

## Protected document contract

The document is JSON, with exactly these fields at each level:

```json
{
  "schema_version": 1,
  "version": "enrollment-1",
  "valid_from_unix_us": 1788566400000000,
  "expires_at_unix_us": 1788652800000000,
  "enrollments": [
    {
      "installation_id": "01990000-0000-7000-8000-000000000001",
      "workspace_id": "work",
      "namespace_id": "production",
      "proxy_id": "01990000-0000-7000-8000-000000000002",
      "subject": "evidence-proxy-a",
      "agent_id": "proxy-a-evidence",
      "credentials": [
        {
          "certificate_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "token_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      ]
    }
  ]
}
```

The example contains illustrative digests and a fixed illustrative interval;
it is not a usable launch credential. Only SHA-256 digests belong here, never raw
tokens. The protected launch-profile owner separately supplies the matching
token and TLS key to its exact proxy workload.

Limits and validation:

- Original bytes: 1–262144, including whitespace; no trailing JSON or BOM.
- `schema_version`: the JSON integer `1`. `version`: safe identifier, 1–128 bytes.
- Times: positive canonical JSON integer tokens in signed SQL `i64` range,
  `valid_from_unix_us < expires_at_unix_us`. No string coercion, floating point,
  exponent, leading zero, sign, or rounding. Start is inclusive; expiry exclusive.
- At most 64 enrollments. An empty array revokes everyone. Each enrollment has
  1–2 explicit credentials, permitting overlap during rotation within that proxy.
- Installation/proxy IDs: exact lowercase RFC-variant UUIDv7. Subject, agent,
  workspace and namespace: existing safe 1–256 byte identifier grammar
  (`A-Z a-z 0-9 . _ : -`, without `..`); no normalization or wildcard scopes.
- Digests: exactly 64 lowercase hex characters. Duplicate certificate/token
  pairs, duplicate logical proxies, and reused agent IDs are refused.
- Unknown and decoded duplicate keys at every level are refused. The bounded
  parser accepts only the schema's JSON types, with depth at most 5 (root at 0),
  2048 value nodes, 8 fields/object, 64 items/array and 256 decoded bytes/string.
  ASCII JSON escapes are decoded before identifier/duplicate checks.

Each lookup hashes a nonempty, at-most-4096-byte ASCII graphic bearer token and
compares the complete digest pair with the actual TLS leaf digest. It selects
exactly one fixed subject/agent and one `workspace_id/namespace_id` scope. It
does not consult the event body for identity. The incumbent verifier invokes
the resolver on every request; ephemeral deny hints cannot create an allow.
Canonical admission still requires the authenticated bound agent to equal both
`envelope.agent_id` and the AGENT actor ID, with exact authenticated scope.
Accepted events use the existing required durable outbox/idempotency pipeline.

## Filesystem and ownership

Production protected reads support Linux x86_64/aarch64 only, with `/proc`
available. Unsupported platforms (including Windows) fail closed. There is no
production ACL waiver or generic injected-reader API. Windows tests exercise a
private `cfg(test)` reader seam; they do not certify production ACL parity.

Protected-open flags are selected at compile time for each architecture:
`O_NOFOLLOW/O_DIRECTORY/O_NONBLOCK` are `0x20000/0x10000/0x800` on x86_64 and
`0x8000/0x4000/0x800` on aarch64. Tests check both sets against the Linux UAPI
definitions and compare the native selection against installed kernel headers
in the opt-in Linux harness. The x86_64 runtime tests do not constitute aarch64
runtime proof; the latter remains unexecuted in the current verification fixture.

Every path component is opened under held directory descriptors using Linux
`O_NOFOLLOW`; directories also require `O_DIRECTORY`, and leaf open uses
`O_NONBLOCK` before its regular-file check. All ancestors must belong to root
or the effective service UID and forbid group/other writes. The regular file
must belong to root or the service UID, have one hard link, and have no execute,
group or other permission bits (normally `0400` or `0600`). Use a readable file
for the service UID. The entire hierarchy remains operator-controlled.
Relative paths, parent traversal, symlinks, special files, broad modes and
oversized files are refused. Descriptor metadata and a fresh confined path walk
are checked after reading. Replace the file atomically inside the protected
hierarchy; do not use symlink-based projected-secret rotation for this mode.

One physical thread, owned by the synchronous startup root, performs the first
read and all refreshes. A full valid first snapshot precedes listener setup.
Refresh waits one second after each read; reads never overlap. Authentication
checks a five-second maximum age measured from the *start* of the successful
read and checks document expiry on each call. An invalid/unreadable replacement
publishes a poisoned snapshot immediately; it never falls back to last good.
A subsequent wholly valid read may restore service. Removal of an enrollment
revokes its credentials. A physically stuck read cannot extend snapshot life.

Dropping the owner closes authentication before joining its reader. Startup
construction failures and listener-return paths retain that owner; the explicit
root join occurs before Tokio runtime teardown. A stuck read intentionally
holds shutdown until the physical read returns, without timeout detachment or
a replacement thread. This change does not add signal handling or redesign the
incumbent fanout/reaper workers. Those existing blocking loops can prevent full
runtime teardown after listener failure even though the enrollment reader has
already been joined; broader worker lifecycle changes need separate coordination.

## Error and verification boundary

Document, protected-read, freshness-at-startup and worker-start failures report
the static `managed evidence enrollment refused` error with no source chain,
path, profile contents, token or certificate details. Mode conflict reports the
selector name and legacy incompatibility. Request failures use the incumbent
`UNAUTHENTICATED` error; canonical actor/scope denials retain incumbent errors.

The scoped tests cover strict schema, exact identities, rotation, poisoning,
expiry, held-read freshness and physical shutdown ownership. The opt-in real
mTLS test uses existing `APEX_BROWSER_TEST_PKI_DIR/trusted-host` certificates,
two identities and disposable fsync-backed journals, and reopens the outbox to
verify only the two authorized canonical events survived. Linux protected-read
tests run independently with `APEX_EVIDENCE_LINUX_TEST_BASE` pointing to a
protected disposable directory. Neither test enables managed gateway Start,
Ready, routes, publication or a production governance authority factory.
