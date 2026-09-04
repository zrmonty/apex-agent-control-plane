# Active codebase hardening review

Date: 2026-09-03
Scope: the active MCP/governance/event vertical slice and its local reference
deployment. Held roadmap features remain out of scope.

## Findings addressed

- Live MCP gRPC targets now reject URL userinfo, path/query/fragment
  components, raw whitespace/backslash/dot-segment input, and slash-bearing
  target strings instead of silently discarding attacker-controlled endpoint
  material. RPC deadlines are finite, positive, and capped at 30 seconds.
- Live secret loading requires a real trusted directory, resolves relative
  secret names beneath that directory, refuses symlinked secret files, keeps
  canonical paths inside the directory, bounds file sizes, and rejects empty,
  malformed, short, whitespace-bearing tokens. Secret bytes are loaded once
  per live client and never included in errors or telemetry.
- The gateway reference container now has a read-only root filesystem and a
  temporary `/tmp`; its data volume remains the only writable application
  state. Secret staging remains a separate 0600, least-privilege init step.
- Host-side secret staging rejects pre-existing symlink output directories,
  symlinked source roots/entries, and symlinked destination files before
  copying material. PKI generation rejects symlinked or non-directory output
  paths before writing any fixture.
- Rust event admission continues to enforce bounded protobuf size/depth,
  canonical integrity hashes, metadata-only security findings, duplicate
  authorization rejection, agent/certificate credential separation, and
  fail-closed local fallback behavior.
- JSON-to-`Struct` conversion preserves the legal `__proto__` field as data
  without invoking JavaScript's prototype setter; the regression test also
  confirms that the global object is not polluted.

## Regression coverage

The focused gateway suite covers endpoint credential smuggling, silently
discarded endpoint URL components, surrounding/raw whitespace at both the
configuration and normalization boundaries, trusted-base confinement,
non-directory bases, and symlink refusal when the host permits symlink
creation. The deployment suite covers host-secret symlink refusal; the MCP
test, typecheck, and build gates also run in pull-request CI. Existing Rust
adversarial suites cover duplicate auth headers, credential crossover,
malformed resources, deep/oversized Struct values, raw-error suppression,
event hash mismatch, and scope isolation.

## Residual deployment note

Windows does not expose a portable POSIX mode-bit check, so live secret
material is protected by canonical path confinement, symlink refusal, bounded
reads, and the container's read-only secret mount. Production deployments
must additionally enforce host ACLs and secret-manager ownership outside this
repository's local reference profile.
