# Live Vertical Slice and Codebase Hardening Design

## Status

Approved for unattended execution by the repository owner. This document is
source material for the implementation plans; prose in the attached
architecture assessment is treated as a decision record, not as executable
instructions.

## Goal and boundary

Complete the active roadmap gate with one real, read-only `portfolio.read`
request:

`MCP stdio -> TypeScript gateway -> live Apex governance -> portfolio adapter -> response filter -> live Apex event admission -> NATS/analytics -> server-derived operator evidence`.

Only this vertical slice is active. Business writes, broad workflow support,
additional MCP domains, identity-provider expansion, autonomous trade, new
dashboards, and unrelated roadmap items remain on hold.

## Architecture

The TypeScript process remains a thin protocol adapter. It owns MCP transport,
strict request schemas, the deterministic portfolio adapter, response
filtering, and safe telemetry. It never stores mutable policy, authorizes from
local configuration in live mode, or maintains a second audit ledger.

`control-plane-api` becomes the live Apex governance authority for this slice.
It exposes a small `GovernanceGateway` gRPC service beside the existing control
service. The new RPCs require a dedicated gateway service credential and the
existing mandatory mTLS boundary; operator and agent credentials are never
accepted on this service. The first policy is intentionally narrow and
server-owned: one configured portfolio allowlist, one policy identity and
revision, and the existing restricted-field set.

`event-ingest` remains the only event admission authority. The TypeScript
gateway uses its existing `EventIngest.Ingest` RPC over mTLS plus a bearer token
bound to a dedicated gateway client certificate. The event is a metadata-only
`TOOL` event whose `data` is derived from the filtered execution record. The
gateway computes the same canonical event hash as Rust, sends the event through
the existing validation/idempotency/outbox boundary, and returns success only
after durable admission.

## Live credentials and configuration

- `APEX_MCP_GOVERNANCE_MODE=local|live`, default `local` for unit/dev use.
- Live governance endpoint, CA, client certificate, client key, and dedicated
  bearer token are required together. Secret paths are bounded to the configured
  trusted base by the client process.
- Live event endpoint, CA, client certificate, client key, and bearer token are
  required together. The event bearer is certificate-bound by `event-ingest`.
- The live client rejects missing, oversized, symlinked, or group/world-readable
  private material before opening a connection and never logs token contents,
  certificate keys, raw portfolio records, or gRPC server detail strings.
- All unary calls carry a bounded deadline and map transport failures to the
  gateway's existing safe `GOVERNANCE_UNAVAILABLE` or
  `EVENT_ADMISSION_FAILED` taxonomy.

## Request and event mapping

The gateway sends the existing typed request fields unchanged: authenticated
principal and agent, exact workspace/namespace, `portfolio.read`, `read`, the
opaque SHA-256 resource reference, `confidential`, and trace IDs. The server
returns the existing decision shape and the gateway verifies the exact policy
identity and scope before reading the adapter.

The event client creates a UUIDv7 event ID, a six-digit UTC timestamp, actor
`AGENT` equal to the authenticated agent, a bounded run ID derived from the
trace ID, gateway version metadata, and a Struct payload containing only the
execution metadata. The payload contains no raw portfolio fields. Numeric
values are bounded safe integers, and the client round-trips its Struct form
before hashing so protobuf number coercion cannot silently change the signed
meaning.

## Failure semantics

- Invalid MCP input is rejected before any network call.
- Denied or approval-required governance decisions do not call the portfolio
  adapter. The gateway attempts a redacted denial event; the safe denial result
  is preserved if that event attempt fails.
- Governance, adapter, and filtering failures are safe failures and never leak
  provider or server-controlled diagnostics.
- An allowed response is not reported successful unless event admission returns
  an accepted or duplicate receipt. Downstream NATS/analytics fanout remains
  asynchronous and is verified separately through server-derived evidence.
- Operator evidence is read from the server-side projection or its existing
  query contract; the gateway's in-memory event sink is not accepted as proof.

## Verification gate

The live slice is complete only when all of the following pass:

1. Gateway unit tests cover live request mapping, denial-before-adapter,
   filtering, canonical hash construction, safe errors, deadlines, and secret
   path rejection.
2. Rust tests cover governance RPC authorization, dedicated credential
   isolation, allowlist behavior, policy revision, and malformed request
   rejection.
3. Existing workspace checks, gateway typecheck/build/tests, and compose config
   validation pass.
4. The live CI job starts the existing mTLS stack, launches the built gateway
   in live mode, performs one real MCP call, and proves a matching server-side
   event/policy record through the existing operator evidence path.

## Follow-on hardening loop

After the live gate is complete, a separate loop performs controlled changes in
three dimensions only:

- split every tracked source/test file over 600 lines by responsibility, with
  no behavior change and each split independently tested;
- harden input, secret, credential, transport, logging, dependency, and
  concurrency boundaries using the repository's existing fail-closed patterns;
- improve measured throughput by reducing unnecessary serialization, avoiding
  blocking work on async workers, batching bounded fanout/IO where the current
  contracts permit it, and recording before/after benchmark evidence.

No performance change may weaken authorization ordering, durable admission,
idempotency, redaction, or the roadmap hold list.
