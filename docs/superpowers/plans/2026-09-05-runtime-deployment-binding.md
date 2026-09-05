# Runtime deployment binding implementation plan

> Execute the approved design using test-driven development and scoped review.

**Design:** [Online runtime deployment binding](../specs/2026-09-05-runtime-deployment-binding-design.md)

**Goal:** provide a usable authoritative resolution RPC and pinned agent client;
keep container execution fail-closed. Work only in the working-mcp-gateway worktree.

**Status:** implemented and independently reviewed September 5, 2026. The real
production-root/PostgreSQL resolution path passes on Windows and Linux. See
[release evidence](../../operations/mcp-gateway-release-evidence.md) for executed
checks and review fixes. This is not completion of parent Task 7 or authorization
to execute containers. The user authorized commit, push and merge on September 5,
2026, after implementation handoff.

## 1. Contract and deployment catalog

- Add proxy_runtime_deployment.proto: separate service, snapshot, deployment
  document/profile and RuntimeDeploymentImage (digest, image_ref) messages.
- Include in both Rust build scripts and regenerate TypeScript artifacts.
- Add private runtime_authority/deployment.rs and tests: strict generated JSON
  decoder, validity/version checks, unique exact selectors, compiler adapter.
- Prove valid profile compiles the verified revision, wrong selectors/host policy
  refuse, duplicate/unknown/malformed metadata refuse, no raw error details escape.

## 2. Control-plane resolution

- Extend optional protected policy files and shared refreshed generation to include
  the catalog; preserve check-only opt-in and bounds when absent.
- Reuse original TLS authorization and fixed PostgreSQL lookup; compile exclusively
  from its verified RuntimeOperationSnapshot. Recheck metadata/lease at handoff.
- Register separate bounded resolution service only with explicit bindings setting.
- Test replacement, rotation, expiry and startup fail-closed behavior.

## 3. Agent client

- Add generated deployment client to the existing pinned channel; share admission
  and request construction/validation where practical without weakening checks.
- Return private ResolvedDeployment; validate authority and configuration relation,
  manifest, version, size and monotonic bounds. No caller manifest argument.
- Test modified config and authority fields, stale responses, deadline/refusal,
  and valid output through actual client calls.

## 4. Integration and handoff

- Exercise real mTLS plus PostgreSQL published revision resolution and refusal
  cases using existing owned test fixtures; run focused regression tests and Clippy.
- Independently review all tracked/untracked implementation changes for this slice.
- Update provisioning documentation, roadmap and release evidence with commands
  actually run and explicit remaining production ingress/container/tracing work.
- Commit, push and merge only with separate user authorization (received September
  5, 2026). Do not enable production execution or mark Task 7 complete.
