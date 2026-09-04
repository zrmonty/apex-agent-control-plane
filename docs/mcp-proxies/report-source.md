# MCP Proxy Research Source Ledger

**Purpose:** Internal traceability for `docs/superpowers/specs/2026-09-04-mcp-proxy-platform-design.md`.
**Research date:** 2026-09-04.

This ledger separates externally sourced protocol and security claims from repository-specific decisions. External sources inform the design; they do not override the repository roadmap or the approved isolated-container architecture.

## Source classes

| Class | Source | Used for |
|---|---|---|
| Repository | `docs/architecture/Operator UI Framework.md` | React/Vite shell, generated clients, secure session boundary, server-side authority |
| Repository | `apps/operator-ui/README.md`, `apps/operator-ui/src/main.tsx` | Existing routes, navigation, UI states, preview status |
| Repository | `apps/mcp-gateway/README.md`, `apps/mcp-gateway/src/*` | Current thin stdio gateway, `portfolio.read`, Apex delegation, filtering, evidence |
| Repository | `apps/control-plane-api`, `crates/apex-policy`, `contracts/proto/apex/v1` | Operator auth, mTLS, approvals, durable control/evidence, contract direction |
| Decision record | `C:\Users\zrmon\Downloads\apex_architecture_assessment_and_mcp_plan.md` | Existing product boundary, thin MCP data plane, RIA enforcement classes, non-goals |
| Protocol | MCP architecture and transport specifications | Host/client/server roles, stdio, Streamable HTTP, origin validation, bounded transport behavior |
| Protocol/security | MCP authorization and security guidance | Protected-resource metadata, OAuth discovery, PKCE, resource indicators, audience binding, token non-passthrough |
| Standards | IETF RFC 9700, RFC 8707, RFC 9728 | OAuth security practice, resource/audience binding, protected-resource discovery |
| Security architecture | NIST SP 800-207 | Policy enforcement point and continuous verification model |
| Application security | OWASP MCP, SSRF, and command-injection guidance | Untrusted tool data, allowlists, URL safety, fixed CLI arguments |
| Runtime security | Docker Engine security and rootless mode | Non-root execution, capability reduction, runtime isolation |
| Observability | OpenTelemetry GenAI semantic conventions | Operation naming, sensitive tool argument/result handling, trace attributes |

## Claim and gap matrix

| Claim or decision | Evidence | Design implication | Remaining gap |
|---|---|---|---|
| MCP separates host, client, and server responsibilities | [MCP architecture](https://modelcontextprotocol.io/specification/2025-06-18/architecture) | Keep lifecycle and policy in Apex; keep protocol/adapters in the proxy | Exact Apex API adapter is implementation work |
| stdio and Streamable HTTP have different trust/transport rules | [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) | Configure transport per ingress and upstream; do not treat stdio as HTTP OAuth | Compatibility matrix for supported SDK revisions |
| HTTP MCP authorization uses protected-resource metadata and OAuth discovery | [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | Per-proxy HTTP identity, discovery, PKCE, scope, issuer, and audience validation | Keycloak/enterprise provider mapping |
| Inbound tokens must not be passed through to upstreams | [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) | Separate upstream credential binding per upstream | Token exchange implementation and provider contract |
| Zero-trust enforcement separates policy decision and enforcement | [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Apex decides; isolated proxy enforces; controller reconciles desired state | Runtime provider implementation |
| CLI execution requires command and argument allowlists | [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) | Fixed executable identity and typed argv; no arbitrary shell | Sandbox implementation and platform-specific process-tree kill |
| Dynamic upstream URLs create SSRF risk | [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Deny-by-default egress, DNS/IP/redirect revalidation, metadata blocking | Cloud/network provider enforcement details |
| Tool descriptions/results are untrusted and can contain sensitive content | [OWASP MCP Security](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | Quarantine discovery, filter output, never promote content to policy or commands | Adversarial corpus for proxy-specific testing |
| Container privileges and capabilities should be reduced | [Docker Engine security](https://docs.docker.com/engine/security/), [Docker rootless mode](https://docs.docker.com/engine/security/rootless/) | Rootless/non-root, read-only rootfs, dropped caps, no runtime socket | Provider-specific enforcement verification |
| Tool spans and content may contain sensitive data | [OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/) | Metadata-only default telemetry; opt-in bounded content capture | Exact Apex event field mapping |

## Repository facts used

- The operator UI has a React/Vite scaffold but no live proxy management route.
- The current gateway is a thin TypeScript stdio implementation with one deterministic read-only tool.
- The control plane already has separate operator and workload credential concepts, mTLS, approvals, durable outbox behavior, and command status paths.
- Existing roadmap holds remain active except for the explicitly approved MCP proxy surface.

## Research limitations

- No third-party proxy product was treated as an authority for Apex architecture.
- The design does not assume a particular secret manager, Kubernetes distribution, service mesh, or cloud provider.
- Performance targets remain to be set by benchmark after the first isolated runtime exists.
- The current repository does not yet contain the proxy management contract, reconciler, runtime provider, or live UI route; those are implementation phases, not completed capabilities.
