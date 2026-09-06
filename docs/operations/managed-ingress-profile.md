# Managed ingress profile (schema 3)

Status: explicit protected metadata selection and gateway validation. This is
not a serving deployment profile by itself. Container start, network ownership,
enrollment, readiness and admission remain independent required gates.

## Compatibility and purpose

The protected runtime-agent authority catalog now supports three exact modes:

| Catalog schema | Profile mode | `managed` map | Meaning |
| --- | --- | --- | --- |
| 1 | Absent | Absent | Existing dormant profile, unchanged |
| 2 | `managed_preparation` | Absent | Existing registration/preparation, unchanged |
| 3 | `managed_ingress` | Required | Explicit future ingress key purpose and policy selection |

Null is not absence. Alternate enum objects, arrays, unknown fields and
schema/mode combinations are rejected. The gateway ingress parser accepts only
schema 3. No legacy launch is upgraded by interpretation or environment fallback.
Schema 3 invokes the existing registration requirement; successful registration
still does not start its dormant container or grant admission.

The outer authority catalog keeps its existing version, validity interval,
scope selector and maximum 32 profiles. Selection writes the following envelope
to `authority-profile.json`. The selected bytes participate in the sealed stage
manifest; merely reproducing them or their hash does not prove provenance.

```json
{
  "schema_version": 3,
  "catalog_version": "authority-2026-09",
  "profile": {
    "installation_id": "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
    "workspace_id": "acme",
    "namespace_id": "prod",
    "proxy_id": "0191b7f1-7f2c-7c13-9a61-2f29f2be1001",
    "host_policy_version": "host-policy-v1",
    "reference": "managed-live",
    "version": "v1",
    "mode": "managed_ingress",
    "governance": {
      "endpoint": "https://control-plane.example",
      "tls_server_name": "control-plane.example"
    },
    "evidence": {
      "endpoint": "https://event-ingest.example:9443",
      "tls_server_name": "event-ingest.example"
    },
    "managed": {
      "evidence_agent_id": "managed-evidence",
      "upstream_credentials": "managed_upstream_v1",
      "network_policy": { "reference": "isolated-gateway", "version": "v1" },
      "ingress": {
        "port": 8080,
        "tls_server_name": "gateway.example",
        "edge_certificate_sha256": [
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ]
      }
    }
  }
}
```

All values above are examples; the repeated `a` fingerprint is a placeholder,
not a real enrolled edge. Use SHA-256 of the actual peer leaf certificate DER,
not a public-key fingerprint or a hostname. One or two unique nonzero lowercase
64-character fingerprints permit a bounded rotation overlap. A pin supplements
normal TLS verification; it never replaces CA, purpose, validity or identity checks.

## Exact boundaries

Governance/evidence endpoints are canonical HTTPS origins, optionally ending in
`/`, with no userinfo, other path, query, fragment or backslash. Their hostname
must equal the protected lowercase DNS TLS name. IP literals, uppercase aliases
and alternate server-name overrides refuse in schema 3. Schema 1/2 retain their
previous accepted transport syntax.

Ingress uses fixed port 8080 and a lowercase DNS name (253 characters maximum,
labels up to 63, no wildcards, trailing dots, underscores or numeric-only address).
Only this new profile assigns the WORKLOAD CA/certificate/key triplet the
ingress-server purpose. Governance and evidence retain separate client TLS roles.
The gateway checks all 13 distinct deployment material roles and references;
actual bytes, TLS purpose and key separation still need the stage/TLS owners.
Health remains the separate launch-defined port 8081; this profile does not
expose or relay it or introduce an agent-health bypass.

The network-policy reference/version select protected installation policy; they
are not arbitrary CIDRs, DNS addresses or an instruction to create a network.
`managed_upstream_v1` is an explicit credential format selection for the new
bootstrap. Its bundle reader is a separate integration requirement. It does not
make a legacy token file into TLS material or add ambient operating-system trust.

Scope/version identifiers use the existing ASCII letters/digits/`_.:-` grammar,
exclude consecutive dots, and have a 128-character limit for profile versions,
references and evidence-agent identity. Installation/proxy IDs remain canonical
UUIDv7; workspace/namespace retain existing scope limits. No raw secret belongs
in this file; tool material remains addressed by published versioned references.

## Gateway consistency checks

`parseManagedIngressProfile` is pure and opens no files or sockets. It copies at
most 256 KiB of original native byte input, rejects invalid UTF-8, duplicate keys
(including escaped duplicates), unknown keys and non-integer numeric tokens.
It independently revalidates the supplied generated runtime configuration and
launch/hash, then matches every deployment-binding field to that launch. The
selected profile must match installation/scope/proxy and authority reference/
version. Output is a deeply frozen defensive copy. Failures use a static error,
not submitted JSON, keys or endpoint credentials.

These checks establish consistency only. Production startup must obtain the
bytes through the protected stage reader with an independently supplied expected
manifest hash, validate tool bindings and host-policy selection, establish actual
authenticated transports, inspect network confinement, and complete the
non-admitting readiness sweep before any current SERVE grant can admit a call.
Do not mark these later gates complete from parser tests.
