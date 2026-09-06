# Managed upstream credential bundles

The schema-3 `managed_ingress` authority profile selects
`upstream_credentials: "managed_upstream_v1"`. Each published upstream
`credentialRef` resolves exactly one versioned, sealed `tool-<SHA256(reference)>`
file. This format does not reinterpret legacy bearer-token files. The immutable
tool-bindings document and runtime configuration select the reference/version;
the file itself cannot choose a destination, request header, path or authority.

## Format

The original file is strict UTF-8 JSON, at most 65,536 bytes, with no duplicate
keys. Whitespace is accepted. `schema_version` has the numeric value 1. Unknown
fields, missing required fields and mode-incompatible fields are rejected.

| `authentication` | Required fields in addition to schema/mode |
| --- | --- |
| `server_tls` | `server_ca` |
| `bearer` | `server_ca`, `token` |
| `mtls` | `server_ca`, `client` |
| `mtls_bearer` | `server_ca`, `client`, `token` |

`server_ca` is the PEM trust anchor for the **remote server**. `client` is an
exact object containing PEM `ca`, `cert`, and `key` for the gateway's upstream
client identity. The client issuer and remote server trust anchor may differ.
There is no ambient operating-system CA fallback or authentication downgrade.
TLS-only is an explicit selected mode, not recovery from failed credentials.

Example shape (placeholders are deliberately not usable credentials):

```json
{
  "schema_version": 1,
  "authentication": "mtls_bearer",
  "server_ca": "<one PEM server-trust CA>",
  "client": {
    "ca": "<one PEM client-issuer CA>",
    "cert": "<one PEM client leaf>",
    "key": "<one unencrypted PKCS8 PEM private key>"
  },
  "token": "<dedicated upstream bearer token>"
}
```

Bearer syntax is 16–4096 ASCII characters from `A-Z a-z 0-9 . _ ~ + / -`,
followed by zero to two `=` characters. The maximum including padding is 4098
characters. Do not include the `Bearer ` prefix. Whitespace, control characters,
line breaks, embedded padding and additional authorization headers are refused.
Inbound user tokens must never supply this field.

## Certificate profile and ownership

Version 1 accepts one canonical self-signed CA per trust role and a directly
signed client leaf, not concatenated chains or encrypted keys. Server trust
preflight checks CA identity, self-signature, supported strong key/signature,
validity and TLS context construction. Client material uses the purpose-aware
[TLS role preflight](managed-tls-materials.md). Expiry is an exact integer Unix
microsecond value, with inclusive start and exclusive expiry. Combined expiry
is the earliest server CA, client CA or client leaf expiry.

These checks are **not full PKIX, revocation validation, protected provenance,
or readiness**. The actual guarded connection must still validate the peer's
chain, original hostname and ALPN. A client `secureConnect` event alone does not
prove the server accepted the client certificate; application readiness must
also succeed. The production root must prohibit upstream client-key reuse with
governance, evidence or ingress identities using the exposed public-key digest.

`parseManagedUpstreamCredential(bytes, nowUnixUs)` performs no I/O and returns
an opaque immutable handle containing only mode, expiry and optional client
fingerprints. `upstreamCredentialMaterial(handle)` returns fresh owned Buffers;
the receiving transport must retain and wipe its copies after physical closure.
`disposeUpstreamCredential(handle)` revokes future access and wipes the decoder's
copies. Callers cannot obtain material from copied or forged handles. Original
input is not modified. JavaScript JSON strings and native crypto/TLS copies are
garbage-collected; this is not a whole-process zeroization guarantee.

## Verification and rollout boundary

Tests cover all four modes, exact keys, UTF-8/duplicate refusal, byte/token bounds,
passive native-byte capture, key/purpose mismatch, expiry at one-microsecond
boundaries, copied ownership and disposal. Native tests use separate synthetic
server/client PKIs through the actual guard and TLS connector, including wrong
name, untrusted server CA and rejected client CA. They run on Windows and Linux.

This is the credential decoder dependency only. Protected bootstrap integration,
runtime role-separation checks, readiness, network confinement and Serving are
separate gates. No credentials are enrolled, published, logged or deployed by
these tests. Updating material requires the protected versioned staging workflow,
not editing a live mounted file.
