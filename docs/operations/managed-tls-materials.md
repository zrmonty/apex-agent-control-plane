# Managed TLS material preflight

The managed bootstrap component `bootstrap/tls-role.ts` performs bounded local
preflight over staged bytes. It does not open files or sockets, enroll a
credential, establish protected-profile provenance, or enable Serving.

Governance and evidence use distinct client identities. The workload triplet in
the new ingress profile is reserved for the gateway's server identity. The
three certificates and their public keys must be distinct: reissuing a different
certificate around the same private key does not create a separate role.
Sharing a trust root is allowed. Legacy dormant/preparation profiles do not
gain ingress meaning from these helpers.

## Supported material shape

The first explicit profile accepts one self-signed issuing CA certificate, one
directly issued non-CA leaf and one unencrypted PKCS8 private key per role. Each
input buffer is limited to 64 KiB. It rejects ambiguous certificate/key bundles,
intermediates, extra text, non-ASCII PEM and noncanonical base64/PKCS8 encoding.
Bundle/rotation support requires a separately validated profile, not fallback.

Checks include certificate validity (inclusive start, exclusive expiry), CA and
leaf roles, issuer metadata and signatures, leaf/private-key correspondence,
and explicit TLS extended key usage. Supported key types are RSA 2048–8192,
P-256/P-384 and Ed25519. Supported signatures are RSA SHA-256/384/512,
ECDSA SHA-256/384/512 and Ed25519. Unsupported variants fail closed.

A server role also requires its protected lowercase DNS name to match a DNS SAN
exactly. Common-name fallback and wildcards are disabled. Client preflight does
not accept a server-name override. A leaf must explicitly permit its required
TLS purpose; only TLS server/client EKUs are accepted.

These checks are not a complete PKIX path validator. Node's issuer check compares
metadata, and signature verification does not perform other certificate checks.
[Node X509 documentation](https://nodejs.org/docs/latest-v24.x/api/crypto.html#x509verifypublickey)
describes that distinction. Actual transports must still enforce CA/name checks,
`rejectUnauthorized`, required mutual TLS and their bounded physical lifetimes.
The production root must complete a real ingress readiness handshake before
granting Serving; preflight is not a substitute for that receipt or revocation
policy.

## Ownership

The preflight copies staged material before parsing and returns an opaque frozen
handle containing leaf/public-key SHA-256 digests and the earliest CA/leaf expiry
in integer Unix microseconds. `tlsRoleMaterial()` returns separate owned buffer
copies. Mutating the original stage or a returned copy cannot change the
preflight's retained material. A copied or forged handle cannot retrieve it.

The composition root owns the stage, returned material copies, TLS clients and
servers separately. It must wipe/release each copy when its last native consumer
has physically closed. `disposeTlsRole()` wipes only the preflight's own buffers
and invalidates further access. JavaScript strings and OpenSSL internal key
objects are not claimed to be fully zeroizable.

## Tests

The test module includes self-contained, explicitly synthetic PKI. Never enroll
its keys or use them outside tests. Its regeneration script prints JSON and does
not touch trusted-host PKI, release keys or local trust configuration.

Focused tests cover wrong key/purpose/SAN, absent SAN/EKU, validity boundaries,
bundles and malformed inputs, same-key reissuance, disposal, immutable copying,
and a real TLS 1.3 mutual-authentication round trip. Windows and an isolated,
unprivileged, network-disabled Linux container have run the same tests. Local
loopback TLS in a component fixture is not evidence of production confinement,
enrollment, published revision binding or complete readiness.
