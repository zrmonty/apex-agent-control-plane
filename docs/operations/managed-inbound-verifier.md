# Staged inbound JWT verifier (Task 4I)

`createManagedInboundVerifier(stagedJwksBytes, generatedRuntimeConfiguration)`
creates a local verifier implementing `InboundTokenVerifier` plus owned
`close(): Promise<void>`. This is a dormant material factory, not root wiring,
enrollment, provenance or permission to serve. It never fetches the configured
JWKS URI or accepts paths, remote key resolution, ambient algorithms or a caller
crypto implementation. The internal test seam is not exported by the public entry.

## Configuration and keys

The factory revalidates the generated message shape, complete runtime metadata
and manifest hash, then copies issuer, exact resource audience, proxy ID and all
required scopes. The hash establishes consistency, not trusted publication.

Staged bytes must be an actual nonshared native Uint8Array (Buffer is supported),
1..65,536 bytes. Foreign-realm native byte views work; proxies, detached/shared
buffers and coercible objects do not. Native copying avoids user-defined byte
getters, iterators and conversion methods. The temporary byte copy is wiped;
the caller still owns its original bytes.

Original JWKS JSON uses strict UTF-8 and duplicate-key detection. It contains
only `keys`, with 1..32 entries and distinct 1..128-character ASCII kids. Each
key has explicit `alg`. Optional `use` must be `sig`; optional `key_ops` must be
exactly `["verify"]`. Unknown/private/symmetric/remote-certificate fields refuse.

Supported keys are RSA/RS256 (2048..8192-bit canonical nonzero-leading odd modulus,
exponent 65537), EC/ES256 (P-256, exact native-valid coordinates), and OKP/EdDSA
(Ed25519). Public keys are imported once, with no hot-path key I/O. These checks
cannot prove an RSA modulus was generated securely or its factors remain secret.

Node native import alone accepts malformed/weak Ed25519 points, including an
identity key that permits forged signatures. A bounded public-point preflight
therefore requires canonical decoding, curve membership and a nonidentity
prime-order point. Its decoding/addition follows [RFC 8032 sections 5.1.1–5.1.4](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3);
the subgroup/nonidentity requirement is this factory's strong-key policy.
This helper never signs or verifies JWT signatures: those remain real JOSE/native
cryptography. Variable-time public-point arithmetic handles no private material.

## Token and claim boundaries

Compact JWTs are primitive strings <=8192 characters, exactly three canonical
unpadded base64url segments. Decoded header/payload/signature caps are
1024/6144/1024 bytes, additionally constrained by the whole-token cap. Original
header and payload JSON are checked before crypto, including duplicates, strict
UTF-8, depth and passive-data limits. Header fields are exactly `alg`, `kid` and
optional `typ` (`JWT` or `at+jwt`); no key-selection URLs, embedded JWK, `crit` or
`b64`. Key selection requires both exact kid and algorithm.

Claims bind to configured issuer, one exact resource audience (string or singleton
array), proxy_id (no camelcase alias), subject grammar <=256 and unique nonempty
space-separated scopes <=4096 containing every published required scope.
`exp` and optional `nbf`/`iat` must be exact integer seconds in 0..253402300799.
Original numeric lexemes are checked so IEEE-754 rounding cannot turn fractional
or underflowed NumericDates into integers. Exactly integral decimal/exponent
spellings remain accepted. This uses Node24 JSON reviver source context; Node24+
is already the gateway's runtime requirement. Bounded unrelated claims are ignored,
never returned. No time leeway: exp>now; nbf/iat<=now, including after crypto.

The result is a fresh frozen existing claims shape only; singleton audience arrays
are frozen copies. `authenticateInbound` remains a separate defense-in-depth
consumer, not a replacement for signature verification.

## Physical lifetime

Each verifier admits at most 128 concurrent operations, retaining their slots
through the actual cryptographic promise settlement. Synchronous parsing also
occupies its operation's slot. Saturation refuses without starting more crypto.
An original monotonic five-second budget spans each verify call's pre/post-crypto
checks. There is no timeout race, timer-based slot release or pretend WebCrypto
cancellation. A held crypto promise can keep verification and closure pending
beyond that budget; after settlement an overdue result refuses.

`close()` is irreversible and idempotent, immediately blocks admission, rejects
late authentication and returns the same drain promise. That promise resolves
only after every admitted operation settles; then retained public-key references
are cleared. Clock exceptions, invalid samples or monotonic regression also close
the verifier. Reentrant close during a clock sample cannot dispatch new crypto.
Ordinary bad tokens/expired operations fail individually without poisoning an
otherwise healthy verifier. All factory/verify failures have the static message
`managed inbound verifier refused safely` without causes or token/key detail.

If native crypto never settles, the owning root's trusted shutdown/termination
policy must resolve the process lifetime. This helper does not claim physical
native cancellation, whole-process zeroization or freeing resources by timeout.
Already delivered claims cannot be retracted; the root must still apply its own
current-call/epoch gate. Rotation requires a new staged verifier; no implicit
refresh, replay or network recovery is performed.

## Evidence boundary

Focused tests cover all three real algorithms, rotation, a real unsigned
identity-point exploit regression, correctly signed duplicate/fractional JWTs,
JWKS/claims/config limits, byte-hook isolation, 128-operation saturation and
original deadline/clock/close behavior. Held-job tests deliberately delay an
internal wrapper's settlement after delegating to real JOSE. They prove owner
retention, not the ability to stall/cancel an OS cryptographic primitive.
The scratch native recipe reruns the suite as Linux UID/GID10001 with a read-only
root, dropped capabilities and network none. Synthetic test keys are generated
in process, never trusted or enrolled. Independent review is required before
integration; no root readiness or Serving claim is made here.
