#!/usr/bin/env python3
"""Generate adversarial client certificates for live transport-admission tests.

Companion to `deploy/compose/live-mtls/generate_pki.py`. That script mints the
*authorized* materials; this one mints everything a client must NOT be able to
authenticate with, so `tests/adversarial_transport.rs` can prove the gateway
rejects each one on a real TLS handshake rather than only in configuration.

LOCAL TEST FIXTURES ONLY. Never use these materials anywhere real.

Outputs (under --out, default `<live-mtls>/adversarial`):

| Basename                | Attack it proves is rejected                     |
|-------------------------|--------------------------------------------------|
| `rogue-ca`              | Client signed by a CA the gateway does not trust  |
| `wrong-ca-client`       | Leaf from that untrusted CA                       |
| `self-signed-client`    | Self-signed leaf presented as its own issuer      |
| `expired-client`        | Trusted CA, `notAfter` in the past                |
| `not-yet-valid-client`  | Trusted CA, `notBefore` in the future             |
| `wrong-san-client`      | Trusted CA, unexpected CN/SAN                     |
| `server-eku-client`     | Trusted CA, serverAuth EKU only (no clientAuth)   |

`wrong-san-client` and `server-eku-client` are valid to the CA. They exist to
separate "the CA chain is checked" from "the leaf identity is pinned": the
gateway must still reject them because their SHA-256 does not match
`APEX_BEARER_CERT_SHA256`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[3]
DEFAULT_LIVE = REPO / "deploy" / "compose" / "live-mtls"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)


def _make_ca(out: Path, basename: str, common_name: str):
    key = _key()
    subject = _name(common_name)
    now = dt.datetime.now(dt.UTC)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_key(out / f"{basename}.key", key)
    _write_cert(out / f"{basename}.pem", cert)
    return key, cert


def _issue(
    *,
    out: Path,
    basename: str,
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    eku: list | None = None,
) -> x509.Certificate:
    key = _key()
    now = dt.datetime.now(dt.UTC)
    san: list[x509.GeneralName] = [x509.DNSName(n) for n in (san_dns or ["apex-ingest"])]
    san.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in (san_ips or ["127.0.0.1"]))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (now - dt.timedelta(minutes=1)))
        .not_valid_after(not_after or (now + dt.timedelta(days=30)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage(eku or [ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    _write_key(out / f"{basename}.key", key)
    _write_cert(out / f"{basename}.pem", cert)
    return cert


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", type=Path, default=DEFAULT_LIVE)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()
    live: Path = args.live
    out: Path = args.out or (live / "adversarial")
    out.mkdir(parents=True, exist_ok=True)

    trusted_ca_key_path = live / "secrets" / "ca.key"
    trusted_ca_path = live / "secrets" / "ca.pem"
    if not trusted_ca_key_path.is_file() or not trusted_ca_path.is_file():
        raise SystemExit(
            f"missing trusted CA under {live / 'secrets'}; run live-mtls/generate_pki.py first"
        )
    trusted_ca_key = serialization.load_pem_private_key(
        trusted_ca_key_path.read_bytes(), password=None
    )
    trusted_ca = x509.load_pem_x509_certificate(trusted_ca_path.read_bytes())

    now = dt.datetime.now(dt.UTC)
    fingerprints: dict[str, str] = {}

    def record(basename: str, cert: x509.Certificate) -> None:
        fingerprints[basename] = cert.fingerprint(hashes.SHA256()).hex()

    # 1. Untrusted CA and a leaf beneath it.
    rogue_key, rogue_ca = _make_ca(out, "rogue-ca", "Apex Rogue Test CA")
    record("rogue-ca", rogue_ca)
    record(
        "wrong-ca-client",
        _issue(
            out=out,
            basename="wrong-ca-client",
            common_name="apex-ingest-http",
            ca_key=rogue_key,
            ca_cert=rogue_ca,
        ),
    )

    # 2. Self-signed leaf claiming to be the authorized client.
    self_key, self_cert = _make_ca(out, "self-signed-client", "apex-ingest-http")
    record("self-signed-client", self_cert)

    # 3. Trusted CA but outside its validity window.
    record(
        "expired-client",
        _issue(
            out=out,
            basename="expired-client",
            common_name="apex-ingest-http",
            ca_key=trusted_ca_key,
            ca_cert=trusted_ca,
            not_before=now - dt.timedelta(days=30),
            not_after=now - dt.timedelta(days=1),
        ),
    )
    record(
        "not-yet-valid-client",
        _issue(
            out=out,
            basename="not-yet-valid-client",
            common_name="apex-ingest-http",
            ca_key=trusted_ca_key,
            ca_cert=trusted_ca,
            not_before=now + dt.timedelta(days=1),
            not_after=now + dt.timedelta(days=30),
        ),
    )

    # 4. Trusted CA, valid window, but a different identity / fingerprint.
    record(
        "wrong-san-client",
        _issue(
            out=out,
            basename="wrong-san-client",
            common_name="attacker-workload",
            ca_key=trusted_ca_key,
            ca_cert=trusted_ca,
            san_dns=["attacker.invalid"],
        ),
    )
    record(
        "server-eku-client",
        _issue(
            out=out,
            basename="server-eku-client",
            common_name="apex-ingest-http",
            ca_key=trusted_ca_key,
            ca_cert=trusted_ca,
            eku=[ExtendedKeyUsageOID.SERVER_AUTH],
        ),
    )

    authorized = live / "secrets" / "ingest-http-client.pem"
    if authorized.is_file():
        cert = x509.load_pem_x509_certificate(authorized.read_bytes())
        fingerprints["authorized-ingest-http-client"] = cert.fingerprint(
            hashes.SHA256()
        ).hex()

    (out / "fingerprints.json").write_text(
        json.dumps(fingerprints, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "README.txt").write_text(
        "ADVERSARIAL LOCAL TEST FIXTURES ONLY.\n"
        "Every certificate here must be REJECTED by the ingest gateway.\n"
        "Regenerated by deploy/compose/e2e/generate_adversarial_pki.py.\n",
        encoding="utf-8",
    )
    print(f"Wrote adversarial client PKI under {out}")
    for name, digest in sorted(fingerprints.items()):
        print(f"  {name}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
