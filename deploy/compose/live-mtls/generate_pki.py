#!/usr/bin/env python3
"""Generate a local-dev-only PKI for live mTLS handshake tests.

NEVER use these materials in production. They exist solely so developers and CI
can exercise Valkey, NATS, and provider mTLS without external CAs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import secrets as secure_secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _prepare_write(path: Path) -> None:
    if path.exists():
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    _prepare_write(path)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    # Lab-only: 0644 so Docker Compose file-secrets are readable by nats/python
    # containers. Compose on Linux ignores secret mode/uid/gid. Do not reuse
    # these keys in production (production mounts use 0400 operator secrets).
    try:
        path.chmod(0o644)
    except OSError:
        pass


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    _prepare_write(path)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        path.chmod(0o644)
    except OSError:
        pass


def _write_runtime_secret(path: Path) -> None:
    """Write a fresh high-entropy local-fixture credential with private mode."""
    _prepare_write(path)
    path.write_text(secure_secrets.token_urlsafe(32) + "\n", encoding="ascii")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_operator_token_table(path: Path) -> None:
    """Write a lab operator credential table for `apps/control-plane-api`.

    The file is the whole `APEX_CONTROL_OPERATOR_TOKENS_FILE` value, not a
    bare token: the format is `token|workspace/namespace[,...];...`, and the
    gateway refuses any token shorter than 16 bytes. Scoped to `acme/prod`
    rather than the `*` break-glass scope so the lab fixture exercises the
    scope check instead of bypassing it.

    Clients that need the raw token (tests, `grpcurl`) split on the last `|`.
    """
    _prepare_write(path)
    path.write_text(
        f"{secure_secrets.token_urlsafe(32)}|acme/prod\n", encoding="ascii"
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_agent_token_table(path: Path, certificate_path: Path, agent_id: str) -> None:
    """Write a lab agent-workload credential table for `PollCommands`.

    Format: `token|cert_sha256|agent_id|workspace/namespace[,...]`. Distinct
    from the operator table on purpose -- per ADR-0006 the authority to
    *issue* a `stop` and the authority to *retrieve* one belong to different
    principals, so they get different credential spaces and different files.

    The fingerprint is computed from the certificate this script just issued,
    so the table and the leaf cannot drift. That binding is what makes the
    bearer credential useless on its own: the gateway refuses a valid token
    presented from a connection holding any other client certificate.

    There is deliberately no `*` scope form here, unlike the operator table:
    an agent workload has exactly one identity.
    """
    fingerprint = (
        x509.load_pem_x509_certificate(certificate_path.read_bytes())
        .fingerprint(hashes.SHA256())
        .hex()
    )
    _prepare_write(path)
    path.write_text(
        f"{secure_secrets.token_urlsafe(32)}|{fingerprint}|{agent_id}|acme/prod\n",
        encoding="ascii",
    )
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _is_private_secret_name(name: str) -> bool:
    """Names the host-side Rust secret policy treats as private material."""
    lower = name.lower()
    return (
        lower.endswith(".key")
        or lower.endswith("-password")
        or lower.endswith("_password")
        or lower in {
            "nats-username",
            "nats-password",
            "control-nats-username",
            "control-nats-password",
            "valkey-ingest-password",
            "valkey-control-password",
            "ingest-bearer-token",
        }
        or "password" in lower
        or "token" in lower
    )


def write_host_secrets(docker_out: Path, host_out: Path | None = None) -> Path:
    """Mirror docker-readable fixtures into a host-restricted tree.

    Docker Compose lab mounts use 0644 private keys so non-root service images
    can read file secrets (Compose on Linux ignores secret mode/uid/gid).
    Host-side event-ingest clients reject private material when mode & 0o077 != 0.
    Tests must load secrets from the host tree, not the docker mount tree.
    """
    if host_out is None:
        host_out = docker_out.parent / f"{docker_out.name}-host"
    host_out.mkdir(parents=True, exist_ok=True)
    for src in sorted(docker_out.iterdir()):
        if not src.is_file():
            continue
        # Skip rendered service configs; host clients only need TLS + credential files.
        if src.name in {
            "nats.conf",
            "valkey.conf",
            "valkey.acl",
            "control-valkey.acl",
            "README.txt",
        }:
            continue
        dest = host_out / src.name
        _prepare_write(dest)
        dest.write_bytes(src.read_bytes())
        mode = 0o600 if _is_private_secret_name(src.name) else 0o644
        try:
            dest.chmod(mode)
        except OSError:
            pass
    (host_out / "README.txt").write_text(
        "HOST-SIDE live-mTLS fixtures for Rust/Python clients.\n"
        "Private keys and credential files are mode 0600.\n"
        "Docker services must keep using the sibling secrets/ tree (0644 keys).\n"
        "Regenerated by generate_pki.py (write_host_secrets).\n",
        encoding="utf-8",
    )
    return host_out


def _ca(out: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = _key()
    subject = _name("Apex Live mTLS Test CA")
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
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
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
    _write_key(out / "ca.key", key)
    _write_cert(out / "ca.pem", cert)
    return key, cert


def _issue(
    *,
    out: Path,
    basename: str,
    common_name: str,
    san_dns: list[str],
    san_ips: list[str],
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    server: bool,
) -> None:
    key = _key()
    now = dt.datetime.now(dt.UTC)
    san: list[x509.GeneralName] = [x509.DNSName(name) for name in san_dns]
    san.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips)
    eku = (
        [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        if server
        else [ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    leaf_ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(leaf_ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
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
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(out / f"{basename}.key", key)
    _write_cert(out / f"{basename}.pem", cert)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "secrets",
        help="Output directory for certificates and keys",
    )
    args = parser.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "README.txt").write_text(
        "LOCAL DEVELOPMENT / LIVE mTLS FIXTURES ONLY.\n"
        "Do not use in production. Regenerated by generate_pki.py.\n",
        encoding="utf-8",
    )
    ca_key, ca_cert = _ca(out)
    # Valkey server + ingest client
    _issue(
        out=out,
        basename="valkey-server",
        common_name="valkey",
        san_dns=["valkey", "localhost"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=True,
    )
    _issue(
        out=out,
        basename="ingest-valkey-client",
        common_name="apex-ingest-valkey",
        san_dns=["apex-ingest"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # NATS server + ingest client
    _issue(
        out=out,
        basename="nats-server",
        common_name="jetstream",
        san_dns=["jetstream", "nats", "localhost"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=True,
    )
    _issue(
        out=out,
        basename="ingest-nats-client",
        common_name="apex-ingest-nats",
        san_dns=["apex-ingest"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # Provider API servers + gateway clients
    for name in ("clickhouse-projection", "archive-provider"):
        _issue(
            out=out,
            basename=f"{name}-server",
            common_name=name,
            san_dns=[name, "localhost"],
            # Include IPv6 loopback: Ubuntu CI often resolves "localhost" to ::1.
            san_ips=["127.0.0.1", "::1"],
            ca_key=ca_key,
            ca_cert=ca_cert,
            server=True,
        )
    _issue(
        out=out,
        basename="ingest-http-client",
        common_name="apex-ingest-http",
        san_dns=["apex-ingest"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # OOB control gateway (apps/control-plane-api). Its own server leaf and its
    # own operator client leaf: per ADR-0006 the control channel is a separate
    # trust boundary from ingest, so it does not reuse the ingest gateway's
    # server certificate or the ingest workload's client certificate.
    _issue(
        out=out,
        basename="control-plane-server",
        common_name="control-plane-api",
        san_dns=["control-plane-api", "localhost"],
        # Include IPv6 loopback: Ubuntu CI often resolves "localhost" to ::1.
        san_ips=["127.0.0.1", "::1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=True,
    )
    _issue(
        out=out,
        basename="control-operator-client",
        common_name="apex-control-operator",
        san_dns=["apex-control-operator"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # The agent workload's client identity for `PollCommands`. Its own leaf,
    # neither the operator's nor the ingest workload's: an operator issues
    # commands, an agent retrieves the ones issued against it, and those are
    # different authorities held by different principals (ADR-0006). The
    # gateway pins this exact certificate to the agent's bearer credential, so
    # a leaked token cannot be used from any other connection.
    _issue(
        out=out,
        basename="agent-workload-client",
        common_name="apex-agent-workload",
        san_dns=["apex-agent-workload"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # A *second* agent leaf and credential, for the cross-agent isolation
    # assertion in the live poll test. Without a real second workload, "agent B
    # cannot read agent A's commands" can only be tested in process.
    _issue(
        out=out,
        basename="agent-workload-b-client",
        common_name="apex-agent-workload-b",
        san_dns=["apex-agent-workload-b"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # One leaf and one credential per *live proof*, not one shared between
    # them. The gateway's inbox is at-least-once with a redelivery window, so a
    # command left over from an earlier test against the same agent identity
    # becomes visible again minutes later -- and a `stop` redelivered into the
    # middle of a pause proof would halt the agent and look like a pause
    # failure. Separate identities make the proofs independent by construction
    # rather than by test ordering, and they also keep the "one workload, one
    # identity" rule the credential table has no wildcard form for.
    for basename, common in (
        ("agent-workload-pause-client", "apex-agent-workload-pause"),
        ("agent-workload-budget-client", "apex-agent-workload-budget"),
        ("agent-workload-inject-client", "apex-agent-workload-inject"),
    ):
        _issue(
            out=out,
            basename=basename,
            common_name=common,
            san_dns=[common],
            san_ips=["127.0.0.1"],
            ca_key=ca_key,
            ca_cert=ca_cert,
            server=False,
        )
    # The control gateway's own NATS client identity for fanout, distinct from
    # `ingest-nats-client`. It publishes into the same `apex.events.>` stream
    # -- a control event belongs in the same trace as everything else -- but
    # it does so as its own broker principal, so the two services' broker
    # authorizations can differ and a compromise of one does not hand over the
    # other's publish rights. `render_configs.py` grants this user strictly
    # less than the ingest publisher: no `$JS.API.>`, since the control
    # gateway never manages streams.
    _issue(
        out=out,
        basename="control-nats-client",
        common_name="apex-control-nats",
        san_dns=["apex-control-nats"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # Keycloak server leaf for the live operator-credential tests
    # (deploy/compose/compose.control-keycloak.yaml). The control gateway
    # trusts *only* this CA for the JWKS endpoint -- `tls_certs_only` replaces
    # the trust store rather than adding to it -- so the SAN must cover both
    # the Compose service name (how the gateway reaches it) and localhost (how
    # the host-side test mints tokens from it).
    _issue(
        out=out,
        basename="keycloak-server",
        common_name="keycloak",
        san_dns=["keycloak", "localhost"],
        san_ips=["127.0.0.1", "::1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=True,
    )
    # The control gateway's own Valkey instance and its own client identity,
    # distinct from `valkey-server` / `ingest-valkey-client` above. Not
    # decoration: `event-ingest`'s ephemeral key prefix is the fixed literal
    # `apex:ingest`, so a shared instance would put both services' rate-limit
    # counters in one keyspace under one ACL user, and either service's
    # credential could then clear or inflate the other's admission state.
    _issue(
        out=out,
        basename="control-valkey-server",
        common_name="control-valkey",
        san_dns=["control-valkey", "localhost"],
        san_ips=["127.0.0.1", "::1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=True,
    )
    _issue(
        out=out,
        basename="control-valkey-client",
        common_name="apex-control-valkey",
        san_dns=["apex-control-valkey"],
        san_ips=["127.0.0.1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=False,
    )
    # Postgres server leaf for the control gateway's own outbox database
    # (deploy/compose/compose.control-pg.yaml). Not optional decoration: the
    # shared `postgres_transport` refuses `sslmode=disable` for anything but a
    # literal loopback IP, so a containerised Postgres reached by service name
    # can only be spoken to over verified TLS. The SAN must be the Compose
    # service name, which is what rustls verifies against.
    _issue(
        out=out,
        basename="control-postgres-server",
        common_name="control-postgres",
        san_dns=["control-postgres", "localhost"],
        san_ips=["127.0.0.1", "::1"],
        ca_key=ca_key,
        ca_cert=ca_cert,
        server=True,
    )
    # Shared secrets used by configs
    # Username is treated as private material by NATS host-side validation.
    _prepare_write(out / "nats-username")
    (out / "nats-username").write_text("ingest-publisher\n", encoding="utf-8")
    try:
        # Docker-readable; host tree gets 0600 via write_host_secrets.
        (out / "nats-username").chmod(0o644)
    except OSError:
        pass
    _write_runtime_secret(out / "nats-password")
    # The control gateway's own NATS account, never the ingest publisher's.
    _prepare_write(out / "control-nats-username")
    (out / "control-nats-username").write_text("control-publisher\n", encoding="utf-8")
    try:
        # Docker-readable; host tree gets 0600 via write_host_secrets.
        (out / "control-nats-username").chmod(0o644)
    except OSError:
        pass
    _write_runtime_secret(out / "control-nats-password")
    _write_runtime_secret(out / "valkey-ingest-password")
    # The control gateway's own Valkey ACL credential, never the ingest
    # workload's -- same rule as the separate NATS account above.
    _write_runtime_secret(out / "valkey-control-password")
    _write_operator_token_table(out / "control-operator-tokens")
    # One entry per agent workload in one table: the agent the stop proof
    # drives, a second workload used only to show it cannot read the first
    # one's commands, and one workload per additional live proof (see the
    # comment on their leaves above for why they are not shared).
    _prepare_write(out / "control-agent-tokens")
    agents = (
        ("control-agent-tokens-a", "agent-workload-client.pem", "reference-agent"),
        ("control-agent-tokens-b", "agent-workload-b-client.pem", "reference-agent-b"),
        (
            "control-agent-tokens-pause",
            "agent-workload-pause-client.pem",
            "reference-agent-pause",
        ),
        (
            "control-agent-tokens-budget",
            "agent-workload-budget-client.pem",
            "reference-agent-budget",
        ),
        (
            "control-agent-tokens-inject",
            "agent-workload-inject-client.pem",
            "reference-agent-inject",
        ),
    )
    for table, certificate, agent_id in agents:
        _write_agent_token_table(out / table, out / certificate, agent_id)
    (out / "control-agent-tokens").write_text(
        ";\n".join(
            (out / table).read_text(encoding="ascii").strip() for table, _, _ in agents
        )
        + "\n",
        encoding="ascii",
    )
    try:
        (out / "control-agent-tokens").chmod(0o600)
    except OSError:
        pass
    host_out = write_host_secrets(out)
    print(f"Wrote local-dev PKI under {out}")
    print(f"Wrote host-restricted client secrets under {host_out}")


if __name__ == "__main__":
    main()
