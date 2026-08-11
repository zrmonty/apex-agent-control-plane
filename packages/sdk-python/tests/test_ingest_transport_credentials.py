"""Tests for ``AgentIngestCredentials`` file loading and
``GrpcEventIngestTransport`` construction.

Split out of a larger ``test_ingest_transport.py`` -- see
``test_ingest_transport.py`` for the Struct encoder,
``test_ingest_transport_envelope.py`` for the envelope encoder,
``test_ingest_transport_integrity.py`` for the pre-send integrity guard, and
``test_ingest_transport_live.py`` for the live in-process mTLS suite.

The ``ingest_pki`` fixture this file's ``credential_files`` fixture builds on
lives in ``conftest.py``, along with the ``_ingest_credentials`` helper:
both ``test_ingest_transport_integrity.py`` and
``test_ingest_transport_live.py`` need them too.
"""

from __future__ import annotations

import os

import pytest

from apex_sdk.errors import ConfigurationError
from apex_sdk.ingest_transport import AgentIngestCredentials, GrpcEventIngestTransport
from conftest import _ingest_credentials

grpc = pytest.importorskip("grpc")
pytest.importorskip("cryptography")


@pytest.fixture
def credential_files(tmp_path, ingest_pki):
    paths = {}
    for name, blob, private in (
        ("ca.pem", ingest_pki["ca_pem"], False),
        ("client.pem", ingest_pki["client_cert_pem"], False),
        ("client.key", ingest_pki["client_key_pem"], True),
        ("ingest-bearer-token", b"gateway-ref-token\n", True),
    ):
        path = tmp_path / name
        path.write_bytes(blob)
        if os.name == "posix":
            path.chmod(0o600 if private else 0o644)
        paths[name] = path
    return paths


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_credentials_load_from_files_and_strip_the_token(credential_files):
    credentials = AgentIngestCredentials.from_files(
        ca_file=credential_files["ca.pem"],
        client_certificate_file=credential_files["client.pem"],
        client_key_file=credential_files["client.key"],
        token_file=credential_files["ingest-bearer-token"],
    )
    assert credentials.token == "gateway-ref-token"
    assert credentials.ca_certificate.startswith(b"-----BEGIN CERTIFICATE-----")
    assert credentials.client_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_supplying_both_or_neither_token_source_is_refused(credential_files):
    common = {
        "ca_file": credential_files["ca.pem"],
        "client_certificate_file": credential_files["client.pem"],
        "client_key_file": credential_files["client.key"],
    }
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(**common)
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            **common, token="a-token", token_file=credential_files["ingest-bearer-token"]
        )


@pytest.mark.parametrize(
    "token",
    ["", "   ", "has space", "téken", "with\x01control", "x" * 4097],
)
def test_a_token_the_gateway_would_refuse_is_refused_here_first(credential_files, token):
    """``auth/verifier.rs`` requires ASCII-graphic bytes and at most 4096 of them.

    Rejecting locally turns a malformed credential into a configuration error at
    startup rather than an opaque UNAUTHENTICATED on first export -- and it is
    strictly stricter than the control transport's check, which admits
    non-printable ASCII.
    """
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token=token,
        )


def test_a_missing_credential_file_is_a_typed_configuration_error(tmp_path, credential_files):
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            ca_file=tmp_path / "nope.pem",
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="gateway-ref-token",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are only meaningful on POSIX")
def test_a_world_readable_private_key_is_refused(credential_files):
    credential_files["client.key"].chmod(0o644)
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="gateway-ref-token",
        )


# ---------------------------------------------------------------------------
# Transport construction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    ["", "   ", "https://localhost:8443", "local host:8443", 8443],
)
def test_a_malformed_endpoint_is_refused(ingest_pki, endpoint):
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport(endpoint, _ingest_credentials(ingest_pki))  # type: ignore[arg-type]


def test_credentials_must_be_the_typed_object(ingest_pki):
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport("localhost:8443", {"token": "x"})  # type: ignore[arg-type]


def test_a_control_credential_object_is_not_accepted_here(ingest_pki):
    """The two services authenticate independently; their credentials are not interchangeable."""
    from apex_sdk.control_transport import AgentControlCredentials

    control = AgentControlCredentials(
        ca_certificate=ingest_pki["ca_pem"],
        client_certificate=ingest_pki["client_cert_pem"],
        client_key=ingest_pki["client_key_pem"],
        token="gateway-ref-token",
    )
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport("localhost:8443", control)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [0, -1, 301, True, "5"])
def test_an_out_of_range_timeout_is_refused(ingest_pki, timeout):
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport("localhost:8443", _ingest_credentials(ingest_pki), timeout_seconds=timeout)  # type: ignore[arg-type]


def test_the_missing_grpc_extra_is_a_typed_configuration_error(monkeypatch, ingest_pki):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "grpc":
            raise ImportError("no grpc")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConfigurationError) as caught:
        GrpcEventIngestTransport("localhost:8443", _ingest_credentials(ingest_pki))
    assert "grpc extra" in str(caught.value)


# ---------------------------------------------------------------------------
# Guards that no ordinary input can reach, exercised directly
# ---------------------------------------------------------------------------


def test_credentials_never_print_the_private_key_or_the_bearer_token(ingest_pki):
    """A dataclass prints every field by default; these two must not be printed.

    ``logging.debug("%r", credentials)``, a pytest ``--showlocals`` traceback,
    or any exception renderer that walks local variables would otherwise put a
    workload private key and a live bearer credential into a log. Asserted for
    both transports' credential objects, because they are the same shape and a
    leak in either is the same incident.
    """
    from apex_sdk.control_transport import AgentControlCredentials

    ingest = _ingest_credentials(ingest_pki)
    control = AgentControlCredentials(
        ca_certificate=ingest_pki["ca_pem"],
        client_certificate=ingest_pki["client_cert_pem"],
        client_key=ingest_pki["client_key_pem"],
        token="agent-a-token-abcdefgh",
    )
    for credentials, token in ((ingest, "gateway-ref-token"), (control, "agent-a-token-abcdefgh")):
        rendered = repr(credentials)
        assert token not in rendered
        assert "PRIVATE KEY" not in rendered
        # The certificate material is not secret and stays visible, so the
        # object is still identifiable in a diagnostic.
        assert "BEGIN CERTIFICATE" in rendered
    # The values themselves are still reachable by the code that needs them.
    assert ingest.token == "gateway-ref-token"
    assert ingest.client_key == ingest_pki["client_key_pem"]
