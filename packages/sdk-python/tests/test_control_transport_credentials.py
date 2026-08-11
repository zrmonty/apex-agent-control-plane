"""Tests for ``AgentControlCredentials`` file loading.

Split out of a larger ``test_control_transport.py`` -- see
``test_control_transport.py`` for the wire codec and
``test_control_transport_live.py`` for transport construction,
error classification, and the live in-process mTLS suite.

The ``control_pki`` fixture this file's ``credential_files`` fixture builds
on lives in ``conftest.py``, not here: ``test_control_transport_live.py``
needs the same CA, so it is one of this split's genuinely shared fixtures.
"""

from __future__ import annotations

import os
import stat

import pytest

from apex_sdk.control_transport import MAX_CREDENTIAL_BYTES, AgentControlCredentials
from apex_sdk.errors import ConfigurationError

pytest.importorskip("grpc")
pytest.importorskip("cryptography")


@pytest.fixture
def credential_files(tmp_path, control_pki):
    paths = {}
    for name, blob, private in (
        ("ca.pem", control_pki["ca_pem"], False),
        ("client.pem", control_pki["client_cert_pem"], False),
        ("client.key", control_pki["client_key_pem"], True),
        ("token", b"agent-a-token-abcdefgh\n", True),
    ):
        path = tmp_path / name
        path.write_bytes(blob)
        if os.name == "posix":
            path.chmod(0o600 if private else 0o644)
        paths[name] = path
    return paths


def test_credentials_load_from_files_and_strip_the_token(credential_files):
    credentials = AgentControlCredentials.from_files(
        ca_file=credential_files["ca.pem"],
        client_certificate_file=credential_files["client.pem"],
        client_key_file=credential_files["client.key"],
        token_file=credential_files["token"],
    )
    assert credentials.token == "agent-a-token-abcdefgh"
    assert credentials.ca_certificate.startswith(b"-----BEGIN CERTIFICATE-----")
    assert credentials.client_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_supplying_both_or_neither_token_source_is_refused(credential_files):
    common = {
        "ca_file": credential_files["ca.pem"],
        "client_certificate_file": credential_files["client.pem"],
        "client_key_file": credential_files["client.key"],
    }
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(**common)
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            **common, token="literal-token-abcdefgh", token_file=credential_files["token"]
        )


@pytest.mark.parametrize("token", ["", "   ", "has space", "téken"])
def test_a_token_that_could_never_be_sent_in_a_bearer_header_is_refused(credential_files, token):
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token=token,
        )


def test_a_missing_credential_file_is_a_typed_configuration_error(tmp_path, credential_files):
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=tmp_path / "nope.pem",
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


def test_a_directory_is_not_a_credential_file(tmp_path, credential_files):
    directory = tmp_path / "a-directory"
    directory.mkdir()
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=directory,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


def test_an_empty_or_oversized_credential_file_is_refused(tmp_path, credential_files):
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=empty,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )
    huge = tmp_path / "huge.pem"
    huge.write_bytes(b"x" * (MAX_CREDENTIAL_BYTES + 1))
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=huge,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


def test_a_symlinked_credential_path_is_refused(tmp_path, credential_files):
    link = tmp_path / "linked-ca.pem"
    try:
        link.symlink_to(credential_files["ca.pem"])
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not permit creating symlinks unprivileged")
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=link,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are only meaningful on POSIX")
def test_a_world_readable_private_key_is_refused(credential_files):
    credential_files["client.key"].chmod(0o644)
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )
    assert stat.S_IMODE(credential_files["client.key"].stat().st_mode) == 0o644
