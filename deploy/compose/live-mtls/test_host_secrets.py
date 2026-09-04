"""Regression tests for the host-restricted live-mTLS secret mirror."""

from __future__ import annotations

from pathlib import Path

import pytest

from host_secrets import write_host_secrets


def test_refuses_a_preexisting_symlink_in_the_host_output(tmp_path: Path) -> None:
    docker_out = tmp_path / "secrets"
    host_out = tmp_path / "secrets-host"
    outside = tmp_path / "outside"
    docker_out.mkdir()
    host_out.mkdir()
    outside.mkdir()
    (docker_out / "token").write_text("new-token", encoding="ascii")
    redirected = outside / "token"
    redirected.write_text("must-remain", encoding="ascii")
    try:
        (host_out / "token").symlink_to(redirected)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(RuntimeError, match="symbolic link"):
        write_host_secrets(docker_out, host_out)
    assert redirected.read_text(encoding="ascii") == "must-remain"


def test_refuses_a_symlinked_docker_source_root(tmp_path: Path) -> None:
    real_source = tmp_path / "real-secrets"
    source_alias = tmp_path / "secrets"
    real_source.mkdir()
    (real_source / "token").write_text("token", encoding="ascii")
    try:
        source_alias.symlink_to(real_source, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(RuntimeError, match="symbolic link"):
        write_host_secrets(source_alias, tmp_path / "secrets-host")
