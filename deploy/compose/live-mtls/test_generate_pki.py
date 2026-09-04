"""Regression tests for local-dev PKI output safety."""

from __future__ import annotations

from pathlib import Path

import pytest

from generate_pki import _prepare_write


def test_refuses_a_preexisting_symlink_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    outside.write_text("must-remain", encoding="ascii")
    destination = tmp_path / "generated.pem"
    try:
        destination.symlink_to(outside)
    except (OSError, NotImplementedError):
        # Windows runners may not grant symlink creation to the test process;
        # still exercise the production guard rather than dropping coverage.
        destination_type = type(destination)
        monkeypatch.setattr(
            destination_type,
            "is_symlink",
            lambda candidate: candidate == destination,
        )

    with pytest.raises(RuntimeError, match="symbolic-link destination"):
        _prepare_write(destination)
    assert outside.read_text(encoding="ascii") == "must-remain"
