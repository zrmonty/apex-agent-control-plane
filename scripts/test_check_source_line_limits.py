from __future__ import annotations

import subprocess
from pathlib import Path

from check_source_line_limits import find_violations, main


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _tracked_fixture_repo(tmp_path: Path) -> Path:
    _git("init", cwd=tmp_path)
    source = tmp_path / "src" / "too_long.py"
    source.parent.mkdir()
    source.write_text("pass\n" * 601, encoding="utf-8")

    git_internal_source = tmp_path / ".git" / "too_long.py"
    git_internal_source.write_text("pass\n" * 601, encoding="utf-8")

    for directory in (
        "target",
        "node_modules",
        "dist",
        "build",
        ".venv",
        "venv",
    ):
        ignored = tmp_path / directory / "too_long.py"
        ignored.parent.mkdir()
        ignored.write_text("pass\n" * 601, encoding="utf-8")

    _git(
        "add",
        "-f",
        "src/too_long.py",
        "target/too_long.py",
        "node_modules/too_long.py",
        "dist/too_long.py",
        "build/too_long.py",
        ".venv/too_long.py",
        "venv/too_long.py",
        cwd=tmp_path,
    )
    return tmp_path


def test_reports_tracked_source_over_limit_and_ignores_excluded_directories(
    tmp_path: Path, capsys
) -> None:
    repo_root = _tracked_fixture_repo(tmp_path)

    assert find_violations(repo_root) == [("src/too_long.py", 601)]
    assert main(["--root", str(repo_root)]) == 1

    output = capsys.readouterr()
    assert "src/too_long.py: 601 lines" in output.out
    assert ".git/too_long.py" not in output.out
    assert "target/too_long.py" not in output.out
    assert "node_modules/too_long.py" not in output.out
    assert "dist/too_long.py" not in output.out
    assert "build/too_long.py" not in output.out
    assert ".venv/too_long.py" not in output.out
    assert "venv/too_long.py" not in output.out


def test_returns_success_when_all_tracked_sources_are_within_limit(tmp_path: Path, capsys) -> None:
    _git("init", cwd=tmp_path)
    source = tmp_path / "ok.rs"
    source.write_text("fn main() {}\n" * 600, encoding="utf-8")
    _git("add", "ok.rs", cwd=tmp_path)

    assert main(["--root", str(tmp_path)]) == 0
    assert "No tracked source files exceed 600 lines." in capsys.readouterr().out
