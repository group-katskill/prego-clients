"""Tests for keyrings.prego with a fake prego on PATH."""

from __future__ import annotations

import os
import stat
import sys
from importlib.metadata import entry_points
from pathlib import Path

import pytest
from keyring.errors import PasswordDeleteError, PasswordSetError

from keyrings import prego
from keyrings.prego import PregoKeyring

INDEX = "https://pypi.prego.k8skill.com/t/acme/default/simple/"


@pytest.fixture
def fake_prego(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A prego script that writes its arguments to a file and prints a token (or fails)."""
    log = tmp_path / "args.txt"
    script = tmp_path / "bin" / "prego"
    script.parent.mkdir()
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" >> "{log}"\n'
        'if [ -n "$FAKE_PREGO_FAIL" ]; then echo "prego: no identity found" >&2; exit 1; fi\n'
        'printf "%s\\n" "${FAKE_PREGO_TOKEN:-tok.en-1}"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(script.parent))
    monkeypatch.delenv("PREGO_PYPI_HOST", raising=False)
    return log


def calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def test_prego_host_gives_the_token(fake_prego: Path) -> None:
    k = PregoKeyring()
    assert k.get_password(INDEX, "__token__") == "tok.en-1"
    assert calls(fake_prego) == ["token", "--python", "--url", INDEX]
    cred = k.get_credential(INDEX, None)
    assert cred is not None
    assert (cred.username, cred.password) == ("__token__", "tok.en-1")


def test_bare_host_and_user_info(fake_prego: Path) -> None:
    k = PregoKeyring()
    assert k.get_password("pypi.prego.k8skill.com", None) == "tok.en-1"
    assert k.get_password("https://__token__@PYPI.prego.k8skill.com:443/t/a/b/simple/", "") == "tok.en-1"


def test_other_hosts_get_nothing_and_run_nothing(fake_prego: Path) -> None:
    k = PregoKeyring()
    for service in [
        "https://pypi.org/simple/",
        "https://pypi.prego.k8skill.com.evil.test/t/a/b/simple/",
        "https://evil.test/pypi.prego.k8skill.com/",
        "files.pythonhosted.org",
        "",
    ]:
        assert k.get_password(service, None) is None, service
        assert k.get_credential(service, None) is None, service
    assert calls(fake_prego) == []


def test_other_usernames_get_nothing(fake_prego: Path) -> None:
    assert PregoKeyring().get_password(INDEX, "alice") is None
    assert PregoKeyring().get_credential(INDEX, "alice") is None
    assert calls(fake_prego) == []


def test_configured_host(fake_prego: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PREGO_PYPI_HOST", "127.0.0.1:8080")
    assert PregoKeyring().get_password("http://127.0.0.1:8080/t/a/b/simple/", None) == "tok.en-1"
    assert PregoKeyring().get_password("http://127.0.0.1:9090/t/a/b/simple/", None) is None


def test_failure_shows_the_message(
    fake_prego: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("FAKE_PREGO_FAIL", "1")
    assert PregoKeyring().get_password(INDEX, None) is None
    assert "keyrings.prego: prego: no identity found" in capsys.readouterr().err


def test_bad_output_is_refused(fake_prego: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FAKE_PREGO_TOKEN", "two words")
    assert PregoKeyring().get_password(INDEX, None) is None


def test_no_prego_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    assert PregoKeyring().get_password(INDEX, None) is None


def test_never_stores() -> None:
    with pytest.raises(PasswordSetError):
        PregoKeyring().set_password(INDEX, "__token__", "x")
    with pytest.raises(PasswordDeleteError):
        PregoKeyring().delete_password(INDEX, "__token__")


def test_priority_and_entry_point() -> None:
    assert PregoKeyring.priority > 0
    names = {ep.name: ep.value for ep in entry_points(group="keyring.backends")}
    assert names.get("prego") == "keyrings.prego"
    assert prego.__version__ == "0.1.0"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell script")
def test_keyring_cli_uses_the_backend(fake_prego: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The keyring CLI, as pip and uv run it with --keyring-provider subprocess."""
    import subprocess

    env = dict(os.environ, PYTHON_KEYRING_BACKEND="keyrings.prego.PregoKeyring")
    out = subprocess.run(
        [sys.executable, "-m", "keyring", "get", INDEX, "__token__"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "tok.en-1"
