"""Keyring backend for Prego Python packages.

pip, uv and Poetry ask the keyring for the password of an index URL. For a Prego Python host, this backend
runs ``prego token --python --url <url>`` and gives the token with the username ``__token__``. For any other
host it gives nothing, so the next backend answers. It never stores a token: prego caches it (mode 0600, in
the runtime directory) until one minute before it ends.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Optional
from urllib.parse import urlsplit

from keyring.backend import KeyringBackend
from keyring.credentials import SimpleCredential
from keyring.errors import PasswordDeleteError, PasswordSetError

__version__ = "0.1.0"

USERNAME = "__token__"
PREGO_DOMAIN = ".prego.k8skill.com"
# A token exchange can wait for a rate limit (at most 60 s, two times).
TIMEOUT_SECONDS = 150


def _host(service: str) -> str:
    """The host of a URL or of a bare ``host[:port]``, in lowercase, without user info and port 443."""
    text = service.strip()
    if "://" not in text:
        text = "https://" + text
    try:
        netloc = urlsplit(text).netloc
    except ValueError:
        return ""
    host = netloc.rsplit("@", 1)[-1].lower()
    if host.endswith(":443"):
        host = host[: -len(":443")]
    return host


def is_prego_host(service: str) -> bool:
    """True for a host under prego.k8skill.com, or the host in PREGO_PYPI_HOST."""
    host = _host(service)
    if not host:
        return False
    configured = os.environ.get("PREGO_PYPI_HOST", "").strip()
    if configured and host == _host(configured):
        return True
    return host.split(":", 1)[0].endswith(PREGO_DOMAIN)


def _token(service: str) -> Optional[str]:
    if not is_prego_host(service):
        return None
    prego = shutil.which("prego")
    if prego is None:
        return None
    try:
        done = subprocess.run(
            [prego, "token", "--python", "--url", service],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        # prego never prints a token on stderr. Show its message, so the user sees why there is no token.
        message = done.stderr.strip().splitlines()
        if message:
            print(f"keyrings.prego: {message[-1]}", file=sys.stderr)
        return None
    token = done.stdout.strip()
    if not token or any(c.isspace() for c in token):
        return None
    return token


def _wanted(username: Optional[str]) -> bool:
    return username in (None, "", USERNAME)


class PregoKeyring(KeyringBackend):
    """Gives Prego tokens for Prego Python hosts only. Other hosts go to the next backend."""

    priority = 9  # type: ignore[assignment]

    def get_password(self, service: str, username: Optional[str]) -> Optional[str]:
        if not _wanted(username):
            return None
        return _token(service)

    def get_credential(self, service: str, username: Optional[str]) -> Optional[SimpleCredential]:
        if not _wanted(username):
            return None
        token = _token(service)
        if token is None:
            return None
        return SimpleCredential(USERNAME, token)

    def set_password(self, service: str, username: str, password: str) -> None:
        raise PasswordSetError("keyrings.prego does not store passwords: prego gets a new token")

    def delete_password(self, service: str, username: str) -> None:
        raise PasswordDeleteError("keyrings.prego does not store passwords")
