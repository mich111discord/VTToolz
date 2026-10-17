"""Utility helpers: hashing, cookie loading, etc."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional


def hash_file(path: str | Path, algo: str = "sha256") -> str:
    """Compute file hash (sha256 / sha1 / md5)."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_cookies_from_file(path: str | Path) -> dict[str, str]:
    """
    Load cookies from a simple Netscape or 'name=value' file.

    Supports:
      - name=value; name2=value2
      - one cookie per line: name=value
      - basic Netscape format (tab-separated)
    """
    cookies: dict[str, str] = {}
    text = Path(path).read_text(encoding="utf-8", errors="ignore")

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Netscape: domain flag path secure expiration name value
        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 7:
                name, value = parts[5], parts[6]
                cookies[name] = value
            continue

        # name=value or name=value; ...
        for part in line.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                cookies[name.strip()] = value.strip()

    return cookies


def looks_like_hash(value: str) -> Optional[str]:
    """Return hash type if value looks like md5/sha1/sha256, else None."""
    value = value.lower().strip()
    if len(value) == 32 and all(c in "0123456789abcdef" for c in value):
        return "md5"
    if len(value) == 40 and all(c in "0123456789abcdef" for c in value):
        return "sha1"
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return "sha256"
    return None
