"""Utility helpers: hashing, cookie loading, etc."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional


def hash_file(path: str | Path, algo: str = "sha256") -> str:
    """Compute file hash (sha256 / sha1 / md5)."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _cookies_from_json_list(items: list) -> dict[str, str]:
    """Parse list of cookie objects (EditThisCookie / Cookie-Editor / Chrome export)."""
    cookies: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("Name")
        value = item.get("value") or item.get("Value")
        if name is None or value is None:
            continue
        # Prefer virustotal.com cookies when domain is present
        domain = str(item.get("domain") or item.get("Domain") or "")
        if domain and "virustotal" not in domain.lower() and "vtapi" not in domain.lower():
            # still accept – user may have filtered already
            pass
        cookies[str(name)] = str(value)
    return cookies


def load_cookies_from_file(path: str | Path) -> dict[str, str]:
    """
    Load cookies from file. Supported formats:

      1. JSON array (EditThisCookie / Cookie-Editor / browser export):
         [{"name":"VT_SESSION","value":"...","domain":".virustotal.com"}, ...]

      2. JSON object:
         {"VT_SESSION": "...", "_ga": "..."}

      3. Netscape cookie file (tab-separated)

      4. Plain name=value (one per line or semicolon-separated)
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return {}

    # --- JSON ---
    if text[0] in ("{", "["):
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError:
            data = None

        if isinstance(data, list):
            return _cookies_from_json_list(data)

        if isinstance(data, dict):
            # object map name -> value
            if all(isinstance(v, (str, int, float, bool)) or v is None for v in data.values()):
                return {str(k): "" if v is None else str(v) for k, v in data.items()}
            # sometimes {"cookies": [ {...}, ... ]}
            if "cookies" in data and isinstance(data["cookies"], list):
                return _cookies_from_json_list(data["cookies"])
            # Puppeteer / Playwright style
            if "name" in data and "value" in data:
                return _cookies_from_json_list([data])

    # --- Netscape / name=value ---
    cookies: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "\t" in line:
            parts = line.split("\t")
            if len(parts) >= 7:
                cookies[parts[5]] = parts[6]
            continue

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
