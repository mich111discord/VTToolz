"""reCAPTCHA helpers: manual token, 2captcha, anti-captcha, external solver."""

from __future__ import annotations

import os
import subprocess
import time
from typing import Optional

import requests

# VirusTotal invisible reCAPTCHA Enterprise sitekey
VT_SITEKEY = "6LdawOwtAAAAAEJuyEXijrVsxVKwqhUS8E1rUkT3"
VT_PAGE_URL = "https://www.virustotal.com/gui/home/upload"


def solve_2captcha(
    api_key: str,
    sitekey: str = VT_SITEKEY,
    page_url: str = VT_PAGE_URL,
    timeout: int = 120,
    poll: float = 5.0,
) -> str:
    """Solve via 2captcha.com → g-recaptcha-response token."""
    create = requests.post(
        "https://2captcha.com/in.php",
        data={
            "key": api_key,
            "method": "userrecaptcha",
            "googlekey": sitekey,
            "pageurl": page_url,
            "invisible": 1,
            "json": 1,
        },
        timeout=30,
    )
    create.raise_for_status()
    body = create.json()
    if body.get("status") != 1:
        raise RuntimeError(f"2captcha create failed: {body}")

    task_id = body["request"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        res = requests.get(
            "https://2captcha.com/res.php",
            params={"key": api_key, "action": "get", "id": task_id, "json": 1},
            timeout=30,
        )
        res.raise_for_status()
        data = res.json()
        if data.get("status") == 1:
            return str(data["request"])
        if data.get("request") != "CAPCHA_NOT_READY":
            raise RuntimeError(f"2captcha error: {data}")
    raise TimeoutError("2captcha: timeout")


def solve_anticaptcha(
    api_key: str,
    sitekey: str = VT_SITEKEY,
    page_url: str = VT_PAGE_URL,
    timeout: int = 120,
    poll: float = 5.0,
) -> str:
    """Solve via anti-captcha.com → g-recaptcha-response token."""
    create = requests.post(
        "https://api.anti-captcha.com/createTask",
        json={
            "clientKey": api_key,
            "task": {
                "type": "RecaptchaV2TaskProxyless",
                "websiteURL": page_url,
                "websiteKey": sitekey,
                "isInvisible": True,
            },
        },
        timeout=30,
    )
    create.raise_for_status()
    body = create.json()
    if body.get("errorId", 1) != 0:
        raise RuntimeError(f"anti-captcha create failed: {body}")

    task_id = body["taskId"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        res = requests.post(
            "https://api.anti-captcha.com/getTaskResult",
            json={"clientKey": api_key, "taskId": task_id},
            timeout=30,
        )
        res.raise_for_status()
        data = res.json()
        if data.get("errorId", 1) != 0:
            raise RuntimeError(f"anti-captcha error: {data}")
        if data.get("status") == "ready":
            solution = data.get("solution") or {}
            token = solution.get("gRecaptchaResponse")
            if not token:
                raise RuntimeError(f"anti-captcha empty solution: {data}")
            return str(token)
    raise TimeoutError("anti-captcha: timeout")


def solve_external(
    command: str,
    sitekey: str = VT_SITEKEY,
    page_url: str = VT_PAGE_URL,
    timeout: int = 180,
) -> str:
    """
    Run an external captcha solver command.

    Placeholders in command string:
      {sitekey}  – reCAPTCHA sitekey
      {pageurl}  – page URL
      {url}      – same as pageurl

    The command must print the token on stdout (last non-empty line is used).

    Examples:
      --captcha-solver "python my_solver.py {sitekey} {pageurl}"
      --captcha-solver "capsolver -k KEY -s {sitekey} -u {pageurl}"
    """
    cmd = (
        command.replace("{sitekey}", sitekey)
        .replace("{pageurl}", page_url)
        .replace("{url}", page_url)
    )
    env = os.environ.copy()
    env["VT_SITEKEY"] = sitekey
    env["VT_PAGEURL"] = page_url

    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"external solver failed (code {proc.returncode}): {err[:400]}")

    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if not lines:
        raise RuntimeError("external solver returned empty stdout")
    return lines[-1]


def load_token_from_file(path: str) -> Optional[str]:
    """Read captcha token from a text file (first non-empty line)."""
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError:
        return None
    return None
