"""HTTP client for VirusTotal UI endpoints (no official API key)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional

import requests

from .anti_abuse import compute_anti_abuse_header

BASE_UI = "https://www.virustotal.com/ui"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/129.0.0.0 Safari/537.36"
)
DEFAULT_APP_VERSION = "v1x304x0"

# Invisible reCAPTCHA Enterprise sitekey used by VirusTotal upload
RECAPTCHA_SITEKEY = "6LdawOwtAAAAAEJuyEXijrVsxVKwqhUS8E1rUkT3"


class VTClient:
    """Session-aware client talking to VirusTotal /ui/ endpoints."""

    def __init__(
        self,
        cookies: Optional[dict[str, str] | str] = None,
        proxy: Optional[str] = None,
        user_agent: str = DEFAULT_USER_AGENT,
        app_version: str = DEFAULT_APP_VERSION,
        timeout: int = 30,
        delay: float = 0.0,
        captcha_token: Optional[str] = None,
    ) -> None:
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.app_version = app_version
        self.captcha_token = captcha_token

        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        if cookies:
            self._load_cookies(cookies)

        self._update_headers()

    def _load_cookies(self, cookies: dict[str, str] | str) -> None:
        """Load cookies from dict or Netscape/HTTP cookie string."""
        if isinstance(cookies, dict):
            self.session.cookies.update(cookies)
            return

        for part in cookies.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                self.session.cookies.set(name.strip(), value.strip())

    def _update_headers(self) -> None:
        headers = {
            "User-Agent": self.user_agent,
            "X-Tool": "vt-ui-main",
            "X-VT-Anti-Abuse-Header": compute_anti_abuse_header(),
            "x-app-version": self.app_version,
            "accept-ianguage": "en-US,en;q=0.9,es;q=0.8",
            "Accept": "application/json",
            "Referer": "https://www.virustotal.com/",
            "Origin": "https://www.virustotal.com",
        }
        self.session.headers.update(headers)

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Low-level request with fresh anti-abuse header every call."""
        self.session.headers["X-VT-Anti-Abuse-Header"] = compute_anti_abuse_header()
        url = path if path.startswith("http") else f"{BASE_UI}{path}"
        if self.delay > 0:
            time.sleep(self.delay)
        return self.session.request(method, url, timeout=self.timeout, **kwargs)

    # ------------------------------------------------------------------
    # Report / search
    # ------------------------------------------------------------------

    def get_file_report(self, file_id: str) -> dict[str, Any]:
        """Fetch file report by SHA-256 / SHA-1 / MD5."""
        resp = self._request("GET", f"/files/{file_id}")
        resp.raise_for_status()
        return resp.json()

    def search(self, query: str, limit: int = 20) -> dict[str, Any]:
        """Search VirusTotal."""
        params = {"query": query, "limit": limit}
        resp = self._request("GET", "/search", params=params)
        resp.raise_for_status()
        return resp.json()

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Fetch analysis status / results by analysis ID."""
        resp = self._request("GET", f"/analyses/{analysis_id}")
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Upload (cookies + optional reCAPTCHA token)
    # ------------------------------------------------------------------

    def get_upload_url(self, captcha_token: Optional[str] = None) -> str:
        """
        Request a one-time upload URL from /ui/files/upload_url.

        VirusTotal returns RecaptchaRequiredError when the request looks automated.
        Providing a valid g-recaptcha-response token (or good cookies from a
        logged-in browser) often bypasses this.
        """
        token = captcha_token or self.captcha_token
        params = {}
        if token:
            params["g-recaptcha-response"] = token

        # Some VT versions expect the token in a header or JSON body
        headers_extra = {}
        if token:
            headers_extra["X-Recaptcha-Response"] = token

        resp = self._request(
            "GET",
            "/files/upload_url",
            params=params,
            headers=headers_extra or None,
        )

        if resp.status_code == 429 or (
            resp.status_code == 400
            and "Recaptcha" in resp.text
        ):
            raise RecaptchaRequiredError(
                "reCAPTCHA required. Supply --captcha-token or use --cookies "
                "from a logged-in browser session."
            )

        resp.raise_for_status()
        data = resp.json()
        # Response can be {"data": "https://..."} or nested
        if isinstance(data, dict):
            upload_url = data.get("data") or data.get("upload_url")
            if isinstance(upload_url, dict):
                upload_url = upload_url.get("url") or upload_url.get("data")
            if upload_url:
                return str(upload_url)
        raise RuntimeError(f"Unexpected upload_url response: {data}")

    def upload_file(
        self,
        file_path: str | Path,
        captcha_token: Optional[str] = None,
        password: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Upload a local file and return the analysis object.

        Flow:
          1. GET /ui/files/upload_url  (may require captcha token / cookies)
          2. POST multipart file to the returned URL
          3. Return the analysis ID / file object
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(path)

        upload_url = self.get_upload_url(captcha_token=captcha_token)

        files = {"file": (path.name, open(path, "rb"), "application/octet-stream")}
        data = {}
        if password:
            data["password"] = password

        # Fresh anti-abuse for the upload POST
        self.session.headers["X-VT-Anti-Abuse-Header"] = compute_anti_abuse_header()

        # Upload URLs are often on a different host (Google App Engine)
        # so we do not force the /ui base
        resp = self.session.post(
            upload_url,
            files=files,
            data=data or None,
            timeout=max(self.timeout, 120),
        )
        files["file"][1].close()

        if resp.status_code >= 400:
            raise RuntimeError(
                f"Upload failed ({resp.status_code}): {resp.text[:300]}"
            )

        return resp.json()

    def wait_for_analysis(
        self,
        analysis_id: str,
        max_wait: int = 180,
        poll_interval: float = 5.0,
    ) -> dict[str, Any]:
        """Poll /ui/analyses/{id} until status is completed or timeout."""
        deadline = time.time() + max_wait
        while time.time() < deadline:
            raw = self.get_analysis(analysis_id)
            status = (
                raw.get("data", {})
                .get("attributes", {})
                .get("status", "unknown")
            )
            if status == "completed":
                return raw
            time.sleep(poll_interval)
        raise TimeoutError(f"Analysis {analysis_id} not completed within {max_wait}s")


class RecaptchaRequiredError(Exception):
    """Raised when VirusTotal demands a reCAPTCHA token."""
