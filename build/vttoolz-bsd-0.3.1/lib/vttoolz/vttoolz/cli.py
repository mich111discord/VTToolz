"""Command-line interface for VTToolz."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .client import RecaptchaRequiredError, VTClient
from .report import extract_detections, print_report
from .utils import hash_file, load_cookies_from_file, looks_like_hash


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vttoolz",
        description="VTToolz – VirusTotal CLI without official API (UI scraper)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vttoolz 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  vttoolz ./malware.exe
  vttoolz ./sample.bin --json
  vttoolz 44d88612fea8a8f36de82e1278abb02f --verbose
  vttoolz ./file.exe --cookies cookies.txt --proxy http://127.0.0.1:8080
  vttoolz ./unknown.bin --upload --cookies cookies.txt
  vttoolz ./unknown.bin --upload --captcha-token "03AFcWeA..."
        """,
    )

    parser.add_argument(
        "target",
        help="File path OR hash (MD5 / SHA-1 / SHA-256)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show extra metadata (dates, tags, permalink)",
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        dest="as_json",
        help="Output raw parsed JSON instead of pretty text",
    )
    parser.add_argument(
        "--cookies",
        metavar="FILE",
        help="Path to cookies file (name=value or Netscape format). "
             "Logged-in session cookies greatly reduce reCAPTCHA.",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between requests (default: 0)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--user-agent",
        metavar="UA",
        help="Custom User-Agent string",
    )
    parser.add_argument(
        "--app-version",
        metavar="VER",
        default="v1x304x0",
        help="x-app-version header (default: v1x304x0)",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Attempt to upload the file if no report exists "
             "(requires cookies and/or --captcha-token)",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="Never attempt upload (hash lookup only)",
    )
    parser.add_argument(
        "--captcha-token",
        metavar="TOKEN",
        help="g-recaptcha-response token (from browser or 2captcha). "
             "Bypasses RecaptchaRequiredError on upload.",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=120,
        metavar="SEC",
        help="Max seconds to wait for analysis after upload (default: 120)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"VTToolz {__version__}",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = args.target
    cookies = None
    if args.cookies:
        cookies = load_cookies_from_file(args.cookies)
        print(f"[*] Loaded {len(cookies)} cookies from {args.cookies}", file=sys.stderr)

    client_kwargs = {
        "cookies": cookies,
        "proxy": args.proxy,
        "timeout": args.timeout,
        "delay": args.delay,
        "app_version": args.app_version,
        "captcha_token": args.captcha_token,
    }
    if args.user_agent:
        client_kwargs["user_agent"] = args.user_agent

    client = VTClient(**client_kwargs)

    # Decide whether target is a hash or a local file
    hash_type = looks_like_hash(target)
    file_path: Path | None = None
    file_hash: str | None = None

    if hash_type:
        file_hash = target.lower()
        print(f"[*] Looking up {hash_type.upper()} hash …", file=sys.stderr)
    else:
        path = Path(target)
        if not path.is_file():
            print(f"[!] Not a valid file or hash: {target}", file=sys.stderr)
            return 1
        file_path = path
        print(f"[*] Computing SHA-256 of {path} …", file=sys.stderr)
        file_hash = hash_file(path, "sha256")
        print(f"[*] SHA-256: {file_hash}", file=sys.stderr)

    # 1) Try existing report
    raw = None
    try:
        raw = client.get_file_report(file_hash)
        print("[*] Report found.", file=sys.stderr)
    except Exception as exc:
        print(f"[*] No existing report ({exc})", file=sys.stderr)

        # 2) Upload if requested and we have a local file
        if file_path and args.upload and not args.no_upload:
            print("[*] Attempting upload …", file=sys.stderr)
            try:
                upload_resp = client.upload_file(
                    file_path,
                    captcha_token=args.captcha_token,
                )
                print(f"[*] Upload response: {json.dumps(upload_resp)[:200]}…", file=sys.stderr)

                # Extract analysis / file id
                analysis_id = None
                data = upload_resp.get("data", upload_resp)
                if isinstance(data, dict):
                    analysis_id = data.get("id")
                    # sometimes nested
                    if not analysis_id and "links" in data:
                        analysis_id = data.get("id")

                if analysis_id:
                    print(f"[*] Waiting for analysis {analysis_id} (max {args.wait}s) …", file=sys.stderr)
                    try:
                        client.wait_for_analysis(analysis_id, max_wait=args.wait)
                    except TimeoutError as te:
                        print(f"[!] {te}", file=sys.stderr)

                # Re-fetch the file report
                raw = client.get_file_report(file_hash)
            except RecaptchaRequiredError as re:
                print(f"[!] {re}", file=sys.stderr)
                print(
                    "[!] Tip: export cookies from a logged-in browser session "
                    "or supply a solved --captcha-token.",
                    file=sys.stderr,
                )
                return 3
            except Exception as up_exc:
                print(f"[!] Upload failed: {up_exc}", file=sys.stderr)
                return 4
        elif not args.no_upload and file_path:
            print(
                "[!] File unknown on VT. Use --upload (with --cookies or "
                "--captcha-token) to submit it.",
                file=sys.stderr,
            )
            return 2
        else:
            print("[!] No report available.", file=sys.stderr)
            return 2

    if raw is None:
        print("[!] Could not obtain report.", file=sys.stderr)
        return 2

    parsed = extract_detections(raw)

    if args.as_json:
        print(json.dumps(parsed, indent=2, ensure_ascii=False))
    else:
        print_report(parsed, verbose=args.verbose)

    return 0


if __name__ == "__main__":
    sys.exit(main())
