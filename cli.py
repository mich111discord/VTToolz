"""Command-line interface for VTToolz."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from . import __version__
from .captcha import (
    VT_SITEKEY,
    load_token_from_file,
    solve_2captcha,
    solve_anticaptcha,
    solve_external,
)
from .client import RecaptchaRequiredError, VTClient
from .report import extract_detections, print_report
from .utils import hash_file, load_cookies_from_file, looks_like_hash


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vttoolz",
        description=(
            "VTToolz – VirusTotal CLI without official API\n"
            "Hash lookup, detections, cookies bypass, optional upload + reCAPTCHA."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  vttoolz 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  vttoolz ./malware.exe -v
  vttoolz ./sample.bin --json -o report.json
  vttoolz HASH --format csv -o engines.csv
  vttoolz ./file.exe --cookies cookies.txt --proxy http://127.0.0.1:8080
  vttoolz ./unknown.bin --upload --cookies cookies.txt
  vttoolz ./unknown.bin --upload --captcha-token "03AFcWeA..."
  vttoolz ./unknown.bin --upload --2captcha-key YOUR_2CAPTCHA_KEY
  vttoolz --show-sitekey

reCAPTCHA bypass tips:
  1. Export cookies (JSON/Netscape) from logged-in browser → --cookies cookies.json
  2. Solve captcha in browser, copy g-recaptcha-response → --captcha-token
  3. 2captcha.com → --2captcha-key KEY
  4. anti-captcha.com → --anticaptcha-key KEY
  5. External tool → --captcha-solver "mytool {sitekey} {pageurl}"
  6. Token file → --captcha-file token.txt
        """,
    )

    # --- target ---
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="File path OR hash (MD5 / SHA-1 / SHA-256). Optional with --show-sitekey.",
    )

    # --- output ---
    out = parser.add_argument_group("Output")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Extra metadata (dates, tags, permalink)")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Minimal stderr (only errors)")
    out.add_argument("-j", "--json", action="store_true", dest="as_json",
                     help="JSON output (same as --format json)")
    out.add_argument("-f", "--format", choices=("text", "json", "csv", "raw"),
                     default="text",
                     help="Output format: text | json | csv | raw (default: text)")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Write result to FILE instead of stdout")
    out.add_argument("--only-detections", action="store_true",
                     help="Show only malicious/suspicious engines")
    out.add_argument("--engines", metavar="LIST",
                     help="Comma-separated engine names to highlight/filter")

    # --- network / identity ---
    net = parser.add_argument_group("Network & identity")
    net.add_argument("--cookies", metavar="FILE",
                     help="Cookies file: JSON (EditThisCookie), Netscape, or name=value. "
                          "Logged-in session greatly reduces reCAPTCHA.")
    net.add_argument("--proxy", metavar="URL",
                     help="HTTP/HTTPS proxy, e.g. http://127.0.0.1:8080")
    net.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                     help="Delay between requests in seconds (default: 0)")
    net.add_argument("--timeout", type=int, default=30, metavar="SEC",
                     help="Request timeout (default: 30)")
    net.add_argument("--user-agent", metavar="UA",
                     help="Custom User-Agent")
    net.add_argument("--app-version", metavar="VER", default="v1x304x0",
                     help="x-app-version header (default: v1x304x0)")

    # --- upload / captcha ---
    up = parser.add_argument_group("Upload & reCAPTCHA")
    up.add_argument("--upload", action="store_true",
                    help="Upload file if no report exists on VT")
    up.add_argument("--no-upload", action="store_true",
                    help="Never upload (hash lookup only)")
    up.add_argument("--captcha-token", metavar="TOKEN",
                    help="g-recaptcha-response token (manual / browser)")
    up.add_argument("--captcha-file", metavar="FILE",
                    help="Read captcha token from FILE (first non-empty line)")
    up.add_argument("--2captcha-key", dest="twocaptcha_key", metavar="KEY",
                    help="2captcha.com API key – auto-solve invisible reCAPTCHA")
    up.add_argument("--anticaptcha-key", dest="anticaptcha_key", metavar="KEY",
                    help="anti-captcha.com API key – auto-solve invisible reCAPTCHA")
    up.add_argument("--captcha-solver", metavar="CMD",
                    help="External solver command. Placeholders: {sitekey} {pageurl}. "
                         "Must print token on stdout.")
    up.add_argument("--show-sitekey", action="store_true",
                    help="Print VirusTotal reCAPTCHA sitekey and exit")
    up.add_argument("--wait", type=int, default=120, metavar="SEC",
                    help="Max seconds to wait after upload (default: 120)")
    up.add_argument("--password", metavar="PASS",
                    help="Password for encrypted ZIP samples")

    # --- hashing ---
    hsh = parser.add_argument_group("Hashing")
    hsh.add_argument("--hash-algo", choices=("sha256", "sha1", "md5"),
                     default="sha256",
                     help="Algo when hashing a local file (default: sha256)")

    parser.add_argument("--version", action="version",
                        version=f"VTToolz {__version__}")

    return parser


def _log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg, file=sys.stderr)


def _write_output(text: str, path: str | None) -> None:
    if path:
        Path(path).write_text(text, encoding="utf-8")
        print(f"[*] Written to {path}", file=sys.stderr)
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def _format_csv(parsed: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["engine", "category", "result", "method", "engine_version", "engine_update"])
    for d in parsed.get("detections", []):
        w.writerow([
            d.get("engine", ""),
            d.get("category", ""),
            d.get("result", ""),
            d.get("method", ""),
            d.get("engine_version", ""),
            d.get("engine_update", ""),
        ])
    return buf.getvalue()


def _resolve_captcha_token(args: argparse.Namespace, quiet: bool) -> str | None:
    token = args.captcha_token
    if not token and args.captcha_file:
        token = load_token_from_file(args.captcha_file)
        if token:
            _log(f"[*] Captcha token loaded from {args.captcha_file}", quiet)

    if not token and getattr(args, "captcha_solver", None):
        _log(f"[*] Solving reCAPTCHA via external solver…", quiet)
        try:
            token = solve_external(args.captcha_solver)
            _log("[*] External solver token received.", quiet)
        except Exception as exc:
            _log(f"[!] External solver failed: {exc}", quiet)
            return None

    if not token and args.twocaptcha_key:
        _log("[*] Solving reCAPTCHA via 2captcha…", quiet)
        try:
            token = solve_2captcha(args.twocaptcha_key)
            _log("[*] 2captcha token received.", quiet)
        except Exception as exc:
            _log(f"[!] 2captcha failed: {exc}", quiet)
            return None

    if not token and getattr(args, "anticaptcha_key", None):
        _log("[*] Solving reCAPTCHA via anti-captcha…", quiet)
        try:
            token = solve_anticaptcha(args.anticaptcha_key)
            _log("[*] anti-captcha token received.", quiet)
        except Exception as exc:
            _log(f"[!] anti-captcha failed: {exc}", quiet)
            return None

    return token


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.show_sitekey:
        print(VT_SITEKEY)
        print(f"# page: https://www.virustotal.com/gui/home/upload")
        return 0

    if not args.target:
        parser.print_help()
        return 0

    quiet = args.quiet
    if args.as_json:
        args.format = "json"

    cookies = None
    if args.cookies:
        cookies = load_cookies_from_file(args.cookies)
        _log(f"[*] Loaded {len(cookies)} cookies from {args.cookies}", quiet)

    captcha_token = _resolve_captcha_token(args, quiet)

    client_kwargs = {
        "cookies": cookies,
        "proxy": args.proxy,
        "timeout": args.timeout,
        "delay": args.delay,
        "app_version": args.app_version,
        "captcha_token": captcha_token,
    }
    if args.user_agent:
        client_kwargs["user_agent"] = args.user_agent

    client = VTClient(**client_kwargs)

    hash_type = looks_like_hash(args.target)
    file_path: Path | None = None
    file_hash: str | None = None

    if hash_type:
        file_hash = args.target.lower()
        _log(f"[*] Looking up {hash_type.upper()} hash …", quiet)
    else:
        path = Path(args.target)
        if not path.is_file():
            print(f"[!] Not a valid file or hash: {args.target}", file=sys.stderr)
            return 1
        file_path = path
        _log(f"[*] Computing {args.hash_algo.upper()} of {path} …", quiet)
        file_hash = hash_file(path, args.hash_algo)
        _log(f"[*] {args.hash_algo.upper()}: {file_hash}", quiet)

    raw = None
    try:
        raw = client.get_file_report(file_hash)
        _log("[*] Report found.", quiet)
    except Exception as exc:
        _log(f"[*] No existing report ({exc})", quiet)

        if file_path and args.upload and not args.no_upload:
            _log("[*] Attempting upload …", quiet)
            try:
                upload_resp = client.upload_file(
                    file_path,
                    captcha_token=captcha_token,
                    password=args.password,
                )
                _log(f"[*] Upload OK: {json.dumps(upload_resp)[:180]}…", quiet)

                data = upload_resp.get("data", upload_resp)
                analysis_id = data.get("id") if isinstance(data, dict) else None
                if analysis_id:
                    _log(f"[*] Waiting for analysis {analysis_id} (max {args.wait}s) …", quiet)
                    try:
                        client.wait_for_analysis(analysis_id, max_wait=args.wait)
                    except TimeoutError as te:
                        _log(f"[!] {te}", quiet)

                raw = client.get_file_report(file_hash)
            except RecaptchaRequiredError as re:
                print(f"[!] {re}", file=sys.stderr)
                print(
                    "[!] Tips:\n"
                    "    --cookies cookies.json         (JSON / Netscape / name=value)\n"
                    "    --captcha-token TOKEN          (from DevTools)\n"
                    "    --captcha-file token.txt\n"
                    "    --2captcha-key KEY             (2captcha.com)\n"
                    "    --anticaptcha-key KEY          (anti-captcha.com)\n"
                    "    --captcha-solver \"CMD {sitekey} {pageurl}\"\n"
                    "    --show-sitekey",
                    file=sys.stderr,
                )
                return 3
            except Exception as up_exc:
                print(f"[!] Upload failed: {up_exc}", file=sys.stderr)
                return 4
        elif not args.no_upload and file_path:
            print(
                "[!] File unknown on VT. Use --upload with --cookies / "
                "--captcha-token / --2captcha-key.",
                file=sys.stderr,
            )
            return 2
        else:
            print("[!] No report available.", file=sys.stderr)
            return 2

    if raw is None:
        print("[!] Could not obtain report.", file=sys.stderr)
        return 2

    if args.format == "raw":
        text = json.dumps(raw, indent=2, ensure_ascii=False)
        _write_output(text + "\n", args.output)
        return 0

    parsed = extract_detections(raw)

    # optional engine filter
    if args.engines:
        wanted = {e.strip().lower() for e in args.engines.split(",") if e.strip()}
        parsed["detections"] = [
            d for d in parsed["detections"]
            if d.get("engine", "").lower() in wanted
        ]
        parsed["detection_count"] = len(parsed["detections"])

    if args.only_detections:
        parsed["detections"] = [
            d for d in parsed["detections"]
            if d.get("category") in ("malicious", "suspicious")
        ]
        parsed["detection_count"] = len(parsed["detections"])

    if args.format == "json":
        text = json.dumps(parsed, indent=2, ensure_ascii=False)
        _write_output(text + "\n", args.output)
    elif args.format == "csv":
        text = _format_csv(parsed)
        _write_output(text, args.output)
    else:
        # text – capture print_report to string if -o
        if args.output:
            buf = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = buf
            try:
                print_report(parsed, verbose=args.verbose)
            finally:
                sys.stdout = old_stdout
            _write_output(buf.getvalue(), args.output)
        else:
            print_report(parsed, verbose=args.verbose)

    return 0


if __name__ == "__main__":
    sys.exit(main())
