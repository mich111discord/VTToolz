# VTToolz

**VirusTotal CLI without the official API.**

Hash lookup, full detection list (engines + threat names), cookies bypass, reCAPTCHA token support, proxies, JSON output.

> No API key required. Uses VirusTotal public UI endpoints + reverse-engineered anti-abuse header.

## Features

- Lookup by **SHA-256 / SHA-1 / MD5** or local **file path**
- Full antivirus detection list (engine + result name)
- Stats (malicious / suspicious / undetected …)
- **Cookies support** – logged-in session greatly reduces reCAPTCHA
- **Upload** of unknown files (`--upload`)
- **reCAPTCHA token** injection (`--captcha-token`) for bypass
- Proxy support
- JSON / human-readable output
- Configurable delay, timeout, User-Agent, app-version
- GitHub Actions for automated builds & releases

## Install

```bash
pip install -e .
# or
pip install -r requirements.txt
```

## Usage

```bash
# By hash
vttoolz 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# By file (computes SHA-256 locally)
vttoolz ./suspicious.exe

# JSON output
vttoolz ./sample.bin --json

# Verbose + cookies + proxy
vttoolz 44d88612fea8a8f36de82e1278abb02f \
  --verbose \
  --cookies cookies.txt \
  --proxy http://127.0.0.1:8080

# Upload unknown file (cookies recommended)
vttoolz ./unknown.bin --upload --cookies cookies.txt

# Upload with solved reCAPTCHA token
vttoolz ./unknown.bin --upload --captcha-token "03AFcWeA...."
```

### Main flags

| Flag | Description |
|------|-------------|
| `target` | File path **or** hash |
| `-v, --verbose` | Extra metadata |
| `-j, --json` | JSON output |
| `--cookies FILE` | Cookies file (logged-in session helps a lot) |
| `--proxy URL` | HTTP/S proxy |
| `--delay SEC` | Delay between requests |
| `--timeout SEC` | Request timeout |
| `--user-agent UA` | Custom UA |
| `--app-version VER` | x-app-version header |
| `--upload` | Try to upload if no report exists |
| `--no-upload` | Never attempt upload |
| `--captcha-token TOKEN` | g-recaptcha-response (bypass reCAPTCHA) |
| `--wait SEC` | Max wait after upload (default 120) |
| `--version` | Show version |

## Cookies bypass

Export cookies from a **logged-in** VirusTotal browser session (EditThisCookie, Cookie-Editor, or DevTools).

Format accepted:

```
name=value
name2=value2
```

or classic Netscape format.

Good cookies often let you call `/ui/files/upload_url` without solving captcha.

## reCAPTCHA token

VirusTotal uses **invisible reCAPTCHA Enterprise** (sitekey `6LdawOwtAAAAAEJuyEXijrVsxVKwqhUS8E1rUkT3`).

You can:

1. Solve it in a real browser and copy `g-recaptcha-response`
2. Use a service like 2captcha / anti-captcha and pass the token via `--captcha-token`

## How it works

1. Generates `X-VT-Anti-Abuse-Header` (base64 of random + "dont be evil" + timestamp)
2. Talks to `https://www.virustotal.com/ui/files/{hash}`
3. Parses `last_analysis_stats` + `last_analysis_results`
4. For upload: requests one-time URL from `/ui/files/upload_url` (cookies + optional captcha token), then POSTs the file

## Development

```bash
python -m vttoolz 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f -v
```

## License

MIT
