#!/usr/bin/env python3
"""
Regular passive security scan of SIPA OS's own domains — same checks as
functions/api/scan.js (the public EilatSecure landing scanner), run on a
schedule against a fixed target list instead of an ad-hoc user-submitted URL.

Read-only GET requests only. No auth bypass, no injection payloads, no brute
force, no port scanning. Same philosophy as the manual scanner: things a
normal visitor/crawler would request.
"""
import json
import ssl
import socket
import sys
from datetime import datetime, timezone
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import URLError, HTTPError

TARGETS = [
    "sipa-os.org",
    "focus.sipa-os.org",
    "ai.sipa-os.org",
    "shell.sipa-os.org",
    "games.sipa-os.org",
    "syntax.sipa-os.org",
    "deck.sipa-os.org",
    "neuropower.sipa-os.org",
    "community.sipa-os.org",
    "status.sipa-os.org",
    "pixels.sipa-os.org",
    "sipa-os.online",
    "app.soulinpsyabstract.store",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php.bak",
    "/config.json", "/.DS_Store", "/backup.zip", "/phpinfo.php",
]

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)", "low"),
    ("content-security-policy", "Content-Security-Policy", "medium"),
    ("x-frame-options", "X-Frame-Options", "low"),
    ("x-content-type-options", "X-Content-Type-Options", "low"),
    ("referrer-policy", "Referrer-Policy", "low"),
    ("permissions-policy", "Permissions-Policy", "low"),
]

TIMEOUT = 6
UA = "EilatSecure-SelfScan/1.0 (+https://web-secure.sipa-os.org)"


def fetch(url, method="GET"):
    req = Request(url, headers={"User-Agent": UA}, method=method)
    try:
        resp = urlopen(req, timeout=TIMEOUT)
        return resp, None
    except HTTPError as e:
        return e, None
    except URLError as e:
        return None, str(e.reason)
    except Exception as e:
        return None, str(e)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_no_redirect(url, method="GET"):
    # urlopen() follows redirects transparently by default, which makes it
    # useless for checking whether a redirect exists — need the raw 3xx
    # response itself, not what it points to.
    req = Request(url, headers={"User-Agent": UA}, method=method)
    opener = build_opener(_NoRedirect)
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        return resp, None
    except HTTPError as e:
        return e, None
    except URLError as e:
        return None, str(e.reason)
    except Exception as e:
        return None, str(e)


def cert_days_left(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (expires - datetime.now(timezone.utc)).days
    except Exception:
        return None


def scan_target(host):
    findings = []
    https_url = f"https://{host}/"
    resp, err = fetch(https_url)

    if resp is None:
        findings.append({"severity": "critical", "title": "Unreachable over HTTPS", "detail": err})
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for key, label, sev in SECURITY_HEADERS:
        if key not in headers:
            findings.append({"severity": sev, "title": f"Missing {label}"})

    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        if "secure" not in low:
            findings.append({"severity": "medium", "title": "Cookie missing Secure flag"})
        if "httponly" not in low:
            findings.append({"severity": "medium", "title": "Cookie missing HttpOnly flag"})

    if headers.get("x-powered-by"):
        findings.append({"severity": "low", "title": f"X-Powered-By discloses: {headers['x-powered-by']}"})
    server = headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"severity": "low", "title": f"Server header discloses version: {server}"})

    # HTTP -> HTTPS redirect (fetch_no_redirect — plain fetch() follows
    # redirects transparently and would always see the final 200, never the 3xx)
    http_resp, _ = fetch_no_redirect(f"http://{host}/")
    if http_resp is not None:
        status = getattr(http_resp, "status", getattr(http_resp, "code", None))
        loc = http_resp.headers.get("Location", "") if hasattr(http_resp, "headers") else ""
        if not (status and 300 <= status < 400 and loc.startswith("https://")):
            findings.append({"severity": "high", "title": "No forced HTTPS redirect"})

    # Sensitive paths
    exposed = []
    for path in SENSITIVE_PATHS:
        r, _ = fetch(f"https://{host}{path}")
        if r is not None:
            status = getattr(r, "status", getattr(r, "code", None))
            ct = r.headers.get("Content-Type", "") if hasattr(r, "headers") else ""
            if status == 200 and "text/html" not in ct:
                exposed.append(path)
    if exposed:
        findings.append({"severity": "critical", "title": f"Exposed sensitive file(s): {', '.join(exposed)}"})

    # TLS expiry
    days = cert_days_left(host)
    if days is not None and days < 21:
        findings.append({"severity": "high" if days < 7 else "medium", "title": f"TLS cert expires in {days} days"})

    return findings


def main():
    ran_at = datetime.now(timezone.utc).isoformat()
    report = {"ran_at": ran_at, "targets": {}}
    any_findings = False

    for host in TARGETS:
        findings = scan_target(host)
        report["targets"][host] = findings
        if findings:
            any_findings = True

    print(f"[{ran_at}] EilatSecure self-scan: {len(TARGETS)} targets, "
          f"{'FINDINGS' if any_findings else 'clean'}")
    for host, findings in report["targets"].items():
        if not findings:
            continue
        for f in findings:
            print(f"  {host}: [{f['severity']}] {f['title']}")

    print(json.dumps(report))
    sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
    main()
