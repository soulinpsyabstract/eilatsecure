# WebSecure

Passive, B2B website-security scanning for local Eilat businesses — a
separate brand from SIPA OS, run by the same team.

**Live site:** https://web-secure.sipa-os.org

## What this is

WebSecure gives small local businesses (the kind that had a website built
by a freelancer or a page builder years ago and never touched it again) a
plain-language, non-intrusive check of how exposed their site actually is,
plus a paid path to a deeper human-reviewed audit and — as a cross-sell —
website/AI-agent build services from the same team under the `web.sipa-os.org`
brand.

It is intentionally **passive**. Every request the scanner makes is one a
normal browser, visitor, or search-engine crawler would also make. It does
**not**:

- attempt logins or credential guessing
- send injection payloads (SQLi, XSS, etc.)
- brute-force anything
- port-scan beyond the default web ports a browser would hit

This is a read-only, GET-only reconnaissance tool, not a penetration tester.

## Services (as shown on the landing page)

| Service | Price | What you get |
|---|---|---|
| Free scan | free | Instant automated pass/fail report from the passive scanner below |
| Full audit | from ₪2,000 | A human goes through what the free scan found, plus what it can't see (outdated CMS versions, weak passwords, exposed admin panels) — clear report in Hebrew within 48 hours |
| Website build (cross-sell, `web.sipa-os.org`) | from ₪1,200 | A real landing page, live within 24 hours — WhatsApp button, Google Maps, HTTPS, three rounds of edits included |
| AI WhatsApp agent (cross-sell, `web.sipa-os.org`) | from ₪4,000 | AI WhatsApp agent for the business |

## What the passive scanner actually checks

Implemented in `functions/api/scan.js` (a Cloudflare Pages Function backing
`POST /api/scan`). Given a URL, it checks:

1. **HTTPS reachability** — can the site be reached over HTTPS at all
2. **HTTP → HTTPS redirect** — does plain `http://` force an upgrade to
   `https://`, or can traffic still go over cleartext
3. **Six security response headers** — presence/absence of:
   - `Strict-Transport-Security` (HSTS)
   - `Content-Security-Policy`
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
   - `Permissions-Policy`
4. **Cookie flags** — whether `Set-Cookie` headers carry `Secure` and
   `HttpOnly`
5. **Technology/version disclosure** — `Server` and `X-Powered-By` headers
   leaking stack/version info
6. **Mixed content** — `http://` resources referenced from an `https://` page
7. **Exposed sensitive paths** — a fixed list of conventionally-public-if-
   present paths is probed with plain GETs: `/.env`, `/.git/config`,
   `/.git/HEAD`, `/wp-config.php.bak`, `/config.json`, `/.DS_Store`,
   `/backup.zip`, `/phpinfo.php`
8. **TLS** — reachability/handshake over HTTPS (certificate expiry is checked
   separately in `scan_own_domains.py`, see below)

The scan returns a JSON payload: `{ target, scannedAt, grade, findings[] }`,
where `grade` starts at 100 and is docked per finding by severity.

### What it does NOT do

No logins, no injection testing, no brute-force, no port scanning. If a
prospective customer needs that, it is out of scope for this tool and would
require an explicit, authorized penetration test — not something a passive
web scanner should ever attempt without a signed engagement.

## `scan_own_domains.py`

A separate, **not customer-facing** script. It runs the same category of
passive checks (headers, cookie flags, sensitive paths, forced HTTPS
redirect, plus TLS certificate expiry) against a fixed list of the
architect's own 14 SIPA OS domains, for self-monitoring rather than as part
of the WebSecure product. It is currently run **manually** — it is not yet
wired into a cron schedule or CI job.

## Deploying

The site is a Cloudflare Pages project (`eilatsecure`) already deployed and
attached to its custom domain — no new infrastructure should be created for
routine deploys. To ship a change:

```bash
export CLOUDFLARE_API_TOKEN="$CLOUDFLARE_WORKERS_TOKEN"
npx wrangler pages deploy . --project-name=eilatsecure --branch=main
```

## Domains — read this before linking anywhere

- **`web-secure.sipa-os.org`** is the current, working, canonical domain —
  a Cloudflare Pages custom domain on the `sipa-os.org` zone. This is the
  only URL that should ever be presented as "the live site."
- **`eilatsecure.com`** is a separate domain, registered via IONOS, that is
  currently **non-functional** — it is stuck mid-transfer between IONOS and
  Cloudflare and WHOIS currently returns "no match." It is **not** live and
  should not be linked to or treated as reachable anywhere until the
  transfer completes.

## Repository layout

```
index.html                                     landing page (free-scan form + pricing)
functions/api/scan.js                          Cloudflare Pages Function — the scan API
scan_own_domains.py                            self-monitoring script (not customer-facing)
REMEDIATION/G15_REMEDIATION_LOG__2026-08-16.md historical one-time remediation log
*.sha256 / *.TAG                               integrity seals (see below)
```

## Integrity seals

Every content file in this repo is sealed with a `<file>.sha256` and
`<file>.TAG` sidecar pair, produced by the shared `reseal.py` tool used
across SIPA OS projects. A `.TAG` records `FILE`, `SHA256`, `SIZE`, `DEVICE`,
and `TS` (plus any extra fields already present, which reseal preserves
rather than dropping). Reseal any content file you change:

```bash
python3 /path/to/sipa-os-governance/scripts/reseal.py <path> [DEVICE]
```

This README is sealed too — check `README.md.sha256` / `README.md.TAG`
alongside it.
