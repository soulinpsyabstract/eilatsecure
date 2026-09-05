// Passive, non-intrusive website security scan.
// Only requests things a normal visitor/browser/search-engine crawler would
// request (the homepage, and a short list of paths that are conventionally
// public if present). No auth bypass, no injection payloads, no brute force,
// no port scanning beyond default web ports. Read-only GET requests only.

const SENSITIVE_PATHS = [
  "/.env",
  "/.git/config",
  "/.git/HEAD",
  "/wp-config.php.bak",
  "/config.json",
  "/.DS_Store",
  "/backup.zip",
  "/phpinfo.php",
];

const SECURITY_HEADERS = [
  { key: "strict-transport-security", label: "HSTS (Strict-Transport-Security)" },
  { key: "content-security-policy", label: "Content-Security-Policy" },
  { key: "x-frame-options", label: "X-Frame-Options" },
  { key: "x-content-type-options", label: "X-Content-Type-Options" },
  { key: "referrer-policy", label: "Referrer-Policy" },
  { key: "permissions-policy", label: "Permissions-Policy" },
];

function normalizeUrl(input) {
  let url = input.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  return new URL(url);
}

async function safeFetch(url, opts = {}) {
  try {
    const res = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
      headers: { "User-Agent": "EilatSecure-Scanner/1.0 (+https://web-secure.sipa-os.org)" },
      ...opts,
    });
    return { ok: true, res };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : "fetch failed" };
  }
}

export async function onRequestPost(context) {
  const { request } = context;
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "bad request" }, { status: 400 });
  }

  const target = String(body.url ?? "").trim();
  if (!target) return Response.json({ error: "url required" }, { status: 400 });

  let parsed;
  try {
    parsed = normalizeUrl(target);
  } catch {
    return Response.json({ error: "invalid url" }, { status: 400 });
  }

  const findings = [];
  let grade = 100;

  // 1. HTTPS check
  const httpsUrl = new URL(parsed);
  httpsUrl.protocol = "https:";
  const httpsResult = await safeFetch(httpsUrl.toString());

  if (!httpsResult.ok) {
    findings.push({
      severity: "critical",
      title: "Site unreachable over HTTPS",
      detail: httpsResult.error,
    });
    grade -= 40;
  } else {
    const res = httpsResult.res;

    // Follow one redirect hop to get final headers (still same-origin scan only)
    let finalRes = res;
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      const loc = new URL(res.headers.get("location"), httpsUrl);
      const hop = await safeFetch(loc.toString());
      if (hop.ok) finalRes = hop.res;
    }

    // 2. Security headers
    for (const h of SECURITY_HEADERS) {
      if (!finalRes.headers.get(h.key)) {
        findings.push({
          severity: h.key === "content-security-policy" ? "medium" : "low",
          title: `Missing ${h.label}`,
          detail: `Response does not set the ${h.label} header — reduces defense-in-depth against clickjacking/XSS/downgrade attacks.`,
        });
        grade -= h.key === "content-security-policy" ? 8 : 4;
      }
    }

    // 3. Cookie flags
    const setCookie = finalRes.headers.get("set-cookie");
    if (setCookie) {
      const lower = setCookie.toLowerCase();
      if (!lower.includes("secure")) {
        findings.push({ severity: "medium", title: "Cookie missing Secure flag", detail: "A session/tracking cookie is set without the Secure flag — it can be sent over unencrypted HTTP." });
        grade -= 6;
      }
      if (!lower.includes("httponly")) {
        findings.push({ severity: "medium", title: "Cookie missing HttpOnly flag", detail: "A cookie is readable by JavaScript, increasing XSS impact if the site has any script-injection bug." });
        grade -= 6;
      }
    }

    // 4. Server / version disclosure
    const serverHeader = finalRes.headers.get("server");
    const poweredBy = finalRes.headers.get("x-powered-by");
    if (poweredBy) {
      findings.push({ severity: "low", title: "Technology disclosure via X-Powered-By", detail: `Header reveals: ${poweredBy}. Makes it easier to target known vulnerabilities for that stack/version.` });
      grade -= 3;
    }
    if (serverHeader && /\d/.test(serverHeader)) {
      findings.push({ severity: "low", title: "Server version disclosed", detail: `Server header reveals: ${serverHeader}.` });
      grade -= 3;
    }

    // 5. Mixed content (cheap check on homepage HTML only)
    try {
      const html = await finalRes.clone().text();
      if (/src=["']http:\/\//i.test(html) || /href=["']http:\/\/(?!.*\.w3\.org)/i.test(html)) {
        findings.push({ severity: "medium", title: "Possible mixed content", detail: "Page references http:// resources while served over https:// — browsers may block or warn." });
        grade -= 5;
      }
    } catch {}
  }

  // 6. HTTP → HTTPS redirect (run in parallel with path probes below)
  const httpUrl = new URL(parsed);
  httpUrl.protocol = "http:";
  const httpResultPromise = safeFetch(httpUrl.toString());

  // 7. Sensitive path exposure — run all probes concurrently, capped overall.
  const pathProbes = SENSITIVE_PATHS.map((path) => {
    const probeUrl = new URL(path, httpsUrl);
    return safeFetch(probeUrl.toString()).then((probe) => ({ path, probe }));
  });

  const [httpResult, pathResults] = await Promise.all([
    httpResultPromise,
    Promise.all(pathProbes),
  ]);

  if (httpResult.ok) {
    const status = httpResult.res.status;
    const loc = httpResult.res.headers.get("location") || "";
    const redirectsToHttps = status >= 300 && status < 400 && loc.startsWith("https://");
    if (!redirectsToHttps) {
      findings.push({ severity: "high", title: "No forced HTTPS redirect", detail: "Visiting the plain http:// version does not redirect to https:// — traffic can be intercepted." });
      grade -= 12;
    }
  }

  const exposedPaths = [];
  for (const { path, probe } of pathResults) {
    if (probe.ok && probe.res.status === 200) {
      const ct = probe.res.headers.get("content-type") || "";
      if (!ct.includes("text/html")) {
        exposedPaths.push(path);
      }
    }
  }
  if (exposedPaths.length) {
    findings.push({
      severity: "critical",
      title: "Publicly exposed sensitive file(s)",
      detail: `Found accessible: ${exposedPaths.join(", ")}. These commonly leak credentials or source code.`,
    });
    grade -= 30;
  }

  grade = Math.max(0, Math.min(100, Math.round(grade)));
  findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity];
  });

  return Response.json({
    target: httpsUrl.hostname,
    scannedAt: new Date().toISOString(),
    grade,
    findings,
  });
}
