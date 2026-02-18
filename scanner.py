import re
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

HEADERS = {"User-Agent": "Mozilla/5.0 (VibeScan/1.0)"}

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SECRET_PATTERNS = [
    (r'sk-[a-zA-Z0-9]{20,}',                                   "OpenAI API key",         CRITICAL),
    (r'AIza[0-9A-Za-z\-_]{35}',                                "Google API key",         CRITICAL),
    (r'AKIA[0-9A-Z]{16}',                                      "AWS Access Key ID",      CRITICAL),
    (r'ghp_[a-zA-Z0-9]{36}',                                   "GitHub Personal Token",  CRITICAL),
    (r'Bearer [a-zA-Z0-9\-_\.]{20,}',                          "Bearer token exposed",   HIGH),
    (r'["\']api[_-]?key["\']\s*:\s*["\'][^"\']{8,}["\']',     "Generic API key",        HIGH),
    (r'["\']secret["\']\s*:\s*["\'][^"\']{8,}["\']',          "Generic secret",         HIGH),
    (r'["\']password["\']\s*:\s*["\'][^"\']{4,}["\']',        "Hardcoded password",     CRITICAL),
    (r'NEXT_PUBLIC_[A-Z_]+=.{4,}',                             "Exposed Next.js env var",MEDIUM),
]

SENSITIVE_FILES = [
    ("/.env",             "Environment file exposed",      CRITICAL),
    ("/.env.local",       ".env.local exposed",            CRITICAL),
    ("/.git/config",      "Git config exposed",            HIGH),
    ("/.git/HEAD",        "Git HEAD exposed",              HIGH),
    ("/config.json",      "config.json exposed",           HIGH),
    ("/api-docs",         "API docs exposed",              MEDIUM),
    ("/swagger.json",     "Swagger/OpenAPI spec exposed",  MEDIUM),
    ("/openapi.json",     "OpenAPI spec exposed",          MEDIUM),
    ("/robots.txt",       "robots.txt (info)",             INFO),
]

SECURITY_HEADERS = [
    ("content-security-policy",   "Missing Content-Security-Policy",  MEDIUM),
    ("x-frame-options",           "Missing X-Frame-Options",          LOW),
    ("x-content-type-options",    "Missing X-Content-Type-Options",   LOW),
    ("strict-transport-security", "Missing HSTS header",              MEDIUM),
]

IDOR_PROBES = [
    "/api/user/1", "/api/users", "/api/profile",
    "/api/admin",  "/api/users/1",
]

REDIRECT_PARAMS = ["next", "redirect", "url", "return", "returnUrl", "goto"]


def _get(url, timeout=5, extra_headers=None):
    h = {**HEADERS, **(extra_headers or {})}
    try:
        return requests.get(url, timeout=timeout, headers=h,
                            allow_redirects=True, verify=True)
    except requests.exceptions.SSLError:
        try:
            return requests.get(url, timeout=timeout, headers=h,
                                allow_redirects=True, verify=False)
        except Exception:
            return None
    except Exception:
        return None


def _post(url, data=None, timeout=5):
    try:
        return requests.post(url, data=data, timeout=timeout,
                             headers=HEADERS, allow_redirects=True, verify=True)
    except Exception:
        return None


def _check_sensitive_file(args):
    base, path, label, severity = args
    r = _get(base + path)
    if r and r.status_code == 200 and len(r.text) > 10:
        return {"title": label, "severity": severity,
                "detail": f"Accessible at: {base + path}"}
    return None


def _check_idor(args):
    base, path = args
    r = _get(base + path)
    if r and r.status_code == 200:
        ct = r.headers.get("content-type", "")
        if "json" in ct or (len(r.text) > 20 and r.text.strip().startswith("{")):
            return {"title": "Possible IDOR / unauthenticated API access", "severity": HIGH,
                    "detail": f"Endpoint returned 200 with data: {base + path}"}
    return None


def scan(url: str, timeout: int = 5) -> list:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    def add(title, severity, detail=""):
        findings.append({"title": title, "severity": severity, "detail": detail})

    # Initial fetch
    resp = _get(url, timeout=timeout)
    if resp is None:
        add("Target unreachable during scan", HIGH,
            f"Could not connect to {url} — check the URL and your network")
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    html = resp.text

    # --- 1. Security headers ---
    for header, label, severity in SECURITY_HEADERS:
        if header not in headers:
            add(label, severity, f"Header '{header}' not present in response")

    # --- 2. Open CORS ---
    cors_resp = _get(url, timeout=timeout, extra_headers={"Origin": "https://evil.com"})
    if cors_resp:
        acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or acao == "https://evil.com":
            add("Open CORS Policy", HIGH,
                f"Access-Control-Allow-Origin: {acao} — arbitrary origins accepted")

    # --- 3. Exposed secrets in HTML ---
    for pattern, label, severity in SECRET_PATTERNS:
        matches = re.findall(pattern, html)
        if matches:
            preview = matches[0][:60] + ("..." if len(matches[0]) > 60 else "")
            add(f"Exposed secret: {label}", severity, f"Found in page source: {preview}")

    # --- 4. Exposed secrets in first 3 external JS files ---
    js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)[:3]
    for src in js_srcs:
        js_url = src if src.startswith("http") else urljoin(base, src)
        js_resp = _get(js_url, timeout=timeout)
        if js_resp and js_resp.status_code == 200:
            for pattern, label, severity in SECRET_PATTERNS:
                matches = re.findall(pattern, js_resp.text)
                if matches:
                    preview = matches[0][:60] + ("..." if len(matches[0]) > 60 else "")
                    add(f"Exposed secret in JS bundle: {label}", severity,
                        f"Found in {js_url}: {preview}")

    # --- 5. Sensitive files (parallel) ---
    file_args = [(base, path, label, sev) for path, label, sev in SENSITIVE_FILES]
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(_check_sensitive_file, a): a for a in file_args}
        for fut in as_completed(futures, timeout=15):
            try:
                result = fut.result()
                if result:
                    findings.append(result)
            except Exception:
                pass

    # --- 6. Error page info disclosure ---
    r = _get(base + "/this-path-does-not-exist-99999", timeout=timeout)
    if r:
        for pattern, label in [
            (r'Traceback \(most recent call last\)', "Python traceback in error page"),
            (r'Flask|Django|FastAPI|Express|Next\.js', "Framework name in error page"),
            (r'SQLite|PostgreSQL|MySQL|MongoDB', "Database name in error page"),
        ]:
            if re.search(pattern, r.text, re.IGNORECASE):
                add(f"Info disclosure: {label}", MEDIUM, f"Triggered at: {base}/this-path-does-not-exist-99999")
                break

    # --- 7. Rate limiting check (3 rapid requests, not 8) ---
    auth_endpoints = ["/login", "/api/login", "/signin"]
    for endpoint in auth_endpoints:
        auth_url = base + endpoint
        r = _get(auth_url, timeout=timeout)
        if r and r.status_code in (200, 405):
            responses = [_post(auth_url, data={"username": "admin", "password": "wrong"}, timeout=3)
                         for _ in range(3)]
            codes = [r.status_code for r in responses if r]
            if codes and 429 not in codes:
                add("No rate limiting on login endpoint", MEDIUM,
                    f"3 rapid requests to {auth_url} — no 429 response")
            break

    # --- 8. IDOR probes (parallel) ---
    idor_args = [(base, path) for path in IDOR_PROBES]
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(_check_idor, a): a for a in idor_args}
        for fut in as_completed(futures, timeout=10):
            try:
                result = fut.result()
                if result:
                    findings.append(result)
            except Exception:
                pass

    # --- 9. Open redirect ---
    for param in REDIRECT_PARAMS[:3]:
        test_url = f"{url}?{param}=https://evil.com"
        r = _get(test_url, timeout=timeout)
        if r and r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("location", "")
            if "evil.com" in location:
                add("Open redirect", HIGH,
                    f"Redirects to external URL via ?{param}= — Location: {location}")

    # --- 10. XSS reflection ---
    xss_payload = "<script>alert(1)</script>"
    for param in ["q", "search", "query", "s"][:2]:
        test_url = f"{url}?{param}={requests.utils.quote(xss_payload)}"
        r = _get(test_url, timeout=timeout)
        if r and xss_payload in r.text:
            add("Reflected XSS", HIGH,
                f"Payload reflected unescaped via ?{param}= at {test_url}")
            break

    return findings
