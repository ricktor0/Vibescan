# VibeScan

Detect AI-generated ("vibe coded") web apps and scan them for common vulnerabilities — no APIs required.

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Detect only
python vibescan.py https://target.com

# Detect + vuln scan
python vibescan.py https://target.com --scan

# Auto-scan if vibe score > 50
python vibescan.py https://target.com --auto-scan

# Skip detection, just scan
python vibescan.py https://target.com --no-detect --scan

# JSON output (for piping/automation)
python vibescan.py https://target.com --scan --json

# Custom timeout
python vibescan.py https://target.com --scan --timeout 15
```

---

## What It Detects

**Vibe Code Signals:**
- Meta generator tags (v0, Bolt, Lovable, etc.)
- Vercel / Netlify / Railway / Replit hosting
- shadcn/ui component patterns
- Next.js / Vite framework fingerprints
- Tailwind CSS usage
- Generic placeholder text
- Missing security headers

**Vulnerability Checks:**
- Exposed API keys / secrets in HTML and JS bundles
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Open CORS policy
- Sensitive file exposure (`.env`, `.git/config`, `swagger.json`, etc.)
- Directory listing
- Error page info disclosure
- No rate limiting on auth endpoints
- Unauthenticated API access (IDOR probes)
- Open redirect
- Reflected XSS

---

## Example Output

```
  Score   : 72/100
  Verdict : Likely vibe coded

  Signals:
    [+15]  Vercel hosting detected
    [+10]  Next.js detected
    [+15]  shadcn/ui component patterns detected
    [+10]  Tailwind CSS detected
    [+10]  Generic placeholder text found
    [ +5]  Missing security headers: content-security-policy, strict-transport-security
    [ +7]  Possible shadcn/ui pattern detected

  [CRITICAL] Exposed secret: OpenAI API key
             Found in page source: sk-proj-...
  [HIGH]     Open CORS Policy
             Access-Control-Allow-Origin: * — arbitrary origins accepted
  [MEDIUM]   Missing Content-Security-Policy
```

---
