#!/usr/bin/env python3
"""
Debug script: fetch innovagetech and show what JS chunks we get + search for text patterns.
Run: python3 debug_fetch.py
"""
import re
import requests
from urllib.parse import urljoin

URL = "https://learning-curve.tech/"
HEADERS = {"User-Agent": "Mozilla/5.0 (VibeScan/1.0)"}

print("[1] Fetching main page...")
r = requests.get(URL, headers=HEADERS, timeout=10)
html = r.text
print(f"    Status: {r.status_code}, Content-Type: {r.headers.get('content-type')}")
print(f"    HTML length: {len(html)} chars")

# Show first 2000 chars of HTML
print("\n[2] First 1000 chars of HTML:")
print(html[:1000])

# Find all script tags
script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
print(f"\n[3] Found {len(script_srcs)} script src tags:")
for s in script_srcs:
    print(f"    {s}")

# Fetch each JS file and show size + first 500 chars
print("\n[4] Fetching JS chunks...")
base = "https://innovagetech.vercel.app"
all_js = ""
for src in script_srcs[:8]:
    js_url = src if src.startswith("http") else urljoin(base, src)
    try:
        jr = requests.get(js_url, headers=HEADERS, timeout=8)
        ct = jr.headers.get("content-type", "")
        print(f"\n  URL: {js_url}")
        print(f"  Status: {jr.status_code}, Content-Type: {ct}, Size: {len(jr.text)} chars")
        # Show a snippet that might contain readable text
        # Look for quoted strings longer than 20 chars
        strings = re.findall(r'"([^"]{20,})"', jr.text)
        readable = [s for s in strings if re.search(r'[a-zA-Z ]{10,}', s)][:5]
        if readable:
            print(f"  Sample readable strings:")
            for s in readable:
                print(f"    > {s[:120]}")
        all_js += jr.text
    except Exception as e:
        print(f"  ERROR: {e}")

# Now search for our patterns in all_js
print("\n[5] Searching for AI writing patterns in combined JS...")
AI_PATTERNS = [
    r'seamless',
    r'cutting.edge',
    r'innovative',
    r'leverage',
    r'empower',
    r'transform',
    r'unlock',
    r'streamlin',
    r'forefront',
    r'digital',
    r'foster',
    r'harness',
]
for p in AI_PATTERNS:
    m = re.search(p, all_js, re.IGNORECASE)
    if m:
        # Show surrounding context
        start = max(0, m.start() - 40)
        end = min(len(all_js), m.end() + 80)
        print(f"  FOUND '{p}': ...{all_js[start:end]}...")
    else:
        print(f"  NOT FOUND: '{p}'")

print("\n[6] Checking for inline JSON data (Next.js __NEXT_DATA__)...")
next_data = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL)
if next_data:
    print(f"  Found __NEXT_DATA__ ({len(next_data.group(1))} chars):")
    print(f"  {next_data.group(1)[:500]}")
else:
    print("  No __NEXT_DATA__ found (likely App Router, not Pages Router)")

print("\n[7] Checking for inline script content in HTML...")
inline_scripts = re.findall(r'<script(?![^>]*src)[^>]*>(.*?)</script>', html, re.DOTALL)
print(f"  Found {len(inline_scripts)} inline scripts")
for i, s in enumerate(inline_scripts[:3]):
    print(f"  Script {i+1} ({len(s)} chars): {s[:200]}")
