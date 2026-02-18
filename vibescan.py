#!/usr/bin/env python3
"""
VibeScan — Detect AI-generated (vibe coded) web apps and scan for vulnerabilities.
Usage: python vibescan.py <url> [--scan] [--json] [--timeout N] [--no-detect]
"""

import argparse
import sys

import detector
import reporter
import scanner


def main():
    parser = argparse.ArgumentParser(
        prog="vibescan",
        description="Detect vibe-coded (AI-generated) web apps and scan for vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vibescan.py https://example.com
  python vibescan.py https://example.com --scan
  python vibescan.py http://172.21.3.109:5000 --scan --json
  python vibescan.py https://example.com --no-detect --scan
        """,
    )

    parser.add_argument("url", help="Target URL to analyze (include http:// or https://)")
    parser.add_argument("--scan", action="store_true",
                        help="Run vulnerability scan after detection")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON (suppresses banner and colors)")
    parser.add_argument("--timeout", type=int, default=10, metavar="N",
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-detect", action="store_true",
                        help="Skip vibe code detection, go straight to vuln scan")
    parser.add_argument("--auto-scan", action="store_true",
                        help="Automatically run vuln scan if vibe score > 50")

    args = parser.parse_args()

    # Normalize URL
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    if not args.json:
        reporter.print_banner()

    detection_result = {
        "url": url,
        "score": 0,
        "signals": [],
        "verdict": "Detection skipped",
        "error": None,
    }
    findings = None

    # --- Detection phase ---
    if not args.no_detect:
        if not args.json:
            print(f"  Analyzing: {url}\n")

        detection_result = detector.detect(url, timeout=args.timeout)

        if detection_result.get("error"):
            if args.json:
                print(f'{{"error": "{detection_result["error"]}"}}')
            else:
                reporter.print_error(detection_result["error"])
            sys.exit(1)

        if not args.json:
            reporter.print_detection(detection_result)

        # Auto-scan trigger
        if args.auto_scan and detection_result["score"] > 50:
            args.scan = True
            if not args.json:
                print(f"\n  [auto-scan] Score > 50 — triggering vulnerability scan...")

    # --- Scan phase ---
    if args.scan or args.no_detect:
        if not args.json:
            print(f"\n  Running vulnerability scan on {url} ...")

        findings = scanner.scan(url, timeout=args.timeout)

        if not args.json:
            reporter.print_scan(findings)

    # --- Output ---
    if args.json:
        reporter.output_json(detection_result, findings if findings is not None else [])
    else:
        reporter.print_summary(detection_result, findings)


if __name__ == "__main__":
    main()
