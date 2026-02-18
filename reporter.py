import json
from colorama import Fore, Style, init

init(autoreset=True)

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

BANNER = f"""{Fore.CYAN + Style.BRIGHT}
 ██╗   ██╗██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ██║██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}{Fore.WHITE}  Detect AI-generated (vibe coded) apps and scan for vulns
  github.com/r1ckt0r/vibescan{Style.RESET_ALL}
"""


def _score_color(score: int) -> str:
    if score <= 20:
        return Fore.GREEN + Style.BRIGHT
    elif score <= 50:
        return Fore.YELLOW
    elif score <= 75:
        return Fore.RED
    else:
        return Fore.RED + Style.BRIGHT


def print_banner():
    print(BANNER)


def print_detection(result: dict):
    score = result["score"]
    verdict = result["verdict"]
    signals = result["signals"]
    color = _score_color(score)

    print(f"\n{Fore.CYAN + Style.BRIGHT}{'─' * 60}")
    print(f"  🔍  VIBE CODE DETECTION")
    print(f"{'─' * 60}{Style.RESET_ALL}")
    print(f"  Target  : {Fore.WHITE}{result['url']}{Style.RESET_ALL}")
    print(f"  Score   : {color}{score}/100{Style.RESET_ALL}")
    print(f"  Verdict : {color}{verdict}{Style.RESET_ALL}")

    if signals:
        print(f"\n  {Fore.CYAN}Signals detected:{Style.RESET_ALL}")
        for sig in signals:
            pts_str = f"+{sig['points']}"
            print(f"    {Fore.YELLOW}[{pts_str:>4}]{Style.RESET_ALL}  {sig['label']}")
    else:
        print(f"\n  {Fore.GREEN}No vibe code signals detected.{Style.RESET_ALL}")


def print_scan(findings: list):
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'─' * 60}")
    print(f"  🛡️   VULNERABILITY SCAN RESULTS")
    print(f"{'─' * 60}{Style.RESET_ALL}")

    if not findings:
        print(f"  {Fore.GREEN}✓ No vulnerabilities found.{Style.RESET_ALL}")
        return

    # Sort by severity
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    sorted_findings = sorted(findings, key=lambda f: order.get(f["severity"], 99))

    counts = {}
    for f in sorted_findings:
        sev = f["severity"]
        color = SEVERITY_COLORS.get(sev, Fore.WHITE)
        counts[sev] = counts.get(sev, 0) + 1
        print(f"\n  {color}[{sev}]{Style.RESET_ALL} {f['title']}")
        if f.get("detail"):
            print(f"         {Fore.WHITE}{f['detail']}{Style.RESET_ALL}")

    # Summary bar
    print(f"\n  {Fore.CYAN}Summary:{Style.RESET_ALL}", end="  ")
    for sev in SEVERITY_ORDER:
        if sev in counts:
            color = SEVERITY_COLORS.get(sev, Fore.WHITE)
            print(f"{color}{sev}: {counts[sev]}{Style.RESET_ALL}  ", end="")
    print()


def print_summary(detection: dict, findings: list):
    score = detection["score"]
    total_vulns = len(findings)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")

    print(f"\n{Fore.CYAN + Style.BRIGHT}{'─' * 60}")
    print(f"  📋  SUMMARY")
    print(f"{'─' * 60}{Style.RESET_ALL}")
    print(f"  Vibe Score    : {_score_color(score)}{score}/100 — {detection['verdict']}{Style.RESET_ALL}")
    if findings is not None:
        print(f"  Vulns Found   : {Fore.WHITE}{total_vulns}{Style.RESET_ALL}  "
              f"({Fore.RED + Style.BRIGHT}{critical} CRITICAL{Style.RESET_ALL}, "
              f"{Fore.RED}{high} HIGH{Style.RESET_ALL})")
    print(f"{Fore.CYAN + Style.BRIGHT}{'─' * 60}{Style.RESET_ALL}\n")


def print_error(msg: str):
    print(f"\n  {Fore.RED + Style.BRIGHT}[ERROR]{Style.RESET_ALL} {msg}\n")


def output_json(detection: dict, findings: list):
    data = {
        "detection": {
            "url": detection["url"],
            "score": detection["score"],
            "verdict": detection["verdict"],
            "signals": detection["signals"],
        },
        "vulnerabilities": findings or [],
    }
    print(json.dumps(data, indent=2))
