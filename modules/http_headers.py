"""
scentinel/modules/http_headers.py
HTTP Header Analysis & Security Header Fingerprinting Module
"""

from __future__ import annotations
import requests
from colorama import Fore, Style


# Security headers and their impact
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
    },
    "Content-Security-Policy": {
        "description": "Mitigates XSS and data injection attacks",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature permissions",
        "severity": "LOW",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (superseded by CSP)",
        "severity": "LOW",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Prevents cross-origin resource loading",
        "severity": "MEDIUM",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context",
        "severity": "MEDIUM",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Restricts cross-origin resource reads",
        "severity": "MEDIUM",
    },
}

# Headers that may leak server information
INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
    "X-Runtime",
    "X-Version",
]


def analyze(url: str, timeout: float = 8.0, follow_redirects: bool = True) -> dict:
    """
    Fetch HTTP headers from a URL and analyse them.

    Args:
        url:              Full URL (e.g. "https://example.com").
        timeout:          Request timeout in seconds.
        follow_redirects: Whether to follow HTTP redirects.

    Returns:
        Dict with keys: status_code, url, raw_headers, security_headers,
        missing_headers, info_leaks, redirect_chain, score.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            headers={"User-Agent": "Scentinel/1.0 Security Scanner"},
            verify=True,
        )
    except requests.exceptions.SSLError:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            headers={"User-Agent": "Scentinel/1.0 Security Scanner"},
            verify=False,
        )
    except Exception as exc:
        return {"error": str(exc)}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    raw_headers   = dict(resp.headers)

    # Evaluate security headers
    present = {}
    missing = []
    for header, meta in SECURITY_HEADERS.items():
        val = headers_lower.get(header.lower())
        if val:
            present[header] = {"value": val, **meta}
        else:
            missing.append({**meta, "header": header})

    # Detect information leakage
    leaks = {}
    for header in INFO_LEAK_HEADERS:
        val = headers_lower.get(header.lower())
        if val:
            leaks[header] = val

    # Simple security score (0-100)
    high_present   = sum(1 for h in present.values() if h["severity"] == "HIGH")
    medium_present = sum(1 for h in present.values() if h["severity"] == "MEDIUM")
    score = min(100, (high_present * 25) + (medium_present * 10) + (len(present) * 3))

    # Redirect chain
    chain = [r.url for r in resp.history] + [resp.url]

    return {
        "status_code":      resp.status_code,
        "final_url":        resp.url,
        "raw_headers":      raw_headers,
        "security_headers": present,
        "missing_headers":  missing,
        "info_leaks":       leaks,
        "redirect_chain":   chain,
        "score":            score,
    }


def display(data: dict, url: str):
    """Pretty-print HTTP header analysis results."""
    print(f"\n{Fore.CYAN}{'─'*60}")
    print(f"  HTTP HEADER ANALYSIS  →  {url}")
    print(f"{'─'*60}{Style.RESET_ALL}")

    if "error" in data:
        print(f"{Fore.RED}  Error: {data['error']}{Style.RESET_ALL}\n")
        return

    status_color = Fore.GREEN if 200 <= data["status_code"] < 300 else Fore.YELLOW
    print(f"  {Fore.YELLOW}Status Code    {Style.RESET_ALL}{status_color}{data['status_code']}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Final URL      {Style.RESET_ALL}{data['final_url']}")

    # Score bar
    score = data["score"]
    bar_filled = int(score / 5)
    bar = f"{'█' * bar_filled}{'░' * (20 - bar_filled)}"
    score_color = Fore.GREEN if score >= 60 else (Fore.YELLOW if score >= 30 else Fore.RED)
    print(f"  {Fore.YELLOW}Security Score {Style.RESET_ALL}{score_color}{bar} {score}/100{Style.RESET_ALL}")

    # Redirect chain
    if len(data["redirect_chain"]) > 1:
        print(f"\n  {Fore.YELLOW}Redirect Chain:{Style.RESET_ALL}")
        for i, r in enumerate(data["redirect_chain"]):
            arrow = "  →" if i > 0 else "   "
            print(f"  {arrow} {r}")

    # Present security headers
    print(f"\n  {Fore.GREEN}✔  Security Headers Present ({len(data['security_headers'])}){Style.RESET_ALL}")
    for header, meta in data["security_headers"].items():
        sev_color = Fore.RED if meta["severity"] == "HIGH" else (
            Fore.YELLOW if meta["severity"] == "MEDIUM" else Fore.WHITE)
        print(f"     {Fore.GREEN}{header}{Style.RESET_ALL}")
        print(f"       Value    : {meta['value'][:80]}")
        print(f"       Severity : {sev_color}{meta['severity']}{Style.RESET_ALL}")

    # Missing security headers
    if data["missing_headers"]:
        print(f"\n  {Fore.RED}✘  Missing Security Headers ({len(data['missing_headers'])}){Style.RESET_ALL}")
        for item in data["missing_headers"]:
            sev_color = Fore.RED if item["severity"] == "HIGH" else (
                Fore.YELLOW if item["severity"] == "MEDIUM" else Fore.WHITE)
            print(f"     {Fore.RED}{item['header']}{Style.RESET_ALL}  [{sev_color}{item['severity']}{Style.RESET_ALL}]")
            print(f"       {item['description']}")

    # Information leaks
    if data["info_leaks"]:
        print(f"\n  {Fore.YELLOW}⚠  Information Leaking Headers{Style.RESET_ALL}")
        for header, value in data["info_leaks"].items():
            print(f"     {Fore.YELLOW}{header}{Style.RESET_ALL}: {value}")

    print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}\n")
