"""
Scentinel — Modular Defensive Cybersecurity Toolkit
=====================================================
A sweet modular defensive cybersec toolkit.

Modules:
    port_scanner    — Multithreaded TCP port scanner
    whois_lookup    — WHOIS domain lookup
    dns_recon       — DNS record enumeration
    ssl_inspector   — SSL/TLS certificate inspection
    http_headers    — HTTP header analysis & security fingerprinting
    vuln_fingerprint — Signature-based vulnerability fingerprinting
    subdomain_enum  — DNS brute-force subdomain enumeration

Usage:
    ./scentinel.py --target example.com --all

GitHub: https://github.com/wifiknight45/scentinel
"""

__version__   = "1.0.0"
__author__    = "wifiknight45"
__github__    = "https://github.com/wifiknight45/scentinel"
__license__   = "MIT"
__all__       = [
    "port_scanner",
    "whois_lookup",
    "dns_recon",
    "ssl_inspector",
    "http_headers",
    "vuln_fingerprint",
    "subdomain_enum",
]
