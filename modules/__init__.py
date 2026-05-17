"""
Scentinel — modules package
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Exposes each scanning/analysis module so the main entry point
(scentinel.py) can import them cleanly:

    from modules import port_scanner, whois_lookup, ...

Submodules
----------
port_scanner    — Multithreaded TCP connect scanner
whois_lookup    — Domain WHOIS retrieval
dns_recon       — DNS record enumeration & reverse lookups
ssl_inspector   — TLS certificate validation & cipher analysis
http_headers    — HTTP header fetching, scoring & fingerprinting
vuln_fingerprint— Banner / body pattern matching for known CVEs
subdomain_enum  — DNS brute-force subdomain discovery
"""

# All seven scanning modules.  Adding a name here makes it show up
# in tab-completion and `from modules import *` if you ever use that.
__all__ = [
    "port_scanner",
    "whois_lookup",
    "dns_recon",
    "ssl_inspector",
    "http_headers",
    "vuln_fingerprint",
    "subdomain_enum",
]

# Re-export the package version so callers can do:
#   from modules import __version__
# without touching the top-level __init__.py.
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("scentinel")
except PackageNotFoundError:          # running straight from source tree
    __version__ = "1.0.0"
