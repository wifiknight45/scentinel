"""
scentinel/modules/whois_lookup.py
WHOIS Lookup Module
"""

from __future__ import annotations
import whois
from colorama import Fore, Style


def lookup(target: str) -> dict:
    """
    Perform a WHOIS lookup for a domain.

    Args:
        target: Domain name (e.g. "example.com").

    Returns:
        Dictionary of WHOIS fields. Empty dict on failure.
    """
    try:
        w = whois.whois(target)
        return {
            "domain_name":     _normalize(w.domain_name),
            "registrar":       _normalize(w.registrar),
            "creation_date":   _normalize(w.creation_date),
            "expiration_date": _normalize(w.expiration_date),
            "updated_date":    _normalize(w.updated_date),
            "name_servers":    _normalize(w.name_servers),
            "status":          _normalize(w.status),
            "emails":          _normalize(w.emails),
            "org":             _normalize(w.org),
            "country":         _normalize(w.country),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _normalize(value) -> str | list | None:
    """Flatten lists/tuples and stringify dates."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        seen = []
        for v in value:
            s = str(v).strip()
            if s not in seen:
                seen.append(s)
        return seen if len(seen) > 1 else (seen[0] if seen else None)
    return str(value).strip()


def display(data: dict, target: str):
    """Pretty-print WHOIS results."""
    print(f"\n{Fore.CYAN}{'─'*50}")
    print(f"  WHOIS RESULTS  →  {target}")
    print(f"{'─'*50}{Style.RESET_ALL}")

    if "error" in data:
        print(f"{Fore.RED}  Error: {data['error']}{Style.RESET_ALL}\n")
        return

    labels = {
        "domain_name":     "Domain Name",
        "registrar":       "Registrar",
        "creation_date":   "Created",
        "expiration_date": "Expires",
        "updated_date":    "Updated",
        "name_servers":    "Name Servers",
        "status":          "Status",
        "emails":          "Emails",
        "org":             "Organisation",
        "country":         "Country",
    }

    for key, label in labels.items():
        value = data.get(key)
        if not value:
            continue
        if isinstance(value, list):
            print(f"  {Fore.YELLOW}{label:<18}{Style.RESET_ALL}{value[0]}")
            for v in value[1:]:
                print(f"  {'':<18}{v}")
        else:
            print(f"  {Fore.YELLOW}{label:<18}{Style.RESET_ALL}{value}")

    print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}\n")
