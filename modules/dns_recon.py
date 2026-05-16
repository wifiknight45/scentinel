"""
scentinel/modules/dns_recon.py
DNS Reconnaissance Module
"""

from __future__ import annotations
import dns.resolver
import dns.reversename
from colorama import Fore, Style


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]


def recon(target: str, record_types: list[str] | None = None) -> dict:
    """
    Enumerate DNS records for a domain.

    Args:
        target:       Domain name to query.
        record_types: List of DNS record types. Defaults to RECORD_TYPES.

    Returns:
        Dict mapping record type → list of string records.
    """
    if record_types is None:
        record_types = RECORD_TYPES

    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            records = []
            for rdata in answers:
                records.append(str(rdata).strip())
            if records:
                results[rtype] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.resolver.Timeout:
            results[rtype] = ["[timeout]"]
        except Exception as exc:
            results[rtype] = [f"[error: {exc}]"]

    return results


def reverse_lookup(ip: str) -> str | None:
    """
    Perform a reverse DNS lookup on an IP address.

    Args:
        ip: IPv4 or IPv6 address.

    Returns:
        Hostname string, or None on failure.
    """
    try:
        rev = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev, "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


def display(data: dict, target: str):
    """Pretty-print DNS recon results."""
    print(f"\n{Fore.CYAN}{'─'*50}")
    print(f"  DNS RECON  →  {target}")
    print(f"{'─'*50}{Style.RESET_ALL}")

    if not data:
        print(f"{Fore.YELLOW}  No DNS records found.{Style.RESET_ALL}\n")
        return

    for rtype, records in data.items():
        print(f"  {Fore.YELLOW}{rtype:<8}{Style.RESET_ALL}", end="")
        if records:
            print(records[0])
            for r in records[1:]:
                print(f"  {'':<8}{r}")
        else:
            print("(none)")

    print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}\n")
