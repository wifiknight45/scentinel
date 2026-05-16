"""
scentinel/modules/ssl_inspector.py
SSL/TLS Certificate Inspection Module
"""

from __future__ import annotations
import ssl
import socket
from datetime import datetime, timezone
from colorama import Fore, Style


def inspect(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Retrieve and parse the SSL/TLS certificate for a host.

    Args:
        host:    Hostname to inspect.
        port:    Port with TLS (default 443).
        timeout: Connection timeout in seconds.

    Returns:
        Dict of certificate fields plus meta (valid, days_remaining, warnings).
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_name, _, bits = ssock.cipher()

        subject    = dict(x[0] for x in cert.get("subject", []))
        issuer     = dict(x[0] for x in cert.get("issuer", []))
        san        = [v for _, v in cert.get("subjectAltName", [])]
        not_before = _parse_cert_date(cert.get("notBefore", ""))
        not_after  = _parse_cert_date(cert.get("notAfter", ""))
        now        = datetime.now(timezone.utc)
        days_left  = (not_after - now).days if not_after else None

        warnings = []
        if days_left is not None and days_left < 30:
            warnings.append(f"Certificate expires in {days_left} days!")
        if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            warnings.append(f"Weak protocol in use: {protocol}")
        if bits and int(bits) < 2048:
            warnings.append(f"Weak key size: {bits} bits")

        return {
            "subject_cn":     subject.get("commonName"),
            "subject_org":    subject.get("organizationName"),
            "issuer_cn":      issuer.get("commonName"),
            "issuer_org":     issuer.get("organizationName"),
            "san":            san,
            "not_before":     str(not_before.date()) if not_before else None,
            "not_after":      str(not_after.date()) if not_after else None,
            "days_remaining": days_left,
            "protocol":       protocol,
            "cipher":         cipher_name,
            "key_bits":       bits,
            "serial_number":  cert.get("serialNumber"),
            "valid":          days_left is not None and days_left > 0,
            "warnings":       warnings,
        }

    except ssl.SSLCertVerificationError as exc:
        return {"error": f"Certificate verification failed: {exc}", "valid": False}
    except ssl.SSLError as exc:
        return {"error": f"SSL error: {exc}", "valid": False}
    except Exception as exc:
        return {"error": str(exc), "valid": False}


def _parse_cert_date(date_str: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def display(data: dict, host: str):
    """Pretty-print SSL inspection results."""
    print(f"\n{Fore.CYAN}{'─'*50}")
    print(f"  SSL CERTIFICATE  →  {host}")
    print(f"{'─'*50}{Style.RESET_ALL}")

    if "error" in data:
        print(f"{Fore.RED}  Error: {data['error']}{Style.RESET_ALL}\n")
        return

    valid_color = Fore.GREEN if data.get("valid") else Fore.RED
    days = data.get("days_remaining")
    days_color = Fore.GREEN if (days and days > 30) else Fore.YELLOW

    fields = [
        ("Subject CN",  data.get("subject_cn")),
        ("Subject Org", data.get("subject_org")),
        ("Issuer CN",   data.get("issuer_cn")),
        ("Issuer Org",  data.get("issuer_org")),
        ("Valid From",  data.get("not_before")),
        ("Valid Until", data.get("not_after")),
        ("Days Left",   f"{days_color}{days}{Style.RESET_ALL}" if days is not None else None),
        ("Protocol",    data.get("protocol")),
        ("Cipher",      data.get("cipher")),
        ("Key Bits",    data.get("key_bits")),
        ("Serial",      data.get("serial_number")),
        ("Valid",       f"{valid_color}{'Yes' if data.get('valid') else 'No'}{Style.RESET_ALL}"),
    ]

    for label, value in fields:
        if value is not None:
            print(f"  {Fore.YELLOW}{label:<14}{Style.RESET_ALL}{value}")

    san = data.get("san", [])
    if san:
        print(f"  {Fore.YELLOW}{'SANs':<14}{Style.RESET_ALL}{san[0]}")
        for s in san[1:6]:
            print(f"  {'':<14}{s}")
        if len(san) > 6:
            print(f"  {'':<14}... and {len(san)-6} more")

    for w in data.get("warnings", []):
        print(f"  {Fore.RED}⚠  {w}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}\n")
