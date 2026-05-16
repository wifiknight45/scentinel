#!/usr/bin/env python3
"""
███████╗ ██████╗███████╗███╗  ██╗████████╗██╗███╗  ██╗███████╗██╗
██╔════╝██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║
███████╗██║     █████╗  ██╔██╗██║   ██║   ██║██╔██╗██║█████╗  ██║
╚════██║██║     ██╔══╝  ██║╚████║   ██║   ██║██║╚████║██╔══╝  ██║
███████║╚██████╗███████╗██║ ╚███║   ██║   ██║██║ ╚███║███████╗███████╗
╚══════╝ ╚═════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝

Scentinel — Modular Defensive Cybersecurity Toolkit
Version : 1.0.0
Author  : wifiknight45 (https://github.com/wifiknight45)
License : MIT

Usage:
    python scentinel.py --target <host/domain/url> [OPTIONS]

Run --help for full usage.
"""

import argparse
import sys
import time
from colorama import Fore, Style, init as colorama_init

from modules import (
    port_scanner,
    whois_lookup,
    dns_recon,
    ssl_inspector,
    http_headers,
    vuln_fingerprint,
    subdomain_enum,
)

colorama_init(autoreset=True)


BANNER = f"""{Fore.CYAN}
  ███████╗ ██████╗███████╗███╗  ██╗████████╗██╗███╗  ██╗███████╗██╗
  ██╔════╝██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║
  ███████╗██║     █████╗  ██╔██╗██║   ██║   ██║██╔██╗██║█████╗  ██║
  ╚════██║██║     ██╔══╝  ██║╚████║   ██║   ██║██║╚████║██╔══╝  ██║
  ███████║╚██████╗███████╗██║ ╚███║   ██║   ██║██║ ╚███║███████╗███████╗
  ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝
{Style.RESET_ALL}
  {Fore.WHITE}Modular Defensive Cybersecurity Toolkit  v1.0.0{Style.RESET_ALL}
  {Fore.YELLOW}github.com/wifiknight45  |  Authorised use only.{Style.RESET_ALL}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scentinel",
        description="Scentinel — Modular Defensive Cybersecurity Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full scan:
    python scentinel.py --target example.com --all

  Port scan only:
    python scentinel.py --target example.com --ports

  Custom port range:
    python scentinel.py --target example.com --ports --port-list 22,80,443,8080

  SSL + HTTP headers:
    python scentinel.py --target example.com --ssl --headers

  Subdomain enumeration:
    python scentinel.py --target example.com --subdomains
        """,
    )

    parser.add_argument("--target", "-t", required=True,
                        help="Target host, domain, or URL")

    # Module toggles
    parser.add_argument("--all", "-a", action="store_true",
                        help="Run all modules")
    parser.add_argument("--ports", action="store_true",
                        help="Run port scanner")
    parser.add_argument("--whois", action="store_true",
                        help="Run WHOIS lookup")
    parser.add_argument("--dns", action="store_true",
                        help="Run DNS recon")
    parser.add_argument("--ssl", action="store_true",
                        help="Inspect SSL/TLS certificate")
    parser.add_argument("--headers", action="store_true",
                        help="Analyse HTTP headers")
    parser.add_argument("--vuln", action="store_true",
                        help="Run vulnerability fingerprinting")
    parser.add_argument("--subdomains", action="store_true",
                        help="Enumerate subdomains")

    # Port scanner options
    parser.add_argument("--port-list", default=None,
                        help="Comma-separated list of ports to scan (e.g. 22,80,443)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Thread count for port scanner / subdomain enum (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-connection timeout in seconds (default: 1.0)")

    # SSL options
    parser.add_argument("--ssl-port", type=int, default=443,
                        help="Port to use for SSL inspection (default: 443)")

    return parser


def clean_host(target: str) -> str:
    """Strip protocol and path, return bare hostname."""
    host = target.replace("https://", "").replace("http://", "")
    return host.split("/")[0].split(":")[0]


def clean_url(target: str) -> str:
    """Ensure target has an HTTP/S scheme."""
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def section(title: str):
    """Print a section divider."""
    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"  ▶  {title.upper()}")
    print(f"{'═'*60}{Style.RESET_ALL}")


def run_port_scanner(host: str, args):
    section("Port Scanner")
    ports = None
    if args.port_list:
        try:
            ports = [int(p.strip()) for p in args.port_list.split(",")]
        except ValueError:
            print(f"{Fore.RED}  Invalid --port-list value. Use comma-separated integers.{Style.RESET_ALL}")
            return
    t0 = time.perf_counter()
    results = port_scanner.scan(host, ports=ports, threads=args.threads, timeout=args.timeout)
    elapsed = time.perf_counter() - t0
    port_scanner.display(results, host)
    print(f"  {Fore.WHITE}Scan completed in {elapsed:.2f}s{Style.RESET_ALL}")


def run_whois(host: str, _args):
    section("WHOIS Lookup")
    data = whois_lookup.lookup(host)
    whois_lookup.display(data, host)


def run_dns(host: str, _args):
    section("DNS Reconnaissance")
    data = dns_recon.recon(host)
    dns_recon.display(data, host)


def run_ssl(host: str, args):
    section("SSL Certificate Inspection")
    data = ssl_inspector.inspect(host, port=args.ssl_port, timeout=args.timeout * 5)
    ssl_inspector.display(data, host)


def run_headers(target: str, _args):
    section("HTTP Header Analysis")
    url = clean_url(target)
    data = http_headers.analyze(url)
    http_headers.display(data, url)


def run_vuln(target: str, _args):
    section("Vulnerability Fingerprinting")
    url = clean_url(target)
    data = vuln_fingerprint.fingerprint(url)
    vuln_fingerprint.display(data, url)


def run_subdomains(host: str, args):
    section("Subdomain Enumeration")
    results = subdomain_enum.enumerate_subdomains(host, threads=args.threads, timeout=args.timeout * 2)
    subdomain_enum.display(results, host)


def main():
    print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    target = args.target.strip()
    host   = clean_host(target)

    run_all = args.all or not any([
        args.ports, args.whois, args.dns, args.ssl,
        args.headers, args.vuln, args.subdomains,
    ])

    print(f"  {Fore.CYAN}Target  : {Fore.WHITE}{target}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Host    : {Fore.WHITE}{host}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Started : {Fore.WHITE}{time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    global_start = time.perf_counter()

    tasks = [
        (args.whois     or run_all, run_whois,      host,   args),
        (args.dns       or run_all, run_dns,         host,   args),
        (args.ssl       or run_all, run_ssl,         host,   args),
        (args.ports     or run_all, run_port_scanner,host,   args),
        (args.headers   or run_all, run_headers,     target, args),
        (args.vuln      or run_all, run_vuln,        target, args),
        (args.subdomains or run_all,run_subdomains,  host,   args),
    ]

    for enabled, fn, t, a in tasks:
        if enabled:
            try:
                fn(t, a)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}  Interrupted by user.{Style.RESET_ALL}")
                sys.exit(0)
            except Exception as exc:
                print(f"{Fore.RED}  Module error: {exc}{Style.RESET_ALL}")

    elapsed = time.perf_counter() - global_start
    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  Scentinel completed in {elapsed:.2f}s")
    print(f"{'═'*60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
