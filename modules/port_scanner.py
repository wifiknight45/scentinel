"""
scentinel/modules/port_scanner.py
Multithreaded Port Scanner Module
"""

import socket
import threading
from queue import Queue
from colorama import Fore, Style


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _scan_port(host: str, port: int, timeout: float, results: list, lock: threading.Lock):
    """Attempt to connect to a single port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = COMMON_PORTS.get(port, "Unknown")
            with lock:
                results.append({"port": port, "state": "open", "service": service})
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass


def scan(host: str, ports: list[int] | None = None, threads: int = 100, timeout: float = 1.0) -> list[dict]:
    """
    Scan a host for open ports using a multithreaded approach.

    Args:
        host:    Target hostname or IP address.
        ports:   List of ports to scan. Defaults to common ports.
        threads: Number of concurrent worker threads.
        timeout: Per-port connection timeout in seconds.

    Returns:
        Sorted list of dicts with keys: port, state, service.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys()) + list(range(1, 1025))
        ports = sorted(set(ports))

    results: list[dict] = []
    lock = threading.Lock()
    queue: Queue = Queue()

    for port in ports:
        queue.put(port)

    def worker():
        while not queue.empty():
            try:
                port = queue.get_nowait()
            except Exception:
                break
            _scan_port(host, port, timeout, results, lock)
            queue.task_done()

    thread_pool = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_pool.append(t)

    for t in thread_pool:
        t.join()

    return sorted(results, key=lambda x: x["port"])


def display(results: list[dict], host: str):
    """Pretty-print scan results to stdout."""
    print(f"\n{Fore.CYAN}{'─'*50}")
    print(f"  PORT SCAN RESULTS  →  {host}")
    print(f"{'─'*50}{Style.RESET_ALL}")

    if not results:
        print(f"{Fore.YELLOW}  No open ports found.{Style.RESET_ALL}")
        return

    print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE'}")
    print(f"  {'─'*6:<8} {'─'*5:<10} {'─'*12}")
    for r in results:
        print(
            f"  {Fore.GREEN}{r['port']:<8}{Style.RESET_ALL}"
            f"{Fore.GREEN}{'open':<10}{Style.RESET_ALL}"
            f"{r['service']}"
        )
    print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}\n")
