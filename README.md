# scentinel
cybersec def toolkit

DISCLAIMER
──────────
Use Scentinel only against systems you own or have explicit
written permission to test. The author assumes no liability for misuse. 
For ethical usage only por favor. 
 
 
ABOUT
─────
Scentinel is a sweet modular defensive cybersecurity
reconnaissance toolkit written in Python 3.10+. Designed for
authorised security assessments, penetration test recon phases,
and general network/web hygiene audits. Every module is fully
self-contained and can be used standalone or as a library.
 
 
FEATURES
────────
  1. Multithreaded Port Scanner
       Concurrent TCP connect scan across common or custom ports.
       Automatically identifies well-known services by port number.
 
  2. WHOIS Lookup
       Retrieves domain registration data: registrar, creation/
       expiry dates, name servers, organisation, and contact emails.
 
  3. DNS Reconnaissance
       Enumerates A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR
       records. Supports reverse IP lookups.
 
  4. SSL Certificate Inspection
       Validates TLS certificates, reports expiry countdown,
       cipher suite, protocol version, SANs, and flags weak
       configurations (old protocols, short key lengths).
 
  5. HTTP Header Analysis
       Fetches HTTP response headers and produces a 0-100 security
       score. Reports present/missing security headers alongside
       information-leaking headers.
 
  6. Security Header Fingerprinting
       Bundled within HTTP Header Analysis. Maps each security
       header (HSTS, CSP, X-Frame-Options, etc.) to a severity
       rating and explains its defensive purpose.
 
  7. Basic Vulnerability Fingerprinting
       Pattern-matches server banners and response bodies against
       a curated list of known-vulnerable software signatures.
       Reports severity and advisory hints — no exploitation.
 
  8. Subdomain Enumeration
       DNS brute-force using a built-in 80+ word wordlist.
       Resolves each candidate and reports live subdomains with
       their resolved IP addresses.
 
 
PROJECT STRUCTURE
─────────────────
  scentinel/
  ├── scentinel.py            ← Main CLI entry point (run this)
  ├── __init__.py             ← Package metadata & version
  ├── requirements.txt        ← Python dependencies
  ├── README.txt              ← This file
  └── modules/
      ├── __init__.py
      ├── port_scanner.py     ← Multithreaded port scanner
      ├── whois_lookup.py     ← WHOIS lookup
      ├── dns_recon.py        ← DNS reconnaissance
      ├── ssl_inspector.py    ← SSL/TLS certificate inspection
      ├── http_headers.py     ← HTTP header analysis & security fingerprinting
      ├── vuln_fingerprint.py ← Vulnerability fingerprinting
      └── subdomain_enum.py   ← Subdomain enumeration
 
 
REQUIREMENTS
────────────
  Python 3.10 or higher.
 
  Dependencies (see requirements.txt):
    python-whois    WHOIS lookups
    dnspython       DNS queries
    requests        HTTP requests
    colorama        Terminal colour output
    tabulate        Tabular output helpers
    cryptography    TLS certificate parsing
    urllib3         HTTP connection pooling
 
 
INSTALLATION
────────────
  1. Clone the repository:
       git clone https://github.com/wifiknight45/scentinel.git
       cd scentinel
 
  2. (Recommended) Create a virtual environment:
       python3 -m venv venv
       source venv/bin/activate        # Linux / macOS
       venv\Scripts\activate.bat       # Windows
 
  3. Install dependencies:
       pip install -r requirements.txt
 
  4. Make executable (Linux / macOS):
       chmod +x scentinel.py
 
 
USAGE
─────
  # Run directly from bash
  ./scentinel.py --target <host/domain/url> [OPTIONS]
 
  # Or via Python
  python3 scentinel.py --target <host/domain/url> [OPTIONS]
 
  Arguments:
    --target, -t    Target host, domain, or URL  [REQUIRED]
 
  Module flags (combine freely):
    --all, -a       Run all modules (default when no flag given)
    --ports         Port scanner
    --whois         WHOIS lookup
    --dns           DNS recon
    --ssl           SSL certificate inspection
    --headers       HTTP header analysis
    --vuln          Vulnerability fingerprinting
    --subdomains    Subdomain enumeration
 
  Tuning options:
    --port-list     Comma-separated ports  e.g. 22,80,443,8080
    --threads       Worker threads (default: 100)
    --timeout       Per-connection timeout seconds (default: 1.0)
    --ssl-port      TLS port to inspect (default: 443)
 
 
EXAMPLES
────────
  # Full scan
  ./scentinel.py --target example.com --all
 
  # Port scan — custom ports
  ./scentinel.py --target 192.168.1.1 --ports --port-list 22,80,443,3306
 
  # SSL + HTTP headers
  ./scentinel.py --target https://example.com --ssl --headers
 
  # Subdomain hunt with more threads
  ./scentinel.py --target example.com --subdomains --threads 75
 
  # DNS recon + WHOIS together
  ./scentinel.py --target example.com --dns --whois
 
 
USING MODULES AS A LIBRARY
───────────────────────────
  Each module exposes a primary function and a display() helper:
 
    from modules import port_scanner, ssl_inspector, dns_recon
 
    # Port scan
    open_ports = port_scanner.scan("example.com", threads=50)
    port_scanner.display(open_ports, "example.com")
 
    # SSL inspection
    cert = ssl_inspector.inspect("example.com")
    ssl_inspector.display(cert, "example.com")
 
    # DNS recon
    records = dns_recon.recon("example.com")
    dns_recon.display(records, "example.com")
 
  All functions return plain Python dicts/lists — easy to pipe
  into reports, CI checks, or custom tooling.
 
 
