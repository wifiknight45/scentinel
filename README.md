![version](https://img.shields.io/badge/version-1.0.0-7F77DD?style=for-the-badge&logo=python&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-1D9E75?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![python](https://img.shields.io/badge/python-3.10+-378ADD?style=for-the-badge&logo=python&logoColor=white)
![purpose](https://img.shields.io/badge/purpose-defensive%20security-D85A30?style=for-the-badge&logo=shield&logoColor=white)
![modules](https://img.shields.io/badge/modules-7-D4537E?style=for-the-badge&logo=files&logoColor=white)
![ethical use](https://img.shields.io/badge/use-ethical%20only-BA7517?style=for-the-badge&logo=checkmarx&logoColor=white)

# scentinel
cybersec def toolkit

### disclaimer 
Use Scentinel only against systems you own or have explicit
written permission to test. The author assumes no liability for misuse. 
For ethical usage; do no harm. 
 
 ## dope features 
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
 
 
### project structure (may not adhere to this) caveat emptor
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
 
 
## reqs

  Python 3.10 or higher.
 
  Dependencies (see requirements.txt):
    python-whois    WHOIS lookups
    dnspython       DNS queries
    requests        HTTP requests
    colorama        Terminal colour output
    tabulate        Tabular output helpers
    cryptography    TLS certificate parsing
    urllib3         HTTP connection pooling
 
 
## installation guide

  1. Clone the repository:
       git clone https://github.com/wifiknight45/scentinel.git
       cd scentinel
 
  2. Create a virtual environment (all the cool kids do):
       python3 -m venv venv
       source venv/bin/activate        # Linux / macOS
       venv\Scripts\activate.bat       # Windows
 
  3. Install dependencies:
       pip install -r requirements.txt
 
  4. Make executable (Linux / macOS):
       chmod +x scentinel.py
 
 
## usage 

  # Run directly from bash
  ./scentinel.py --target <host/domain/url>
 
  # Or via Python
  python3 scentinel.py --target <host/domain/url> 
 
  Arguments:
    --target, -t    Target host, domain, or URL  
 
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
 
 ## examples 
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
 
 
 
