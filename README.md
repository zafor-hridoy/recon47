# 🔱 Recon47

**Automated Reconnaissance & Vulnerability Scanner**

> **Tool Name:** Recon47  
> **Author:** Xaff  
> **Version:** 1.0.0  
> **Language:** Python 3.10+  
> **Type:** CLI-based Automated Reconnaissance & Vulnerability Scanner

Recon47 is a **production-ready, modular, CLI-based** tool that automates the entire reconnaissance and vulnerability scanning workflow for web targets. It accepts a domain, subdomain, URL, or IP address and performs a comprehensive security assessment — from passive/active reconnaissance to vulnerability scanning — then generates a **stunning hacker-themed HTML report** with PDF download capability.

> 📄 **Full Product Requirements Document:** See [`recon47_prd.md`](recon47_prd.md) for the complete PRD with architecture diagrams, module specifications, and design decisions.

---

## 📸 Sample Output

### Console Output
```
╔═════════════════════════════════ 🔱 RECON47 COMPLETE ════════════════════════════╗
║                                                                                  ║
║  ✓ Scan completed successfully!                                                  ║
║  Duration: 61.6s                                                                 ║
║  Report:   recon47_output/report.html                                            ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

### HTML Report Features
- 🎨 Dark "Cyber Matrix" hacker theme with animated scanline
- 📊 Interactive dashboard with severity donut chart  
- 📂 Collapsible/expandable sections for all findings
- 🔴 Color-coded severity badges (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- 📥 **Download PDF** button (one-click print-to-PDF)
- 📱 Responsive design for all screen sizes

---

## ✨ Features

### 🔍 Reconnaissance Modules
| Module | Technique | Description |
|--------|-----------|-------------|
| **Subdomain Enumeration** | crt.sh, HackerTarget, RapidDNS + DNS brute-force | Multi-source passive + active subdomain discovery |
| **Port Scanner** | Multi-threaded TCP connect scan | Top 100 ports with service detection & banner grabbing |
| **Technology Detection** | HTTP headers, meta tags, body analysis | Wappalyzer-style fingerprinting for 30+ technologies |
| **Header Security Audit** | Security header analysis | 8 security headers checked + cookie analysis + info disclosure |
| **DNS Reconnaissance** | Full DNS record enumeration | A, AAAA, CNAME, MX, NS, TXT, SOA, PTR records |
| **WHOIS Lookup** | Domain registration data | Registrar, creation/expiry dates, nameservers, org info |

### 🕷️ Crawling & Discovery Modules
| Module | Technique | Description |
|--------|-----------|-------------|
| **Web Crawler** | Recursive BFS with depth control | Smart deduplication, JS file extraction, form discovery |
| **Directory Bruteforce** | Wordlist-based path discovery | 80+ common paths with status code filtering |
| **JavaScript Analyzer** | Regex pattern matching | Extract API keys, secrets, endpoints from JS files |
| **Parameter Extractor** | URL + form field mining | Deduplicates params from crawled URLs and form inputs |

### ⚡ Vulnerability Scanner Modules
| Module | Technique | Description |
|--------|-----------|-------------|
| **Custom Security Checks** | 9 built-in checks | CORS, clickjacking, XSS reflection, SQL error detection, open redirect, sensitive files, HTTP methods, info disclosure, missing headers |
| **Nikto Integration** | External CLI wrapper | Wraps Nikto scanner, parses JSON output (optional) |
| **Nuclei Integration** | External CLI wrapper | Wraps Nuclei scanner, parses JSONL output (optional) |

### 🎁 Bonus Features Implemented
| Feature | Implementation |
|---------|----------------|
| ✅ Recursive crawling | Depth-controlled BFS crawler |
| ✅ Multi-threading | ThreadPoolExecutor across all modules |
| ✅ Smart deduplication | URL normalization + set-based dedup |
| ✅ HTML report generation | Full hacker-themed report with charts |
| ✅ PDF download | Browser print-to-PDF with expanded sections |
| ✅ Stealth scanning | Rate-limiting, random User-Agents, jitter delays |
| ✅ Advanced attack surface | JS secret extraction, parameter mining |
| ✅ Docker support | Dockerfile + docker-compose.yml |
| ✅ HTTP/HTTPS auto-detection | Automatic fallback if HTTPS fails |

---

## 🏗️ Architecture

```
recon47/
├── recon47.py                        # Main CLI entry point
├── requirements.txt                  # Python dependencies
├── Dockerfile                        # Docker support
├── docker-compose.yml                # Docker compose
├── README.md                         # This file
├── recon47_prd.md                    # Product Requirements Document
│
├── core/                             # Core infrastructure
│   ├── __init__.py
│   ├── engine.py                     # Scan orchestrator (module pipeline)
│   ├── config.py                     # Configuration, wordlists, signatures
│   ├── logger.py                     # Rich-based console output
│   └── validator.py                  # Input validation & normalization
│
└── modules/                          # Feature modules
    ├── __init__.py
    ├── recon/                        # Reconnaissance
    │   ├── subdomain_enum.py         # Subdomain discovery
    │   ├── port_scanner.py           # TCP port scanning
    │   ├── tech_detect.py            # Technology fingerprinting
    │   ├── header_analyzer.py        # Security header audit
    │   ├── dns_recon.py              # DNS record enumeration
    │   └── whois_lookup.py           # WHOIS lookup
    ├── crawler/                      # Crawling & Discovery
    │   ├── crawler.py                # Recursive web crawler
    │   ├── js_analyzer.py            # JS secret extraction
    │   ├── param_extractor.py        # Parameter mining
    │   └── dir_bruteforce.py         # Directory discovery
    ├── scanners/                     # Vulnerability Scanning
    │   ├── nikto_scanner.py          # Nikto CLI integration
    │   ├── nuclei_scanner.py         # Nuclei CLI integration
    │   └── custom_checks.py          # 9 built-in security checks
    └── report/                       # Report Generation
        ├── html_report.py            # Hacker-themed HTML report
        └── json_export.py            # Machine-readable JSON export
```

### Scan Pipeline Flow
```
Target Input → Validation → HTTP/HTTPS Probe
    │
    ├── Phase 1: RECONNAISSANCE
    │   └── WHOIS → DNS → Subdomains → Ports → Tech Detection → Headers
    │
    ├── Phase 2: CRAWLING & DISCOVERY
    │   └── Web Crawler → Dir Bruteforce → JS Analysis → Param Extraction
    │
    ├── Phase 3: VULNERABILITY SCANNING
    │   └── Custom Checks → Nikto (opt) → Nuclei (opt)
    │
    └── Phase 4: REPORT GENERATION
        └── Statistics → JSON Export → HTML Report
```

---

## 📦 Installation

### Prerequisites
- **Python 3.10+**
- **pip** (Python package manager)
- **Git**

### Quick Setup (Kali Linux — Recommended)

```bash
# Clone the repository
git clone https://github.com/zafor-hridoy/recon47.git
cd recon47

# One-command setup (creates venv + installs deps)
chmod +x setup.sh && ./setup.sh

# Activate and run
source venv/bin/activate
python3 recon47.py -t example.com
```

### Manual Setup (with Virtual Environment)

```bash
git clone https://github.com/zafor-hridoy/recon47.git
cd recon47

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python3 recon47.py -t example.com
```

> ⚠️ **Kali Linux Note:** Modern Kali uses PEP 668 which blocks system-wide pip installs. Always use a virtual environment (`python3 -m venv venv`) as shown above.

### Optional: External Scanners (for full vuln scanning)

```bash
# Nikto (Kali Linux — pre-installed)
sudo apt install nikto

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# or download from: https://github.com/projectdiscovery/nuclei/releases
```

---

## 🚀 Usage

### Basic Scan
```bash
python3 recon47.py -t example.com
```

### Full Scan with External Tools
```bash
python3 recon47.py -t example.com --nikto --nuclei -o results
```

### Scan an IP Address
```bash
python3 recon47.py -t 192.168.1.1
```

### Stealth Mode (slower, evasive)
```bash
python3 recon47.py -t example.com --stealth --rate-limit 5 --threads 3
```

### Custom Options
```bash
python3 recon47.py -t https://example.com \
    --threads 20 \
    --timeout 15 \
    --depth 5 \
    -o my_scan_results
```

### Skip Phases
```bash
# Only reconnaissance
python3 recon47.py -t example.com --skip-crawl --skip-vuln

# Only crawling + vuln scan
python3 recon47.py -t example.com --skip-recon
```

### Docker
```bash
# Build
docker build -t recon47 .

# Run
docker run --rm -v $(pwd)/output:/app/recon47_output recon47 -t example.com
```

---

## 📖 CLI Reference

```
usage: recon47.py [-h] -t TARGET [-o OUTPUT] [--threads N] [--timeout N]
                  [--depth N] [--rate-limit N]
                  [--skip-recon] [--skip-crawl] [--skip-vuln]
                  [--nikto] [--nuclei] [--stealth]
                  [-v] [--no-banner]

Required:
  -t, --target TARGET     Target domain, URL, or IP address

Scan Options:
  -o, --output OUTPUT     Output directory (default: recon47_output)
  --threads N             Number of threads (default: 10)
  --timeout N             Request timeout in seconds (default: 10)
  --depth N               Crawler depth (default: 3)
  --rate-limit N          Max requests per second (default: 15)

Phase Control:
  --skip-recon            Skip reconnaissance phase
  --skip-crawl            Skip crawling phase
  --skip-vuln             Skip vulnerability scanning

External Scanners:
  --nikto                 Enable Nikto scanner
  --nuclei                Enable Nuclei scanner

Stealth & Display:
  --stealth               Enable stealth mode (random delays, User-Agent rotation)
  -v, --verbose           Verbose output
  --no-banner             Suppress ASCII banner
```

---

## 📊 Output & Reporting

Recon47 generates two report files in the output directory:

| File | Format | Description |
|------|--------|-------------|
| `report.html` | HTML | Interactive hacker-themed report with donut chart, expandable sections, severity badges, and **PDF download** |
| `results.json` | JSON | Machine-readable structured data for automation pipelines |

### HTML Report Sections
1. **Dashboard** — Summary statistics (subdomains, ports, technologies, URLs, vulnerabilities, duration)
2. **Target Information** — Domain, IP, URL, scheme
3. **Reconnaissance** — Subdomains, open ports, technologies, DNS records, WHOIS, security headers
4. **Crawling & Discovery** — Crawled URLs, directories, JS files, extracted parameters, JS secrets
5. **Vulnerabilities** — All findings sorted by severity with expandable detail cards
6. **Footer** — Scan metadata and disclaimer

### Downloading as PDF
Click the **"Download PDF"** button in the report → all sections expand automatically → browser print dialog opens → **Save as PDF**.

---

## 🛡️ Ethical Safeguards

- ⚠️ **Authorization disclaimer** displayed on every scan
- 🔒 Rate-limiting enabled by default (15 req/s)
- 🚫 No destructive payloads — read-only checks only
- 🎭 User-Agent rotation to avoid fingerprinting
- 📝 All scan activities logged with timestamps

---

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing only.**

- Only scan targets you have **explicit written permission** to test
- Do **NOT** use this tool against unauthorized targets
- Do **NOT** attempt to alter, delete, or destroy any data
- Follow all applicable laws and ethical hacking guidelines

The author assumes **no liability** for misuse of this tool.

---

## 📝 License

This project is for educational and authorized security testing purposes only.

---

**Built with ❤️ by Xaff**
