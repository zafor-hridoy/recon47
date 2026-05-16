# 🔱 Recon47

**Automated Reconnaissance & Vulnerability Scanner**

> **Author:** Xaff | **Version:** 1.0.0 | **Language:** Python 3.10+

Recon47 is a **production-ready, modular, CLI-based** automated reconnaissance and vulnerability scanning tool. Give it any target — domain, subdomain, URL, or IP address — and it performs a full security assessment, then generates a **hacker-themed HTML report** you can download as PDF.

> 📄 See [`recon47_prd.md`](recon47_prd.md) for the full Product Requirements Document.

---

## 📸 What You Get

- **2000+ subdomains** discovered via 6 passive sources + SecLists DNS brute-force
- **1000+ ports** scanned (Nmap top 1000)
- **Technology fingerprinting** with WAF bypass headers
- **3000+ directory paths** tested via SecLists wordlists
- **9 vulnerability checks** (CORS, XSS, SQLi, clickjacking, open redirect, etc.)
- **Hacker-themed HTML report** with severity chart, smart sorting, and PDF download

---

## ⚡ Quick Start (First-Time Setup)

### Step 1: Clone the Repository

```bash
git clone https://github.com/zafor-hridoy/recon47.git
cd recon47
```

### Step 2: Run the Setup Script

```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Create a Python virtual environment (`venv/`)
- Install all Python dependencies
- Check for SecLists and offer to download if not found

> **What is SecLists?** It's the industry-standard collection of wordlists used by penetration testers worldwide. Recon47 uses it for subdomain brute-force and directory discovery. On Kali Linux, you can also install it via `sudo apt install seclists`.

### Step 3: Activate the Virtual Environment

```bash
source venv/bin/activate
```

> ⚠️ **You must run this command every time you open a new terminal before using Recon47.**

### Step 4: Run Your First Scan

```bash
python3 recon47.py -t scanme.nmap.org
```

### Step 5: View the Report

After the scan completes, open the HTML report in your browser:

```bash
# The tool will print the report path, e.g.:
# Report: recon47_output/scanme_nmap_org_20260517_030000/report.html

# Open it in Firefox (Kali default browser)
firefox recon47_output/*/report.html
```

### Step 6: Download as PDF

In the HTML report, click the **"Download PDF"** button → all sections expand → browser print dialog opens → choose **"Save as PDF"**.

---

## 🚀 Usage Examples

### Basic Scan (any domain)
```bash
python3 recon47.py -t example.com
```

### Scan an IP Address
```bash
python3 recon47.py -t 192.168.1.1
```

### Scan a Full URL
```bash
python3 recon47.py -t https://target.com
```

### Full Scan with External Tools
```bash
python3 recon47.py -t example.com --nikto --nuclei
```

### Stealth Mode (slower, evasive)
```bash
python3 recon47.py -t example.com --stealth
```

### Custom Thread Count and Depth
```bash
python3 recon47.py -t example.com --threads 20 --depth 5
```

### Skip Specific Phases
```bash
# Only reconnaissance (no crawling or vuln scanning)
python3 recon47.py -t example.com --skip-crawl --skip-vuln

# Only crawling + vuln scanning (no recon)
python3 recon47.py -t example.com --skip-recon
```

### Show Help
```bash
python3 recon47.py -h
```

---

## 📖 CLI Options Reference

```
usage: recon47.py [-h] -t TARGET [-o OUTPUT] [--threads N] [--timeout N]
                  [--depth N] [--rate-limit N]
                  [--skip-recon] [--skip-crawl] [--skip-vuln]
                  [--nikto] [--nuclei] [--stealth]
                  [-v] [--no-banner]

Required:
  -t, --target TARGET     Target domain, URL, or IP address

Scan Options:
  -o, --output OUTPUT     Output base directory (default: recon47_output)
  --threads N             Number of threads (default: 10)
  --timeout N             Request timeout in seconds (default: 15)
  --depth N               Crawler depth (default: 3)
  --rate-limit N          Max requests per second (default: 15)

Phase Control:
  --skip-recon            Skip reconnaissance phase
  --skip-crawl            Skip crawling phase
  --skip-vuln             Skip vulnerability scanning

External Scanners:
  --nikto                 Enable Nikto scanner (must be installed)
  --nuclei                Enable Nuclei scanner (must be installed)

Stealth & Display:
  --stealth               Enable stealth mode (random delays, User-Agent rotation)
  -v, --verbose           Verbose output
  --no-banner             Suppress ASCII banner
```

---

## ✨ Features

### 🔍 Reconnaissance (6 Modules)
| Module | What It Does |
|--------|-------------|
| **WHOIS Lookup** | Domain registration, registrar, creation/expiry dates, nameservers |
| **DNS Recon** | A, AAAA, CNAME, MX, NS, TXT, SOA, PTR records |
| **Subdomain Enum** | 6 passive sources (crt.sh, HackerTarget, RapidDNS, AlienVault OTX, URLScan.io, Anubis-DB) + SecLists DNS brute-force (5000 words) |
| **Port Scanner** | Nmap top 1000 ports with 50-thread parallel scanning + banner grabbing |
| **Tech Detection** | Wappalyzer-style fingerprinting for 30+ technologies with WAF bypass headers |
| **Header Audit** | 8 security headers checked + cookie analysis + info disclosure detection |

### 🕷️ Crawling & Discovery (4 Modules)
| Module | What It Does |
|--------|-------------|
| **Web Crawler** | Recursive BFS crawler with depth control and smart deduplication |
| **Dir Bruteforce** | SecLists `raft-medium-directories.txt` (3000 paths) |
| **JS Analyzer** | Extract API keys, secrets, and endpoints from JavaScript files |
| **Param Extractor** | Mine URL query parameters and HTML form fields |

### ⚡ Vulnerability Scanning (3 Modules)
| Module | What It Does |
|--------|-------------|
| **Custom Checks** | 9 built-in checks: CORS, clickjacking, XSS reflection, SQL error detection, open redirect, sensitive files, HTTP methods, info disclosure, missing headers |
| **Nikto** | External web server scanner (optional, must be installed) |
| **Nuclei** | Template-based vulnerability scanner (optional, must be installed) |

### 📊 Reporting (2 Modules)
| Module | What It Does |
|--------|-------------|
| **HTML Report** | Hacker-themed dark report with severity donut chart, expandable sections, smart sorting, and PDF download |
| **JSON Export** | Machine-readable structured data for automation pipelines |

---

## 🏗️ Project Structure

```
recon47/
├── recon47.py                 # Main CLI entry point
├── setup.sh                   # One-command Kali setup script
├── requirements.txt           # Python dependencies
├── recon47_prd.md             # Product Requirements Document
├── README.md                  # This file
├── Dockerfile                 # Docker support
├── docker-compose.yml         # Docker compose
├── .gitignore
│
├── core/                      # Core infrastructure
│   ├── engine.py              # Scan orchestrator (phase pipeline)
│   ├── config.py              # Config, wordlists, signatures, top 1000 ports
│   ├── logger.py              # Rich-based console output
│   ├── validator.py           # Input validation & HTTP/HTTPS fallback
│   └── seclists.py            # SecLists auto-detection & download manager
│
└── modules/
    ├── recon/                 # 6 reconnaissance modules
    ├── crawler/               # 4 crawling & discovery modules
    ├── scanners/              # 3 vulnerability scanner modules
    └── report/                # HTML + JSON report generators
```

### Scan Pipeline
```
Target → Validation → HTTP/HTTPS Probe → SecLists Init
  │
  ├─ Phase 1: RECONNAISSANCE
  │  └─ WHOIS → DNS → Subdomains → Ports (1000) → Tech → Headers
  │
  ├─ Phase 2: CRAWLING & DISCOVERY
  │  └─ Crawler → Dir Bruteforce (3000 paths) → JS Analysis → Params
  │
  ├─ Phase 3: VULNERABILITY SCANNING
  │  └─ 9 Custom Checks → Nikto (opt) → Nuclei (opt)
  │
  └─ Phase 4: REPORTING
     └─ Statistics → JSON → HTML Report (with PDF download)
```

---

## 📊 Output & Reports

Each scan creates a **unique timestamped folder** so reports never overwrite each other:

```
recon47_output/
├── bestbuy_com_20260517_030000/
│   ├── report.html          # Interactive HTML report
│   └── results.json         # Machine-readable JSON
├── scanme_nmap_org_20260517_031500/
│   ├── report.html
│   └── results.json
```

### HTML Report Features
- 🎨 Dark "Cyber Matrix" hacker theme with animated scanline
- 📊 Dashboard with live statistics and severity donut chart
- 🔴 **Red-highlighted rows** for subdomains with internal IPs (10.x, 192.168.x)
- 🟡 **Amber-highlighted rows** for interesting subdomains (admin, dev, staging, vpn)
- 📂 Smart sorting: most interesting/vulnerable findings always on top
- 📥 One-click **Download PDF** button
- 📱 Responsive design for all screen sizes

---

## 🔧 Optional: External Scanners

These are optional and only used when you pass `--nikto` or `--nuclei` flags:

```bash
# Nikto (usually pre-installed on Kali)
sudo apt install nikto

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

---

## 🐳 Docker (Alternative)

```bash
# Build
docker build -t recon47 .

# Run
docker run --rm -v $(pwd)/output:/app/recon47_output recon47 -t example.com
```

---

## 🛡️ Ethical Safeguards

- ⚠️ Authorization disclaimer displayed on every scan
- 🔒 Rate-limiting enabled by default (15 req/s)
- 🚫 No destructive payloads — read-only checks only
- 🎭 User-Agent rotation to avoid fingerprinting
- 📝 All scan activities logged with timestamps

---

## ❓ Troubleshooting

### "externally-managed-environment" error on Kali
Always use a virtual environment. Run `./setup.sh` or manually:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Technology Detection / Header Analysis times out
Some sites (like BestBuy, Amazon) use aggressive WAFs (Akamai, Cloudflare) that block automated requests even with browser-like headers. This is expected — those WAFs require JavaScript execution which Python `requests` can't do. The tool will still collect subdomains, ports, DNS, and WHOIS data successfully.

### "SecLists not found" warning
Install SecLists:
```bash
sudo apt install seclists          # Kali/Debian
# OR
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists
```

### Scan is slow
- Port scanning 1000 ports takes ~60s depending on the target
- Use `--skip-recon` or `--skip-crawl` to skip phases you don't need
- Increase threads: `--threads 30`

---

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing only.**

- Only scan targets you have **explicit written permission** to test
- Do **NOT** use this tool against unauthorized targets
- Follow all applicable laws and ethical hacking guidelines
- The author assumes **no liability** for misuse of this tool

---

## 📝 License

This project is for educational and authorized security testing purposes only.

---

**Built with ❤️ by Xaff**
