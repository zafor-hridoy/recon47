"""
Recon47 - Core Scan Engine
Author: Xaff
Orchestrates all scanning modules and manages scan state.
"""

import os
import time
import json
from datetime import datetime

from core.config import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR,
    DEFAULT_OUTPUT_DIR, DEFAULT_THREADS, DEFAULT_TIMEOUT,
    DEFAULT_CRAWL_DEPTH, DEFAULT_RATE_LIMIT
)
from core.logger import Logger
from core.validator import TargetValidator

# Recon modules
from modules.recon.subdomain_enum import SubdomainEnumerator
from modules.recon.port_scanner import PortScanner
from modules.recon.tech_detect import TechDetector
from modules.recon.header_analyzer import HeaderAnalyzer
from modules.recon.dns_recon import DNSRecon
from modules.recon.whois_lookup import WhoisLookup

# Crawler modules
from modules.crawler.crawler import WebCrawler
from modules.crawler.js_analyzer import JSAnalyzer
from modules.crawler.param_extractor import ParamExtractor
from modules.crawler.dir_bruteforce import DirBruteforcer

# Scanner modules
from modules.scanners.nikto_scanner import NiktoScanner
from modules.scanners.nuclei_scanner import NucleiScanner
from modules.scanners.custom_checks import CustomVulnChecker

# Report modules
from modules.report.html_report import HTMLReportGenerator
from modules.report.json_export import JSONExporter


class ScanEngine:
    """
    Core engine that orchestrates all Recon47 modules.
    Manages scan lifecycle, module execution order, and result aggregation.
    """

    def __init__(self, args):
        self.args = args
        self.target = None
        self.validator = None
        self.start_time = None
        self.end_time = None
        self.output_base = args.output or DEFAULT_OUTPUT_DIR
        self.output_dir = None  # Set after target validation
        self.threads = args.threads or DEFAULT_THREADS
        self.timeout = args.timeout or DEFAULT_TIMEOUT
        self.depth = args.depth or DEFAULT_CRAWL_DEPTH
        self.rate_limit = args.rate_limit or DEFAULT_RATE_LIMIT
        self.stealth = args.stealth if hasattr(args, 'stealth') else False

        # Aggregated results
        self.results = {
            "meta": {},
            "target": {},
            "recon": {
                "subdomains": [],
                "ports": [],
                "technologies": [],
                "headers": {},
                "dns": {},
                "whois": {}
            },
            "crawler": {
                "urls": [],
                "js_files": [],
                "js_secrets": [],
                "parameters": [],
                "forms": [],
                "directories": []
            },
            "vulnerabilities": [],
            "statistics": {}
        }

    def run(self):
        """Execute the full scan pipeline."""
        self.start_time = time.time()

        # Display banner
        if not self.args.no_banner:
            Logger.banner()
            Logger.disclaimer()

        # Validate target
        Logger.phase("TARGET VALIDATION", "🎯")
        try:
            self.validator = TargetValidator(self.args.target)
            self.validator.validate()
            self.target = self.validator.get_info()
        except ValueError as e:
            Logger.error(str(e))
            return

        # Probe connectivity — try HTTPS, fall back to HTTP
        import requests
        base_url = self.validator.get_base_url()
        try:
            requests.head(base_url, timeout=5, verify=False, allow_redirects=True)
        except requests.ConnectionError:
            if self.target["scheme"] == "https":
                alt_url = base_url.replace("https://", "http://", 1)
                try:
                    requests.head(alt_url, timeout=5, verify=False, allow_redirects=True)
                    Logger.warning(f"HTTPS unreachable, falling back to HTTP")
                    self.validator.scheme = "http"
                    self.validator.url = alt_url
                    self.target = self.validator.get_info()
                    self.target["scheme"] = "http"
                    self.target["url"] = alt_url
                except requests.ConnectionError:
                    Logger.warning("Target may be unreachable on both HTTP and HTTPS")
        except Exception:
            pass

        Logger.summary_panel("Target Information", {
            "Target": self.target["domain"],
            "IP Address": self.target["ip"] or "Unresolved",
            "URL": self.target["url"],
            "Type": self.target["target_type"].upper()
        })

        # Populate metadata
        self.results["meta"] = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "author": TOOL_AUTHOR,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_timestamp": datetime.now().isoformat(),
            "threads": self.threads,
            "timeout": self.timeout
        }
        self.results["target"] = self.target

        # Prepare unique output directory per scan
        safe_target = self.target["domain"].replace(".", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = os.path.join(self.output_base, f"{safe_target}_{timestamp}")
        os.makedirs(self.output_dir, exist_ok=True)
        Logger.info(f"Output directory: {self.output_dir}")

        # ── Phase 1: Reconnaissance ────────────────────────────
        if not self.args.skip_recon:
            self._run_recon()

        # ── Phase 2: Crawling & Discovery ──────────────────────
        if not self.args.skip_crawl:
            self._run_crawl()

        # ── Phase 3: Vulnerability Scanning ────────────────────
        if not self.args.skip_vuln:
            self._run_vuln_scan()

        # ── Phase 4: Compute Statistics & Generate Reports ─────
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        self._compute_statistics(duration)
        self._generate_reports()

        report_path = os.path.join(self.output_dir, "report.html")
        Logger.scan_complete(duration, report_path)

    def _run_recon(self):
        """Execute all reconnaissance modules."""
        Logger.phase("RECONNAISSANCE", "🔍")

        # 1. WHOIS Lookup
        Logger.module("WHOIS Lookup", "Domain registration info")
        try:
            whois = WhoisLookup(self.target["domain"], self.timeout)
            self.results["recon"]["whois"] = whois.run()
            Logger.success(f"WHOIS data collected")
        except Exception as e:
            Logger.error(f"WHOIS lookup failed: {e}")

        # 2. DNS Reconnaissance
        Logger.module("DNS Reconnaissance", "Record enumeration")
        try:
            dns = DNSRecon(self.target["domain"], self.timeout)
            self.results["recon"]["dns"] = dns.run()
            record_count = sum(len(v) if isinstance(v, list) else 1
                               for v in self.results["recon"]["dns"].values()
                               if v)
            Logger.success(f"Collected {record_count} DNS records")
        except Exception as e:
            Logger.error(f"DNS recon failed: {e}")

        # 3. Subdomain Enumeration
        Logger.module("Subdomain Enumeration", "Passive + active discovery")
        try:
            sub_enum = SubdomainEnumerator(
                self.target["domain"], self.threads, self.timeout
            )
            self.results["recon"]["subdomains"] = sub_enum.run()
            Logger.success(
                f"Found {len(self.results['recon']['subdomains'])} subdomains"
            )
        except Exception as e:
            Logger.error(f"Subdomain enumeration failed: {e}")

        # 4. Port Scanning
        Logger.module("Port Scanning", "Service discovery")
        try:
            port_scanner = PortScanner(
                self.target["ip"] or self.target["domain"],
                threads=self.threads,
                timeout=self.timeout
            )
            self.results["recon"]["ports"] = port_scanner.run()
            open_ports = [p for p in self.results["recon"]["ports"]
                          if p.get("state") == "open"]
            Logger.success(f"Found {len(open_ports)} open ports")
        except Exception as e:
            Logger.error(f"Port scanning failed: {e}")

        # 5. Technology Detection
        Logger.module("Technology Detection", "Fingerprinting stack")
        try:
            tech = TechDetector(self.target["url"], self.timeout)
            self.results["recon"]["technologies"] = tech.run()
            Logger.success(
                f"Detected {len(self.results['recon']['technologies'])} technologies"
            )
        except Exception as e:
            Logger.error(f"Technology detection failed: {e}")

        # 6. HTTP Header Analysis
        Logger.module("Header Security Analysis", "Security header audit")
        try:
            headers = HeaderAnalyzer(self.target["url"], self.timeout)
            self.results["recon"]["headers"] = headers.run()
            missing = len(self.results["recon"]["headers"].get("missing", []))
            Logger.success(f"Header analysis complete — {missing} missing security headers")
        except Exception as e:
            Logger.error(f"Header analysis failed: {e}")

    def _run_crawl(self):
        """Execute all crawler modules."""
        Logger.phase("CRAWLING & DISCOVERY", "🕷️")
        base_url = self.validator.get_base_url()

        # 1. Web Crawler
        Logger.module("Web Crawler", f"Recursive depth={self.depth}")
        try:
            crawler = WebCrawler(
                base_url, max_depth=self.depth,
                threads=self.threads, timeout=self.timeout,
                rate_limit=self.rate_limit, stealth=self.stealth
            )
            crawl_results = crawler.run()
            self.results["crawler"]["urls"] = crawl_results.get("urls", [])
            self.results["crawler"]["js_files"] = crawl_results.get("js_files", [])
            self.results["crawler"]["forms"] = crawl_results.get("forms", [])
            Logger.success(
                f"Crawled {len(self.results['crawler']['urls'])} URLs, "
                f"found {len(self.results['crawler']['js_files'])} JS files"
            )
        except Exception as e:
            Logger.error(f"Crawling failed: {e}")

        # 2. Directory Bruteforce
        Logger.module("Directory Bruteforce", "Common paths discovery")
        try:
            dir_brute = DirBruteforcer(
                base_url, threads=self.threads,
                timeout=self.timeout, rate_limit=self.rate_limit,
                stealth=self.stealth
            )
            self.results["crawler"]["directories"] = dir_brute.run()
            Logger.success(
                f"Found {len(self.results['crawler']['directories'])} directories/files"
            )
        except Exception as e:
            Logger.error(f"Directory bruteforce failed: {e}")

        # 3. JavaScript Analysis
        if self.results["crawler"]["js_files"]:
            Logger.module("JavaScript Analysis", "Extracting secrets & endpoints")
            try:
                js_analyzer = JSAnalyzer(
                    self.results["crawler"]["js_files"],
                    timeout=self.timeout
                )
                js_results = js_analyzer.run()
                self.results["crawler"]["js_secrets"] = js_results.get("secrets", [])
                endpoints = js_results.get("endpoints", [])
                # Merge discovered endpoints into URL list
                for ep in endpoints:
                    if ep not in self.results["crawler"]["urls"]:
                        self.results["crawler"]["urls"].append(ep)
                Logger.success(
                    f"Found {len(self.results['crawler']['js_secrets'])} secrets, "
                    f"{len(endpoints)} endpoints in JS files"
                )
            except Exception as e:
                Logger.error(f"JS analysis failed: {e}")

        # 4. Parameter Extraction
        Logger.module("Parameter Extraction", "Mining params & form fields")
        try:
            param_extractor = ParamExtractor(
                self.results["crawler"]["urls"],
                self.results["crawler"]["forms"]
            )
            param_results = param_extractor.run()
            self.results["crawler"]["parameters"] = param_results
            Logger.success(
                f"Extracted {len(param_results)} unique parameters"
            )
        except Exception as e:
            Logger.error(f"Parameter extraction failed: {e}")

    def _run_vuln_scan(self):
        """Execute vulnerability scanning modules."""
        Logger.phase("VULNERABILITY SCANNING", "⚡")
        base_url = self.validator.get_base_url()

        # 1. Custom Vulnerability Checks
        Logger.module("Custom Security Checks", "Built-in vulnerability detection")
        try:
            custom = CustomVulnChecker(
                base_url,
                urls=self.results["crawler"]["urls"],
                params=self.results["crawler"]["parameters"],
                headers_data=self.results["recon"]["headers"],
                timeout=self.timeout,
                threads=self.threads
            )
            custom_vulns = custom.run()
            self.results["vulnerabilities"].extend(custom_vulns)
            Logger.success(f"Custom checks found {len(custom_vulns)} issues")
        except Exception as e:
            Logger.error(f"Custom checks failed: {e}")

        # 2. Nikto Scanner (optional)
        if self.args.nikto:
            Logger.module("Nikto Scanner", "External vulnerability scanner")
            try:
                nikto = NiktoScanner(base_url, self.output_dir)
                nikto_vulns = nikto.run()
                self.results["vulnerabilities"].extend(nikto_vulns)
                Logger.success(f"Nikto found {len(nikto_vulns)} issues")
            except Exception as e:
                Logger.error(f"Nikto scan failed: {e}")

        # 3. Nuclei Scanner (optional)
        if self.args.nuclei:
            Logger.module("Nuclei Scanner", "Template-based vulnerability scanner")
            try:
                nuclei = NucleiScanner(base_url, self.output_dir)
                nuclei_vulns = nuclei.run()
                self.results["vulnerabilities"].extend(nuclei_vulns)
                Logger.success(f"Nuclei found {len(nuclei_vulns)} issues")
            except Exception as e:
                Logger.error(f"Nuclei scan failed: {e}")

        # Display vulnerability summary
        if self.results["vulnerabilities"]:
            self._display_vuln_summary()

    def _display_vuln_summary(self):
        """Show a summary table of discovered vulnerabilities."""
        vulns = self.results["vulnerabilities"]
        severity_count = {}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            severity_count[sev] = severity_count.get(sev, 0) + 1

        Logger.separator()
        rows = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in severity_count:
                rows.append((sev, str(severity_count[sev])))

        if rows:
            Logger.table("Vulnerability Summary",
                         ["Severity", "Count"], rows)

        # Show top findings
        for v in sorted(vulns,
                        key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                       "LOW": 3, "INFO": 4}.get(
                            x.get("severity", "INFO").upper(), 5)):
            Logger.vuln(
                v.get("severity", "INFO"),
                v.get("title", "Unknown"),
                v.get("detail", "")
            )

    def _generate_reports(self):
        """Generate HTML and JSON reports."""
        Logger.phase("REPORT GENERATION", "📊")

        # JSON Export
        Logger.module("JSON Export", "Structured data export")
        try:
            json_path = os.path.join(self.output_dir, "results.json")
            exporter = JSONExporter(self.results, json_path)
            exporter.export()
            Logger.success(f"JSON report saved → {json_path}")
        except Exception as e:
            Logger.error(f"JSON export failed: {e}")

        # HTML Report
        Logger.module("HTML Report", "Generating hacker-themed report")
        try:
            html_path = os.path.join(self.output_dir, "report.html")
            html_gen = HTMLReportGenerator(self.results, html_path)
            html_gen.generate()
            Logger.success(f"HTML report saved → {html_path}")
        except Exception as e:
            Logger.error(f"HTML report generation failed: {e}")

    def _compute_statistics(self, duration):
        """Compute final scan statistics."""
        vulns = self.results["vulnerabilities"]
        severity_count = {}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            severity_count[sev] = severity_count.get(sev, 0) + 1

        self.results["statistics"] = {
            "scan_duration": f"{duration:.1f}s",
            "total_subdomains": len(self.results["recon"]["subdomains"]),
            "total_open_ports": len([p for p in self.results["recon"]["ports"]
                                     if p.get("state") == "open"]),
            "total_technologies": len(self.results["recon"]["technologies"]),
            "total_urls_crawled": len(self.results["crawler"]["urls"]),
            "total_js_files": len(self.results["crawler"]["js_files"]),
            "total_parameters": len(self.results["crawler"]["parameters"]),
            "total_directories": len(self.results["crawler"]["directories"]),
            "total_vulnerabilities": len(vulns),
            "severity_breakdown": severity_count
        }

        # Update the JSON with final stats
        try:
            json_path = os.path.join(self.output_dir, "results.json")
            exporter = JSONExporter(self.results, json_path)
            exporter.export()
        except Exception:
            pass
