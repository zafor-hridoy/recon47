"""
Recon47 - JavaScript Analyzer Module
Author: Xaff
Analyzes JavaScript files for secrets, API endpoints, and sensitive data.
"""

import re
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import USER_AGENTS
from core.logger import Logger


class JSAnalyzer:
    """Extracts secrets and endpoints from JavaScript files."""

    SECRET_PATTERNS = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "AWS Secret Key": r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "Slack Token": r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        "GitHub Token": r'gh[ps]_[A-Za-z0-9_]{36}',
        "JWT Token": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "Generic API Key": r'(?i)(api[_-]?key|apikey|api_secret)[\'"\s:=]+[\'"][a-zA-Z0-9]{16,}[\'"]',
        "Generic Secret": r'(?i)(secret|password|passwd|token)[\'"\s:=]+[\'"][^\'"]{8,}[\'"]',
        "Authorization Bearer": r'(?i)bearer\s+[a-zA-Z0-9\-_.~+/]+=*',
        "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "Internal IP": r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
    }

    ENDPOINT_PATTERNS = [
        r'[\'"`](/api/[a-zA-Z0-9/_\-]+)[\'"`]',
        r'[\'"`](/v[0-9]+/[a-zA-Z0-9/_\-]+)[\'"`]',
        r'[\'"`](https?://[^\s\'"<>]+)[\'"`]',
        r'(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"]+)[\'"`]',
        r'[\'"`](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+){1,})[\'"`]',
    ]

    def __init__(self, js_urls, timeout=10):
        self.js_urls = js_urls
        self.timeout = timeout
        self.secrets = []
        self.endpoints = set()

    def run(self):
        """Analyze all JS files and return findings."""
        Logger.info(f"Analyzing {len(self.js_urls)} JavaScript files...")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self._analyze_file, url): url for url in self.js_urls}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        if self.secrets:
            rows = [(s["type"], s["file"].split("/")[-1], s["value"][:50]) for s in self.secrets[:15]]
            Logger.table("JS Secrets Found", ["Type", "File", "Value"], rows)

        return {"secrets": self.secrets, "endpoints": sorted(list(self.endpoints))}

    def _analyze_file(self, url):
        """Download and analyze a single JS file."""
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = requests.get(url, timeout=self.timeout, headers=headers, verify=False)
            if resp.status_code != 200:
                return
            content = resp.text
            self._find_secrets(content, url)
            self._find_endpoints(content)
        except Exception:
            pass

    def _find_secrets(self, content, url):
        """Search for secret patterns in JS content."""
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    val = match if isinstance(match, str) else match[0]
                    if len(val) > 200:
                        continue
                    self.secrets.append({"type": secret_type, "value": val, "file": url})
            except re.error:
                pass

    def _find_endpoints(self, content):
        """Search for API endpoints in JS content."""
        for pattern in self.ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    ep = match if isinstance(match, str) else match[0]
                    if len(ep) < 200 and not ep.endswith(('.js', '.css', '.png', '.jpg')):
                        self.endpoints.add(ep)
            except re.error:
                pass
