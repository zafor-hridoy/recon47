"""
Recon47 - Subdomain Enumeration Module
Author: Xaff
Discovers subdomains using 6 passive sources + active DNS brute-force with SecLists.
"""

import re
import json
import socket
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import COMMON_SUBDOMAINS, USER_AGENTS
from core.logger import Logger
import random


class SubdomainEnumerator:
    """Industry-level subdomain enumeration with multiple passive + active techniques."""

    def __init__(self, domain, threads=10, timeout=15):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.subdomains = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS)
        })

    def run(self):
        """Execute all subdomain enumeration techniques and return results."""
        # Passive enumeration — 6 sources
        self._crtsh_enum()
        self._hackertarget_enum()
        self._rapiddns_enum()
        self._alienvault_enum()
        self._urlscan_enum()
        self._anubis_enum()

        Logger.info(f"Passive sources found {len(self.subdomains)} unique subdomains")

        # Active DNS brute-force with SecLists
        self._dns_bruteforce()

        # Resolve and validate
        results = self._resolve_subdomains()
        return results

    def _crtsh_enum(self):
        """Query crt.sh certificate transparency logs."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.session.get(url, timeout=25)
            if resp.status_code == 200:
                data = resp.json()
                before = len(self.subdomains)
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            self.subdomains.add(sub)
                found = len(self.subdomains) - before
                Logger.found(f"crt.sh", f"{found} subdomains")
        except Exception as e:
            Logger.warning(f"crt.sh failed: {e}")

    def _hackertarget_enum(self):
        """Query HackerTarget API."""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                before = len(self.subdomains)
                for line in resp.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(self.domain):
                            self.subdomains.add(sub)
                Logger.found(f"HackerTarget", f"{len(self.subdomains) - before} subdomains")
        except Exception as e:
            Logger.warning(f"HackerTarget failed: {e}")

    def _rapiddns_enum(self):
        """Query RapidDNS."""
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                before = len(self.subdomains)
                pattern = r'<td>([a-zA-Z0-9\.\-]+\.' + re.escape(self.domain) + r')</td>'
                for m in re.findall(pattern, resp.text):
                    self.subdomains.add(m.lower())
                Logger.found(f"RapidDNS", f"{len(self.subdomains) - before} subdomains")
        except Exception as e:
            Logger.warning(f"RapidDNS failed: {e}")

    def _alienvault_enum(self):
        """Query AlienVault OTX."""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                before = len(self.subdomains)
                for entry in resp.json().get("passive_dns", []):
                    hostname = entry.get("hostname", "").lower()
                    if hostname.endswith(self.domain) and "*" not in hostname:
                        self.subdomains.add(hostname)
                Logger.found(f"AlienVault OTX", f"{len(self.subdomains) - before} subdomains")
        except Exception as e:
            Logger.warning(f"AlienVault failed: {e}")

    def _urlscan_enum(self):
        """Query URLScan.io."""
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                before = len(self.subdomains)
                for result in resp.json().get("results", []):
                    domain = result.get("page", {}).get("domain", "").lower()
                    if domain.endswith(self.domain):
                        self.subdomains.add(domain)
                Logger.found(f"URLScan.io", f"{len(self.subdomains) - before} subdomains")
        except Exception as e:
            Logger.warning(f"URLScan failed: {e}")

    def _anubis_enum(self):
        """Query Anubis-DB."""
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                before = len(self.subdomains)
                data = resp.json()
                if isinstance(data, list):
                    for sub in data:
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            self.subdomains.add(sub)
                Logger.found(f"Anubis-DB", f"{len(self.subdomains) - before} subdomains")
        except Exception as e:
            Logger.warning(f"Anubis failed: {e}")

    def _dns_bruteforce(self):
        """Brute-force subdomains using SecLists wordlist."""
        from core.seclists import SecListsManager
        wordlist = SecListsManager.get_wordlist("subdomains", max_words=5000)

        if not wordlist:
            Logger.warning("SecLists unavailable, using built-in wordlist")
            wordlist = COMMON_SUBDOMAINS

        Logger.info(f"DNS brute-force: {len(wordlist)} words...")
        found_count = 0

        def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            if subdomain in self.subdomains:
                return None
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(subdomain)
                return subdomain
            except (socket.gaierror, socket.timeout, OSError):
                return None

        with ThreadPoolExecutor(max_workers=min(self.threads * 3, 50)) as executor:
            futures = {executor.submit(check_subdomain, w): w for w in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)
                    found_count += 1

        Logger.found(f"DNS brute-force", f"{found_count} new subdomains")

    def _resolve_subdomains(self):
        """Resolve all discovered subdomains to IPs."""
        results = []
        seen = set()

        def resolve(sub):
            try:
                socket.setdefaulttimeout(3)
                ip = socket.gethostbyname(sub)
                return {"subdomain": sub, "ip": ip, "status": "active"}
            except (socket.gaierror, socket.timeout, OSError):
                return {"subdomain": sub, "ip": None, "status": "unresolved"}

        with ThreadPoolExecutor(max_workers=min(self.threads * 2, 30)) as executor:
            futures = {executor.submit(resolve, s): s for s in self.subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result["subdomain"] not in seen:
                    seen.add(result["subdomain"])
                    results.append(result)

        results.sort(key=lambda x: x["subdomain"])

        active = [r for r in results if r["status"] == "active"]
        if active:
            rows = [(r["subdomain"], r["ip"]) for r in active[:30]]
            Logger.table("Discovered Subdomains", ["Subdomain", "IP Address"], rows)
            if len(active) > 30:
                Logger.info(f"... and {len(active) - 30} more active subdomains")

        return results
