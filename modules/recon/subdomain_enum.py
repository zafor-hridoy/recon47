"""
Recon47 - Subdomain Enumeration Module
Author: Xaff
Discovers subdomains using passive (crt.sh, web APIs) and active (DNS brute-force) techniques.
"""

import re
import json
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import COMMON_SUBDOMAINS, USER_AGENTS
from core.logger import Logger
import random


class SubdomainEnumerator:
    """Enumerates subdomains using multiple techniques."""

    def __init__(self, domain, threads=10, timeout=10):
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
        # Passive enumeration
        self._crtsh_enum()
        self._hackertarget_enum()
        self._rapiddns_enum()

        # Active DNS brute-force
        self._dns_bruteforce()

        # Resolve and validate
        results = self._resolve_subdomains()
        return results

    def _crtsh_enum(self):
        """Query crt.sh certificate transparency logs."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and "*" not in sub:
                            self.subdomains.add(sub)
                Logger.found(f"crt.sh", f"{len(self.subdomains)} entries")
        except Exception as e:
            Logger.warning(f"crt.sh query failed: {e}")

    def _hackertarget_enum(self):
        """Query HackerTarget API for subdomains."""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(self.domain):
                            self.subdomains.add(sub)
                Logger.found(f"HackerTarget", f"enumerated")
        except Exception as e:
            Logger.warning(f"HackerTarget query failed: {e}")

    def _rapiddns_enum(self):
        """Query RapidDNS for subdomains."""
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                pattern = r'<td>([a-zA-Z0-9\.\-]+\.' + re.escape(self.domain) + r')</td>'
                matches = re.findall(pattern, resp.text)
                for m in matches:
                    self.subdomains.add(m.lower())
                Logger.found(f"RapidDNS", f"enumerated")
        except Exception as e:
            Logger.warning(f"RapidDNS query failed: {e}")

    def _dns_bruteforce(self):
        """Brute-force subdomains using common wordlist."""
        Logger.info("Running DNS brute-force...")
        found_count = 0

        def check_subdomain(word):
            subdomain = f"{word}.{self.domain}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(check_subdomain, word): word
                for word in COMMON_SUBDOMAINS
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)
                    found_count += 1

        Logger.found(f"DNS brute-force", f"{found_count} resolved")

    def _resolve_subdomains(self):
        """Resolve all discovered subdomains to IP addresses."""
        results = []
        seen = set()

        def resolve(sub):
            try:
                ip = socket.gethostbyname(sub)
                return {"subdomain": sub, "ip": ip, "status": "active"}
            except socket.gaierror:
                return {"subdomain": sub, "ip": None, "status": "unresolved"}

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(resolve, s): s for s in self.subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result["subdomain"] not in seen:
                    seen.add(result["subdomain"])
                    results.append(result)

        # Sort by subdomain name
        results.sort(key=lambda x: x["subdomain"])

        # Display table of active subdomains
        active = [r for r in results if r["status"] == "active"]
        if active:
            rows = [(r["subdomain"], r["ip"]) for r in active[:20]]
            Logger.table("Discovered Subdomains",
                         ["Subdomain", "IP Address"], rows)
            if len(active) > 20:
                Logger.info(f"... and {len(active) - 20} more")

        return results
