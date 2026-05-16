"""
Recon47 - Directory Bruteforce Module
Author: Xaff
Discovers hidden directories and files using a wordlist.
"""

import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import COMMON_DIRS, USER_AGENTS
from core.logger import Logger


class DirBruteforcer:
    """Discovers directories and files via brute-force."""

    def __init__(self, base_url, threads=10, timeout=10, rate_limit=15, stealth=False):
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.stealth = stealth
        self.delay = 1.0 / rate_limit if rate_limit > 0 else 0
        self.results = []
        self.session = requests.Session()

    def run(self):
        """Bruteforce common directories and return results."""
        Logger.info(f"Testing {len(COMMON_DIRS)} common paths...")
        found = []

        with Logger.progress("Directory Bruteforce") as progress:
            task = progress.add_task("Checking paths", total=len(COMMON_DIRS))

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._check_path, path): path
                    for path in COMMON_DIRS
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        found.append(result)
                    progress.update(task, advance=1)

        found.sort(key=lambda x: x["status_code"])

        if found:
            rows = [(f["path"], str(f["status_code"]), f["content_type"][:40],
                      str(f["content_length"]))
                    for f in found[:25]]
            Logger.table("Discovered Paths",
                         ["Path", "Status", "Content-Type", "Size"], rows)
            if len(found) > 25:
                Logger.info(f"... and {len(found) - 25} more")

        return found

    def _check_path(self, path):
        """Check a single path for existence."""
        url = f"{self.base_url}/{path}"
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = self.session.get(url, timeout=self.timeout, headers=headers,
                                    verify=False, allow_redirects=False)

            if self.stealth:
                time.sleep(random.uniform(0.2, 0.8))

            # Consider 200, 301, 302, 403 as found
            if resp.status_code in (200, 301, 302, 403, 405):
                return {
                    "path": f"/{path}",
                    "url": url,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", "unknown"),
                    "content_length": len(resp.content),
                    "redirect": resp.headers.get("Location", "")
                }
        except Exception:
            pass
        return None
