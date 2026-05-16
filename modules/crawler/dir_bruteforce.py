"""
Recon47 - Directory Bruteforce Module
Author: Xaff
Discovers hidden directories and files using SecLists wordlists.
"""

import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import COMMON_DIRS, USER_AGENTS
from core.logger import Logger


class DirBruteforcer:
    """Discovers directories and files via brute-force with SecLists."""

    def __init__(self, base_url, threads=10, timeout=10, rate_limit=15, stealth=False):
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.stealth = stealth
        self.results = []
        self.session = requests.Session()

    def _get_wordlist(self):
        """Get SecLists directory wordlist, fallback to built-in."""
        from core.seclists import SecListsManager
        wordlist = SecListsManager.get_wordlist("directories", max_words=3000)
        if wordlist:
            return wordlist
        Logger.warning("SecLists unavailable, using built-in directory list")
        return COMMON_DIRS

    def run(self):
        """Bruteforce directories and return results."""
        wordlist = self._get_wordlist()
        Logger.info(f"Testing {len(wordlist)} paths...")
        found = []

        with Logger.progress("Directory Bruteforce") as progress:
            task = progress.add_task("Checking paths", total=len(wordlist))

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._check_path, path): path
                    for path in wordlist
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
                    for f in found[:30]]
            Logger.table("Discovered Paths",
                         ["Path", "Status", "Content-Type", "Size"], rows)
            if len(found) > 30:
                Logger.info(f"... and {len(found) - 30} more")

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
