"""
Recon47 - Web Crawler Module
Author: Xaff
Recursive web crawler with depth control, JS file extraction, and form discovery.
"""

import re
import time
import random
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from core.config import USER_AGENTS
from core.logger import Logger


class WebCrawler:
    """Recursive web crawler with smart deduplication."""

    def __init__(self, base_url, max_depth=3, threads=10, timeout=10,
                 rate_limit=15, stealth=False):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.stealth = stealth
        self.delay = 1.0 / rate_limit if rate_limit > 0 else 0

        self.visited = set()
        self.urls = set()
        self.js_files = set()
        self.forms = []
        self.queue = deque()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        })

        # Excluded extensions
        self.skip_ext = {
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.woff', '.woff2',
            '.ttf', '.eot', '.otf', '.css'
        }

    def run(self):
        """Run the crawler and return discovered assets."""
        Logger.info(f"Crawling {self.base_url} (depth={self.max_depth})...")
        self.queue.append((self.base_url, 0))
        self.visited.add(self._normalize(self.base_url))

        with Logger.progress("Crawling") as progress:
            task = progress.add_task("Discovering URLs", total=None)
            while self.queue:
                batch = []
                while self.queue and len(batch) < self.threads:
                    batch.append(self.queue.popleft())

                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {
                        executor.submit(self._fetch, url, depth): (url, depth)
                        for url, depth in batch
                    }
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            pass

                progress.update(task, description=f"Discovered {len(self.urls)} URLs")
                if self.stealth:
                    time.sleep(random.uniform(0.5, 1.5))

        results = {
            "urls": sorted(list(self.urls)),
            "js_files": sorted(list(self.js_files)),
            "forms": self.forms
        }
        Logger.success(f"Crawl complete: {len(self.urls)} URLs, {len(self.js_files)} JS files, {len(self.forms)} forms")
        return results

    def _fetch(self, url, depth):
        """Fetch a URL and extract links."""
        if depth > self.max_depth:
            return
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            resp = self.session.get(url, timeout=self.timeout, headers=headers,
                                    verify=False, allow_redirects=True)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                return
            self.urls.add(url)
            soup = BeautifulSoup(resp.text, "lxml")
            self._extract_links(soup, url, depth)
            self._extract_js(soup, url)
            self._extract_forms(soup, url)
            if self.stealth:
                time.sleep(random.uniform(0.3, 1.0))
        except Exception:
            pass

    def _extract_links(self, soup, current_url, depth):
        """Extract and queue new links from HTML."""
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag["href"]
            full_url = urljoin(current_url, href)
            normalized = self._normalize(full_url)
            parsed = urlparse(full_url)

            if parsed.netloc != self.parsed_base.netloc:
                continue
            ext = '.' + parsed.path.rsplit('.', 1)[-1].lower() if '.' in parsed.path else ''
            if ext in self.skip_ext:
                continue
            if normalized not in self.visited:
                self.visited.add(normalized)
                self.urls.add(full_url)
                if depth + 1 <= self.max_depth:
                    self.queue.append((full_url, depth + 1))

    def _extract_js(self, soup, current_url):
        """Extract JavaScript file URLs."""
        for script in soup.find_all("script", src=True):
            js_url = urljoin(current_url, script["src"])
            self.js_files.add(js_url)

    def _extract_forms(self, soup, current_url):
        """Extract form details."""
        for form in soup.find_all("form"):
            action = urljoin(current_url, form.get("action", ""))
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                })
            self.forms.append({
                "action": action, "method": method,
                "inputs": inputs, "page": current_url
            })

    @staticmethod
    def _normalize(url):
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/") or "/"
        return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
