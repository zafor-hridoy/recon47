"""
Recon47 - Technology Detection Module
Author: Xaff
Detects web technologies, frameworks, and services via HTTP headers and HTML content.
"""

import re
import random
import requests
from core.config import TECH_SIGNATURES, USER_AGENTS
from core.logger import Logger


class TechDetector:
    """Wappalyzer-style technology fingerprinting."""

    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.detected = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS)
        })

    def run(self):
        """Run technology detection and return list of detected technologies."""
        resp = None
        for attempt in range(3):
            try:
                self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
                resp = self.session.get(
                    self.url, timeout=max(self.timeout, 20),
                    verify=False, allow_redirects=True
                )
                break
            except requests.RequestException as e:
                if attempt == 2:
                    Logger.warning(f"Could not fetch {self.url} after 3 attempts: {e}")
                    return self.detected

        # Get response components
        headers_str = str(resp.headers).lower()
        body = resp.text.lower() if resp.text else ""
        cookies_str = str(resp.cookies.get_dict()).lower()
        server_header = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")

        # Check technology signatures
        for tech_name, sigs in TECH_SIGNATURES.items():
            confidence = 0
            matched_evidence = []

            # Check headers
            for header_sig in sigs.get("headers", []):
                if header_sig.lower() in headers_str or header_sig.lower() in cookies_str:
                    confidence += 50
                    matched_evidence.append(f"Header: {header_sig}")

            # Check body/meta tags
            for meta_sig in sigs.get("meta", []):
                if meta_sig.lower() in body:
                    confidence += 30
                    matched_evidence.append(f"Body: {meta_sig}")

            if confidence > 0:
                self.detected.append({
                    "name": tech_name,
                    "confidence": min(confidence, 100),
                    "evidence": matched_evidence
                })

        # Additional server header parsing
        if server_header and not any(d["name"] == server_header.split("/")[0]
                                     for d in self.detected):
            self.detected.append({
                "name": server_header,
                "confidence": 90,
                "evidence": [f"Server header: {server_header}"]
            })

        # X-Powered-By detection
        if powered_by and not any(d["name"] == powered_by for d in self.detected):
            self.detected.append({
                "name": powered_by,
                "confidence": 90,
                "evidence": [f"X-Powered-By: {powered_by}"]
            })

        # Additional heuristic checks
        self._check_cms_patterns(body, resp.headers)
        self._check_programming_language(resp.headers, body)

        # Sort by confidence
        self.detected.sort(key=lambda x: x["confidence"], reverse=True)

        # Deduplicate
        seen = set()
        unique = []
        for d in self.detected:
            if d["name"] not in seen:
                seen.add(d["name"])
                unique.append(d)
        self.detected = unique

        # Display
        if self.detected:
            rows = [(d["name"], f"{d['confidence']}%",
                     ", ".join(d["evidence"][:2])) for d in self.detected[:15]]
            Logger.table("Detected Technologies",
                         ["Technology", "Confidence", "Evidence"], rows)

        return self.detected

    def _check_cms_patterns(self, body, headers):
        """Check for CMS-specific patterns not in main signatures."""
        cms_checks = {
            "Shopify": ["cdn.shopify.com", "shopify.com"],
            "Squarespace": ["squarespace.com", "sqsp.net"],
            "Wix": ["wix.com", "wixsite.com"],
            "Ghost": ["ghost-frontend"],
            "Hugo": ["hugo-", "powered by hugo"],
            "Gatsby": ["gatsby-"],
            "Next.js": ["__next", "_next/static"],
            "Nuxt.js": ["__nuxt", "_nuxt/"],
        }
        for cms, patterns in cms_checks.items():
            if not any(d["name"] == cms for d in self.detected):
                for pattern in patterns:
                    if pattern in body:
                        self.detected.append({
                            "name": cms,
                            "confidence": 60,
                            "evidence": [f"Pattern: {pattern}"]
                        })
                        break

    def _check_programming_language(self, headers, body):
        """Detect server-side programming languages."""
        lang_checks = {
            "PHP": {
                "headers": ["x-powered-by: php", "phpsessid"],
                "body": [".php", "<?php"]
            },
            "Python": {
                "headers": ["x-powered-by: python", "wsgi"],
                "body": []
            },
            "Ruby": {
                "headers": ["x-powered-by: phusion", "x-rack-"],
                "body": []
            },
            "Java": {
                "headers": ["x-powered-by: servlet", "jsessionid"],
                "body": [".jsp", ".do", ".action"]
            },
        }
        headers_lower = str(headers).lower()
        for lang, checks in lang_checks.items():
            if not any(d["name"] == lang for d in self.detected):
                for h in checks.get("headers", []):
                    if h in headers_lower:
                        self.detected.append({
                            "name": lang,
                            "confidence": 70,
                            "evidence": [f"Header pattern: {h}"]
                        })
                        break
