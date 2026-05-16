"""
Recon47 - HTTP Header Security Analyzer
Author: Xaff
Audits HTTP response headers for security best practices.
"""

import random
import requests
from core.config import SECURITY_HEADERS, USER_AGENTS
from core.logger import Logger


class HeaderAnalyzer:
    """Analyzes HTTP response headers for security issues."""

    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
        })

    def run(self):
        """Analyze headers and return structured results."""
        results = {
            "raw_headers": {},
            "present": [],
            "missing": [],
            "findings": [],
            "server_info": {},
            "cookies": []
        }

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
                    Logger.warning(f"Could not fetch headers from {self.url} after 3 attempts: {e}")
                    return results

        # Store raw headers
        results["raw_headers"] = dict(resp.headers)

        # Server information
        results["server_info"] = {
            "status_code": resp.status_code,
            "server": resp.headers.get("Server", "Not disclosed"),
            "powered_by": resp.headers.get("X-Powered-By", "Not disclosed"),
            "content_type": resp.headers.get("Content-Type", ""),
        }

        # Check security headers
        for header_name, header_info in SECURITY_HEADERS.items():
            header_value = resp.headers.get(header_name)
            if header_value:
                results["present"].append({
                    "header": header_name,
                    "value": header_value,
                    "description": header_info["description"]
                })
            else:
                results["missing"].append({
                    "header": header_name,
                    "severity": header_info["severity"],
                    "description": header_info["description"],
                    "recommendation": header_info["recommendation"]
                })
                results["findings"].append({
                    "title": f"Missing {header_name} Header",
                    "severity": header_info["severity"],
                    "description": header_info["description"],
                    "recommendation": header_info["recommendation"]
                })

        # Analyze cookies
        for cookie in resp.cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "httponly" in str(cookie._rest).lower(),
                "samesite": cookie._rest.get("SameSite", "Not set"),
                "issues": []
            }
            if not cookie.secure:
                cookie_info["issues"].append("Missing Secure flag")
            if not cookie_info["httponly"]:
                cookie_info["issues"].append("Missing HttpOnly flag")
            if cookie_info["samesite"] == "Not set":
                cookie_info["issues"].append("Missing SameSite attribute")
            results["cookies"].append(cookie_info)

        # Check for information disclosure
        self._check_info_disclosure(resp.headers, results)

        # Display results
        self._display_results(results)

        return results

    def _check_info_disclosure(self, headers, results):
        """Check for headers that disclose sensitive server information."""
        disclosure_headers = {
            "Server": "Server version disclosed",
            "X-Powered-By": "Technology stack disclosed",
            "X-AspNet-Version": "ASP.NET version disclosed",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
        }
        for header, desc in disclosure_headers.items():
            value = headers.get(header)
            if value:
                # Only flag if it contains version info
                if any(c.isdigit() for c in value):
                    results["findings"].append({
                        "title": f"Information Disclosure: {header}",
                        "severity": "LOW",
                        "description": f"{desc}: {value}",
                        "recommendation": f"Remove or obfuscate the {header} header"
                    })

    def _display_results(self, results):
        """Display header analysis results."""
        # Present headers
        if results["present"]:
            rows = [(h["header"], h["value"][:60]) for h in results["present"]]
            Logger.table("Security Headers Present",
                         ["Header", "Value"], rows)

        # Missing headers
        if results["missing"]:
            rows = [(h["header"], h["severity"], h["recommendation"][:60])
                    for h in results["missing"]]
            Logger.table("Missing Security Headers",
                         ["Header", "Severity", "Recommendation"], rows)

        # Cookie issues
        insecure_cookies = [c for c in results["cookies"] if c["issues"]]
        if insecure_cookies:
            rows = [(c["name"], ", ".join(c["issues"]))
                    for c in insecure_cookies]
            Logger.table("Cookie Security Issues",
                         ["Cookie", "Issues"], rows)
