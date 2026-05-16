"""
Recon47 - Custom Vulnerability Checks Module
Author: Xaff
Built-in security checks for common web vulnerabilities.
"""

import re
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.config import USER_AGENTS, SECURITY_HEADERS
from core.logger import Logger


class CustomVulnChecker:
    """Custom vulnerability scanner with built-in security checks."""

    def __init__(self, base_url, urls=None, params=None, headers_data=None,
                 timeout=10, threads=5):
        self.base_url = base_url
        self.urls = urls or []
        self.params = params or []
        self.headers_data = headers_data or {}
        self.timeout = timeout
        self.threads = threads
        self.vulns = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    def run(self):
        """Run all custom vulnerability checks."""
        self._check_cors()
        self._check_clickjacking()
        self._check_info_disclosure()
        self._check_open_redirect()
        self._check_sql_error_based()
        self._check_xss_reflection()
        self._check_sensitive_files()
        self._check_missing_headers()
        self._check_http_methods()

        return self.vulns

    def _check_cors(self):
        """Check for CORS misconfiguration."""
        Logger.info("Checking CORS configuration...")
        try:
            headers = {"Origin": "https://evil-attacker.com"}
            resp = self.session.get(self.base_url, headers=headers,
                                    timeout=self.timeout, verify=False)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                self.vulns.append({
                    "title": "CORS Wildcard Origin",
                    "severity": "MEDIUM",
                    "source": "Custom",
                    "detail": "Access-Control-Allow-Origin is set to '*'",
                    "url": self.base_url,
                    "recommendation": "Restrict CORS to specific trusted origins"
                })
            elif "evil-attacker.com" in acao:
                sev = "HIGH" if acac.lower() == "true" else "MEDIUM"
                self.vulns.append({
                    "title": "CORS Origin Reflection",
                    "severity": sev,
                    "source": "Custom",
                    "detail": f"Origin reflected: {acao}, Credentials: {acac}",
                    "url": self.base_url,
                    "recommendation": "Validate allowed origins server-side"
                })
        except Exception:
            pass

    def _check_clickjacking(self):
        """Check for clickjacking vulnerability."""
        Logger.info("Checking clickjacking protection...")
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout, verify=False)
            xfo = resp.headers.get("X-Frame-Options", "")
            csp = resp.headers.get("Content-Security-Policy", "")

            if not xfo and "frame-ancestors" not in csp:
                self.vulns.append({
                    "title": "Clickjacking - Missing Frame Protection",
                    "severity": "MEDIUM",
                    "source": "Custom",
                    "detail": "No X-Frame-Options or CSP frame-ancestors directive",
                    "url": self.base_url,
                    "recommendation": "Add X-Frame-Options: DENY header"
                })
        except Exception:
            pass

    def _check_info_disclosure(self):
        """Check for information disclosure via error pages and headers."""
        Logger.info("Checking information disclosure...")
        test_paths = [
            "/nonexistent-page-" + str(random.randint(10000, 99999)),
            "/%00", "/~root", "/trace"
        ]
        for path in test_paths:
            try:
                url = f"{self.base_url}{path}"
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                body = resp.text.lower()

                # Check for stack traces
                indicators = [
                    ("stack trace", "Stack Trace Exposed"),
                    ("traceback", "Python Traceback Exposed"),
                    ("exception", "Exception Details Exposed"),
                    ("sql syntax", "SQL Error Exposed"),
                    ("at /", "Server Path Exposed"),
                ]
                for indicator, title in indicators:
                    if indicator in body and resp.status_code >= 400:
                        self.vulns.append({
                            "title": f"Information Disclosure: {title}",
                            "severity": "LOW",
                            "source": "Custom",
                            "detail": f"Found '{indicator}' in error page at {path}",
                            "url": url,
                            "recommendation": "Configure custom error pages"
                        })
                        break
            except Exception:
                pass

    def _check_open_redirect(self):
        """Check for open redirect vulnerabilities."""
        Logger.info("Checking open redirect...")
        payloads = [
            "//evil.com", "https://evil.com", "/\\evil.com",
            "//evil.com/%2f..", "https://evil.com%40target.com"
        ]
        redirect_params = ["url", "redirect", "next", "return", "goto",
                          "returnTo", "redirect_uri", "continue", "dest"]

        for param_info in self.params:
            name = param_info.get("name", "") if isinstance(param_info, dict) else str(param_info)
            if name.lower() in redirect_params:
                for payload in payloads[:2]:
                    try:
                        url = f"{self.base_url}?{name}={payload}"
                        resp = self.session.get(url, timeout=self.timeout,
                                                verify=False, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            self.vulns.append({
                                "title": f"Open Redirect via '{name}' parameter",
                                "severity": "MEDIUM",
                                "source": "Custom",
                                "detail": f"Redirects to: {location}",
                                "url": url,
                                "recommendation": "Validate redirect URLs server-side"
                            })
                            break
                    except Exception:
                        pass

    def _check_sql_error_based(self):
        """Check for SQL error-based injection indicators."""
        Logger.info("Checking SQL error indicators...")
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql", "unclosed quotation mark",
            "microsoft ole db provider", "odbc drivers error",
            "postgresql", "ora-01756", "sqlite3.operationalerror"
        ]
        payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='2"]

        tested = 0
        for param_info in self.params[:10]:
            name = param_info.get("name", "") if isinstance(param_info, dict) else str(param_info)
            if not name:
                continue
            for payload in payloads[:2]:
                try:
                    url = f"{self.base_url}?{name}={payload}"
                    resp = self.session.get(url, timeout=self.timeout, verify=False)
                    body = resp.text.lower()
                    for error in sql_errors:
                        if error in body:
                            self.vulns.append({
                                "title": f"Possible SQL Injection via '{name}'",
                                "severity": "HIGH",
                                "source": "Custom",
                                "detail": f"SQL error pattern found: {error}",
                                "url": url,
                                "recommendation": "Use parameterized queries"
                            })
                            break
                    tested += 1
                except Exception:
                    pass

    def _check_xss_reflection(self):
        """Check for reflected XSS indicators."""
        Logger.info("Checking XSS reflection...")
        probe = "r3c0n47xss"

        for param_info in self.params[:10]:
            name = param_info.get("name", "") if isinstance(param_info, dict) else str(param_info)
            if not name:
                continue
            try:
                url = f"{self.base_url}?{name}={probe}"
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if probe in resp.text:
                    self.vulns.append({
                        "title": f"Reflected Input via '{name}' parameter",
                        "severity": "MEDIUM",
                        "source": "Custom",
                        "detail": f"Input reflected in response (potential XSS)",
                        "url": url,
                        "recommendation": "Implement output encoding and CSP"
                    })
            except Exception:
                pass

    def _check_sensitive_files(self):
        """Check for exposed sensitive files."""
        Logger.info("Checking sensitive file exposure...")
        sensitive = {
            "/.env": "Environment file",
            "/.git/HEAD": "Git repository",
            "/wp-config.php.bak": "WordPress config backup",
            "/server-status": "Apache server status",
            "/phpinfo.php": "PHP info page",
            "/.htpasswd": "Apache password file",
            "/web.config": "IIS configuration",
        }
        for path, desc in sensitive.items():
            try:
                url = f"{self.base_url}{path}"
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Verify it's not a generic error page
                    if path == "/.git/HEAD" and "ref:" in resp.text:
                        self.vulns.append({
                            "title": f"Exposed {desc}",
                            "severity": "HIGH",
                            "source": "Custom",
                            "detail": f"{desc} accessible at {path}",
                            "url": url,
                            "recommendation": f"Restrict access to {path}"
                        })
                    elif path == "/.env" and "=" in resp.text:
                        self.vulns.append({
                            "title": f"Exposed {desc}",
                            "severity": "CRITICAL",
                            "source": "Custom",
                            "detail": f"{desc} accessible at {path}",
                            "url": url,
                            "recommendation": f"Remove {path} from web root"
                        })
                    elif path == "/phpinfo.php" and "phpinfo" in resp.text.lower():
                        self.vulns.append({
                            "title": f"Exposed {desc}",
                            "severity": "MEDIUM",
                            "source": "Custom",
                            "detail": f"{desc} accessible at {path}",
                            "url": url,
                            "recommendation": f"Remove {path} from production"
                        })
            except Exception:
                pass

    def _check_missing_headers(self):
        """Convert missing security headers into vulnerability findings."""
        missing = self.headers_data.get("missing", [])
        for h in missing:
            self.vulns.append({
                "title": f"Missing Security Header: {h['header']}",
                "severity": h.get("severity", "LOW"),
                "source": "Custom",
                "detail": h.get("description", ""),
                "url": self.base_url,
                "recommendation": h.get("recommendation", "")
            })

    def _check_http_methods(self):
        """Check for dangerous HTTP methods."""
        Logger.info("Checking HTTP methods...")
        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
        try:
            resp = self.session.options(self.base_url, timeout=self.timeout, verify=False)
            allow = resp.headers.get("Allow", "")
            for method in dangerous:
                if method in allow.upper():
                    self.vulns.append({
                        "title": f"Dangerous HTTP Method Enabled: {method}",
                        "severity": "MEDIUM",
                        "source": "Custom",
                        "detail": f"HTTP {method} method is allowed. Allow: {allow}",
                        "url": self.base_url,
                        "recommendation": f"Disable {method} method on web server"
                    })
        except Exception:
            pass
