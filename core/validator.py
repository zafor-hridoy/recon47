"""
Recon47 - Input Validator Module
Author: Xaff
Validates and normalizes target input (domain, IP, URL).
"""

import re
import socket
from urllib.parse import urlparse


class TargetValidator:
    """Validates and normalizes scan target input."""

    def __init__(self, raw_target):
        self.raw = raw_target.strip()
        self.domain = None
        self.ip = None
        self.url = None
        self.scheme = "https"
        self.port = None
        self.target_type = None  # 'domain', 'ip', 'url'

    def validate(self):
        """
        Validate the raw target string and extract components.
        Returns True if valid, raises ValueError otherwise.
        """
        if not self.raw:
            raise ValueError("Target cannot be empty.")

        # Check if it's a full URL
        if re.match(r'^https?://', self.raw, re.IGNORECASE):
            return self._parse_url(self.raw)

        # Check if it's an IP address
        if self._is_ip(self.raw):
            self.ip = self.raw
            self.domain = self.raw
            self.url = f"http://{self.raw}"
            self.scheme = "http"
            self.target_type = "ip"
            return True

        # Check if it's an IP:port
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}:\d+$', self.raw):
            parts = self.raw.split(':')
            if self._is_ip(parts[0]):
                self.ip = parts[0]
                self.domain = parts[0]
                self.port = int(parts[1])
                self.url = f"http://{self.raw}"
                self.scheme = "http"
                self.target_type = "ip"
                return True

        # Check if it's a domain
        if self._is_domain(self.raw):
            self.domain = self.raw.lower()
            self.url = f"https://{self.domain}"
            self.target_type = "domain"
            # Try to resolve domain to IP
            try:
                self.ip = socket.gethostbyname(self.domain)
            except socket.gaierror:
                self.ip = None
            return True

        # Try adding https:// and parsing
        test_url = f"https://{self.raw}"
        parsed = urlparse(test_url)
        if parsed.hostname and self._is_domain(parsed.hostname):
            return self._parse_url(test_url)

        raise ValueError(
            f"Invalid target: '{self.raw}'. "
            f"Please provide a valid domain, IP address, or URL."
        )

    def _parse_url(self, url):
        """Parse a full URL and extract components."""
        parsed = urlparse(url)
        self.scheme = parsed.scheme or "https"
        self.domain = parsed.hostname
        self.port = parsed.port
        self.url = f"{self.scheme}://{self.domain}"
        if self.port:
            self.url += f":{self.port}"
        self.target_type = "url"

        if self._is_ip(self.domain):
            self.ip = self.domain
            self.target_type = "ip"
        else:
            try:
                self.ip = socket.gethostbyname(self.domain)
            except socket.gaierror:
                self.ip = None

        return True

    @staticmethod
    def _is_ip(value):
        """Check if a string is a valid IPv4 address."""
        try:
            socket.inet_aton(value)
            parts = value.split('.')
            return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
        except (socket.error, ValueError):
            return False

    @staticmethod
    def _is_domain(value):
        """Check if a string is a valid domain name."""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, value))

    def get_info(self):
        """Return a dictionary of validated target information."""
        return {
            "raw_input": self.raw,
            "domain": self.domain,
            "ip": self.ip,
            "url": self.url,
            "scheme": self.scheme,
            "port": self.port,
            "target_type": self.target_type
        }

    def get_base_url(self):
        """Return the base URL for crawling/scanning."""
        if self.port:
            return f"{self.scheme}://{self.domain}:{self.port}"
        return f"{self.scheme}://{self.domain}"
