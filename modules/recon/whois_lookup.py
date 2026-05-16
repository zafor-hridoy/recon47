"""
Recon47 - WHOIS Lookup Module
Author: Xaff
Retrieves WHOIS registration data for a target domain.
"""

import whois
from core.logger import Logger


class WhoisLookup:
    """Domain WHOIS information retrieval."""

    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout

    def run(self):
        results = {}
        try:
            w = whois.whois(self.domain)
            results = {
                "domain_name": self._clean(w.domain_name),
                "registrar": self._clean(w.registrar),
                "creation_date": str(self._clean(w.creation_date)),
                "expiration_date": str(self._clean(w.expiration_date)),
                "updated_date": str(self._clean(w.updated_date)),
                "name_servers": self._clean(w.name_servers) or [],
                "status": self._clean(w.status) or [],
                "emails": self._clean(w.emails) or [],
                "org": self._clean(w.org),
                "country": self._clean(w.country),
                "state": self._clean(w.state),
                "city": self._clean(w.city),
            }
            self._display(results)
        except Exception as e:
            Logger.warning(f"WHOIS lookup failed: {e}")
        return results

    @staticmethod
    def _clean(value):
        if isinstance(value, list):
            return value[0] if len(value) == 1 else value
        return value

    def _display(self, results):
        display = {}
        for k, v in results.items():
            if v and v != "None":
                key = k.replace("_", " ").title()
                val = str(v) if not isinstance(v, list) else ", ".join(str(x) for x in v[:5])
                display[key] = val[:80]
        if display:
            Logger.summary_panel("WHOIS Information", display)
