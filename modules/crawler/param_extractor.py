"""
Recon47 - Parameter Extractor Module
Author: Xaff
Extracts URL query parameters and form fields from crawled data.
"""

from urllib.parse import urlparse, parse_qs
from core.logger import Logger


class ParamExtractor:
    """Extracts and deduplicates parameters from URLs and forms."""

    def __init__(self, urls, forms):
        self.urls = urls or []
        self.forms = forms or []
        self.parameters = {}

    def run(self):
        """Extract parameters and return deduplicated list."""
        self._extract_url_params()
        self._extract_form_params()

        results = []
        for name, info in self.parameters.items():
            results.append({
                "name": name,
                "sources": list(info["sources"]),
                "methods": list(info["methods"]),
                "sample_values": list(info["values"])[:3]
            })

        results.sort(key=lambda x: x["name"])

        if results:
            rows = [(p["name"], ", ".join(p["sources"]), ", ".join(p["methods"]))
                    for p in results[:20]]
            Logger.table("Extracted Parameters",
                         ["Parameter", "Source", "Methods"], rows)
            if len(results) > 20:
                Logger.info(f"... and {len(results) - 20} more parameters")

        return results

    def _extract_url_params(self):
        """Extract query parameters from URLs."""
        for url in self.urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for name, values in params.items():
                    self._add_param(name, "URL", "GET", values)
            except Exception:
                pass

    def _extract_form_params(self):
        """Extract parameters from discovered forms."""
        for form in self.forms:
            method = form.get("method", "GET")
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                if name:
                    value = inp.get("value", "")
                    self._add_param(name, "Form", method, [value] if value else [])

    def _add_param(self, name, source, method, values):
        """Add a parameter to the collection."""
        if not name:
            return
        if name not in self.parameters:
            self.parameters[name] = {"sources": set(), "methods": set(), "values": set()}
        self.parameters[name]["sources"].add(source)
        self.parameters[name]["methods"].add(method)
        for v in values:
            if v:
                self.parameters[name]["values"].add(v)
