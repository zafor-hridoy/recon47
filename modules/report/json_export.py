"""
Recon47 - JSON Export Module
Author: Xaff
Exports scan results to structured JSON format.
"""

import json
from datetime import datetime


class JSONExporter:
    """Exports scan results to a structured JSON file."""

    def __init__(self, results, output_path):
        self.results = results
        self.output_path = output_path

    def export(self):
        """Write results to JSON file."""
        output = {
            "meta": self.results.get("meta", {}),
            "target": self._clean_target(self.results.get("target", {})),
            "reconnaissance": self._clean_recon(self.results.get("recon", {})),
            "crawler": self._clean_crawler(self.results.get("crawler", {})),
            "vulnerabilities": self.results.get("vulnerabilities", []),
            "statistics": self.results.get("statistics", {}),
            "exported_at": datetime.now().isoformat()
        }
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str, ensure_ascii=False)

    @staticmethod
    def _clean_target(target):
        return {k: v for k, v in target.items() if v is not None}

    @staticmethod
    def _clean_recon(recon):
        cleaned = {}
        for key, value in recon.items():
            if isinstance(value, list):
                cleaned[key] = value
            elif isinstance(value, dict):
                cleaned[key] = {k: v for k, v in value.items() if v}
            else:
                cleaned[key] = value
        return cleaned

    @staticmethod
    def _clean_crawler(crawler):
        return {k: v for k, v in crawler.items() if v}
