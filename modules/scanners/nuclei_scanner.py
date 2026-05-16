"""
Recon47 - Nuclei Scanner Integration
Author: Xaff
Wraps the Nuclei CLI tool and parses its JSON output.
"""

import os
import json
import subprocess
import shutil
from core.logger import Logger


class NucleiScanner:
    """Integrates with ProjectDiscovery Nuclei scanner."""

    def __init__(self, target_url, output_dir):
        self.target_url = target_url
        self.output_dir = output_dir
        self.nuclei_path = shutil.which("nuclei")

    def run(self):
        """Run Nuclei scan and return parsed results."""
        if not self.nuclei_path:
            Logger.warning("Nuclei not found in PATH. Skipping Nuclei scan.")
            Logger.info("Install: https://github.com/projectdiscovery/nuclei")
            return []

        Logger.info(f"Running Nuclei against {self.target_url}...")
        output_file = os.path.join(self.output_dir, "nuclei_output.jsonl")

        try:
            cmd = [
                self.nuclei_path,
                "-u", self.target_url,
                "-jsonl",
                "-o", output_file,
                "-silent",
                "-timeout", "10",
                "-rate-limit", "50",
                "-severity", "info,low,medium,high,critical"
            ]
            process = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )

            if os.path.exists(output_file):
                return self._parse_output(output_file)
            return self._parse_stdout(process.stdout)
        except subprocess.TimeoutExpired:
            Logger.warning("Nuclei scan timed out after 10 minutes")
            if os.path.exists(output_file):
                return self._parse_output(output_file)
        except Exception as e:
            Logger.error(f"Nuclei execution error: {e}")
        return []

    def _parse_output(self, filepath):
        """Parse Nuclei JSONL output."""
        vulns = []
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        info = item.get("info", {})
                        vuln = {
                            "title": info.get("name", item.get("template-id", "Nuclei Finding")),
                            "severity": info.get("severity", "info").upper(),
                            "source": "Nuclei",
                            "detail": info.get("description", ""),
                            "url": item.get("matched-at", item.get("host", self.target_url)),
                            "template": item.get("template-id", ""),
                            "tags": info.get("tags", []),
                            "reference": info.get("reference", []),
                            "matcher_name": item.get("matcher-name", ""),
                            "curl_command": item.get("curl-command", "")
                        }
                        vulns.append(vuln)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            Logger.warning(f"Failed to parse Nuclei output: {e}")
        return vulns

    def _parse_stdout(self, stdout):
        """Parse Nuclei stdout as fallback."""
        vulns = []
        if not stdout:
            return vulns
        for line in stdout.strip().split("\n"):
            if line.strip():
                vulns.append({
                    "title": line.strip(),
                    "severity": "INFO",
                    "source": "Nuclei",
                    "detail": line.strip(),
                    "url": self.target_url
                })
        return vulns
