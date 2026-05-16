"""
Recon47 - Nikto Scanner Integration
Author: Xaff
Wraps the Nikto CLI tool and parses its output.
"""

import os
import json
import subprocess
import shutil
from core.logger import Logger


class NiktoScanner:
    """Integrates with Nikto web server scanner."""

    def __init__(self, target_url, output_dir):
        self.target_url = target_url
        self.output_dir = output_dir
        self.nikto_path = shutil.which("nikto")

    def run(self):
        """Run Nikto scan and return parsed results."""
        if not self.nikto_path:
            Logger.warning("Nikto not found in PATH. Skipping Nikto scan.")
            Logger.info("Install Nikto: https://github.com/sullo/nikto")
            return []

        Logger.info(f"Running Nikto against {self.target_url}...")
        output_file = os.path.join(self.output_dir, "nikto_output.json")

        try:
            cmd = [
                self.nikto_path,
                "-h", self.target_url,
                "-Format", "json",
                "-output", output_file,
                "-Tuning", "123456789",
                "-maxtime", "300",
                "-nointeractive"
            ]
            process = subprocess.run(
                cmd, capture_output=True, text=True, timeout=360
            )

            if os.path.exists(output_file):
                return self._parse_output(output_file)
            else:
                # Try parsing stdout
                return self._parse_stdout(process.stdout)
        except subprocess.TimeoutExpired:
            Logger.warning("Nikto scan timed out after 6 minutes")
            if os.path.exists(output_file):
                return self._parse_output(output_file)
        except Exception as e:
            Logger.error(f"Nikto execution error: {e}")
        return []

    def _parse_output(self, filepath):
        """Parse Nikto JSON output file."""
        vulns = []
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            if isinstance(data, dict):
                items = data.get("vulnerabilities", [])
                if not items:
                    # Nikto format varies
                    for key in data:
                        if isinstance(data[key], list):
                            items = data[key]
                            break
            elif isinstance(data, list):
                items = data
            else:
                return vulns

            for item in items:
                vuln = {
                    "title": item.get("msg", item.get("description", "Nikto Finding")),
                    "severity": self._map_severity(item.get("osvdbid", "")),
                    "source": "Nikto",
                    "detail": item.get("msg", ""),
                    "url": item.get("url", self.target_url),
                    "method": item.get("method", "GET"),
                    "osvdb": item.get("osvdbid", "")
                }
                vulns.append(vuln)
        except Exception as e:
            Logger.warning(f"Failed to parse Nikto output: {e}")
        return vulns

    def _parse_stdout(self, stdout):
        """Parse Nikto stdout as fallback."""
        vulns = []
        if not stdout:
            return vulns
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("+ ") and ":" in line:
                vulns.append({
                    "title": line[2:].strip(),
                    "severity": "MEDIUM",
                    "source": "Nikto",
                    "detail": line,
                    "url": self.target_url
                })
        return vulns

    @staticmethod
    def _map_severity(osvdb_id):
        """Map OSVDB ID presence to severity level."""
        if osvdb_id and str(osvdb_id) != "0":
            return "MEDIUM"
        return "INFO"
