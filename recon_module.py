"""
CYBER-VISION | Module 1: The Scout (Reconnaissance)
----------------------------------------------------
Handles Nmap scanning and result parsing.
Nmap must be installed on your Windows PATH or at the default location.
----------------------------------------------------
"""

import subprocess
import re
import json
import os


class ReconScout:
    def __init__(self):
        self.nmap_path = "nmap"
        fallback = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if not self._is_nmap_available() and os.path.exists(fallback):
            self.nmap_path = fallback

    def _is_nmap_available(self):
        try:
            subprocess.run([self.nmap_path, "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False

    def quick_scan(self, target_ip):
        """Fast TCP scan of the top 100 ports."""
        print(f"[*] Starting Quick Scan on: {target_ip}")
        try:
            result = subprocess.run(
                [self.nmap_path, "-F", target_ip],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"[!] Nmap Error: {e.stderr}"
        except FileNotFoundError:
            return (
                "[!] Error: Nmap not found.\n"
                "FIX: Ensure Nmap is installed at C:\\Program Files (x86)\\Nmap"
            )

    def parse_results(self, nmap_output):
        """Parses Nmap raw output into a clean list of dicts for the AI brain."""
        pattern = r"(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)"
        matches = re.findall(pattern, nmap_output)
        return [
            {"port": m[0], "protocol": m[1], "state": m[2], "service": m[3].strip()}
            for m in matches
        ]


if __name__ == "__main__":
    scout = ReconScout()
    raw = scout.quick_scan("127.0.0.1")
    print(raw)
    print(json.dumps(scout.parse_results(raw), indent=4))