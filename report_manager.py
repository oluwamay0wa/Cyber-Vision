"""
CYBER-VISION | Module 4: Report Manager
----------------------------------------
Generates professional security audit reports as .txt files.
Saved to the /reports directory automatically.
----------------------------------------
"""

import datetime
import os
import json


class ReportManager:
    def __init__(self, base_dir="reports"):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def _calculate_risk_level(self, scan_data):
        """Heuristic risk scoring based on port criticality."""
        critical_ports = {"445", "139", "3389", "21"}
        score = 0
        if isinstance(scan_data, list):
            for item in scan_data:
                score += 3 if str(item.get('port')) in critical_ports else 1
        if score >= 5:
            return "CRITICAL"
        if score >= 2:
            return "MEDIUM"
        return "LOW"

    def generate_report(self, target: str, scan_data, ai_analysis: str) -> Optional[str]:
        """Saves a formatted audit report and returns the file path."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        sanitized = target.replace(".", "-").replace(":", "_")
        filepath = os.path.join(self.base_dir, f"Audit_{sanitized}_{timestamp}.txt")
        risk = self._calculate_risk_level(scan_data)
        scan_display = json.dumps(scan_data, indent=4) if isinstance(scan_data, (list, dict)) else str(scan_data)

        report = f"""
================================================================================
                    CYBER-VISION SECURITY AUDIT REPORT
================================================================================
Report ID:    {timestamp}
Target Host:  {target}
Risk Level:   {risk}
Generated:    {datetime.datetime.now().strftime("%A, %B %d, %Y - %I:%M %p")}
Tool:         Cyber-Vision v1.4

--------------------------------------------------------------------------------
[SECTION 1] RECONNAISSANCE SUMMARY
--------------------------------------------------------------------------------
{scan_display}

--------------------------------------------------------------------------------
[SECTION 2] AI VULNERABILITY ANALYSIS
--------------------------------------------------------------------------------
{ai_analysis}

--------------------------------------------------------------------------------
[SECTION 3] RECOMMENDATIONS
--------------------------------------------------------------------------------
1. Review all CRITICAL/HIGH ports immediately (445, 139, 3389, 21).
2. Apply Metasploit modules listed in Section 2 for verification.
3. Patch confirmed vulnerabilities before re-testing.

================================================================================
DISCLAIMER: For authorized security testing only.
================================================================================
""".strip()

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"[+] Report saved: {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Failed to write report: {e}")
            return None


if __name__ == "__main__":
    mgr = ReportManager()
    path = mgr.generate_report(
        "127.0.0.1",
        [{"port": "445", "service": "microsoft-ds", "state": "open"}],
        "Potential EternalBlue vulnerability detected on SMB port 445."
    )
    if path:
        print(f"Report at: {path}")