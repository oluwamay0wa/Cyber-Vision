"""
CYBER-VISION | Module 2: The Agentic Brain
-------------------------------------------
Supports multiple AI providers: Groq, OpenAI, Anthropic, Gemini.
Provider and API key are loaded from config.json at runtime.
Falls back to local rule-based engine if API is unreachable.
-------------------------------------------
"""

import requests
import json
import os

CONFIG_PATH = "config.json"


class AgentBrain:
    def __init__(self):
        self.provider = "groq"
        self.api_key = ""
        self._load_config()

    # ─── CONFIG ───────────────────────────────────────────────────────────────

    def _load_config(self):
        """Loads provider and API key from config.json."""
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r") as f:
                    config = json.load(f)
                self.provider = config.get("provider", "groq").lower()
                self.api_key = config.get("api_key", "")
                print(f"[+] AI Brain loaded: provider={self.provider}")
            except Exception as e:
                print(f"[!] Failed to load config: {e}")
        else:
            print("[!] No config.json found. Configure API key in Settings.")

    def save_config(self, provider: str, api_key: str):
        """Saves provider and API key to config.json."""
        self.provider = provider.lower()
        self.api_key = api_key
        try:
            with open(CONFIG_PATH, "w") as f:
                json.dump({"provider": self.provider, "api_key": self.api_key}, f, indent=4)
            print(f"[+] Config saved: provider={self.provider}")
            return True
        except Exception as e:
            print(f"[!] Failed to save config: {e}")
            return False

    # ─── ROUTING ──────────────────────────────────────────────────────────────

    def analyze_scan(self, scan_results):
        """Routes to the correct provider based on config."""
        if not self.api_key:
            return self._local_expert_logic(scan_results, reason="No API key configured — go to Settings.")

        print(f"[*] Dispatching to {self.provider.upper()}...")

        try:
            if self.provider == "groq":
                return self._call_groq(scan_results)
            elif self.provider == "openai":
                return self._call_openai(scan_results)
            elif self.provider == "anthropic":
                return self._call_anthropic(scan_results)
            elif self.provider == "gemini":
                return self._call_gemini(scan_results)
            else:
                return self._local_expert_logic(scan_results, reason=f"Unknown provider: {self.provider}")
        except Exception as e:
            print(f"[!] Provider call failed: {e}")
            return self._local_expert_logic(scan_results, reason=str(e))

    # ─── PROVIDERS ────────────────────────────────────────────────────────────

    def _system_prompt(self):
        return (
            "You are an Elite Cyber Security Researcher. "
            "Analyze the provided JSON port scan data. "
            "Identify vulnerabilities and provide the exact Metasploit module path for each finding. "
            "Be concise and structured."
        )

    def _call_groq(self, scan_results):
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "max_tokens": 1024,
                "temperature": 0.7,
                "messages": [
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": f"Scan Data: {json.dumps(scan_results)}"}
                ]
            },
            timeout=20
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        raise Exception(f"Groq HTTP {response.status_code}: {response.json().get('error', {}).get('message', '')}")

    def _call_openai(self, scan_results):
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": "gpt-4o-mini",
                "max_tokens": 1024,
                "messages": [
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": f"Scan Data: {json.dumps(scan_results)}"}
                ]
            },
            timeout=20
        )
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        raise Exception(f"OpenAI HTTP {response.status_code}: {response.json().get('error', {}).get('message', '')}")

    def _call_anthropic(self, scan_results):
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 1024,
                "system": self._system_prompt(),
                "messages": [
                    {"role": "user", "content": f"Scan Data: {json.dumps(scan_results)}"}
                ]
            },
            timeout=20
        )
        if response.status_code == 200:
            return response.json()["content"][0]["text"]
        raise Exception(f"Anthropic HTTP {response.status_code}: {response.json().get('error', {}).get('message', '')}")

    def _call_gemini(self, scan_results):
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={self.api_key}",
            headers={"Content-Type": "application/json"},
            json={
                "contents": [{
                    "parts": [{"text": f"{self._system_prompt()}\n\nScan Data: {json.dumps(scan_results)}"}]
                }],
                "generationConfig": {"temperature": 0.7, "maxOutputTokens": 1024}
            },
            timeout=20
        )
        if response.status_code == 200:
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        raise Exception(f"Gemini HTTP {response.status_code}: {response.json().get('error', {}).get('message', '')}")

    # ─── FALLBACK ─────────────────────────────────────────────────────────────

    def _local_expert_logic(self, scan_results, reason=""):
        report = "--- CYBER-VISION SECURITY REPORT (Local Expert Mode) ---\n"
        report += f"[Diagnostic: {reason}]\n"
        report += "=" * 55 + "\n"

        for item in scan_results:
            p = str(item.get('port'))
            svc = item.get('service', 'unknown').upper()

            if p == "445":
                report += f"PORT 445 [{svc}]: CRITICAL\n- Risk: EternalBlue / DoublePulsar\n- Module: exploit/windows/smb/ms17_010_eternalblue\n"
            elif p == "21":
                report += f"PORT 21 [{svc}]: HIGH\n- Risk: Anonymous Login / Cleartext\n- Module: auxiliary/scanner/ftp/ftp_login\n"
            elif p in ["80", "443"]:
                report += f"PORT {p} [{svc}]: MEDIUM\n- Risk: Web Service Exposed\n- Module: auxiliary/scanner/http/http_version\n"
            elif p == "3389":
                report += f"PORT 3389 [{svc}]: HIGH\n- Risk: RDP Exposed\n- Module: auxiliary/scanner/rdp/rdp_scanner\n"
            elif p == "22":
                report += f"PORT 22 [{svc}]: MEDIUM\n- Risk: SSH Brute Force\n- Module: auxiliary/scanner/ssh/ssh_login\n"
            else:
                report += f"PORT {p} [{svc}]: INFO\n- Action: Perform OS fingerprinting (-O)\n"
            report += "-" * 30 + "\n"

        return report + "\n[!] Status: Cloud offline. Using Local Signature database."


if __name__ == "__main__":
    brain = AgentBrain()
    mock_scan = [{"port": "445", "service": "microsoft-ds"}, {"port": "22", "service": "ssh"}]
    print(brain.analyze_scan(mock_scan))