"""
CYBER-VISION v1.5 | Master GUI Application
--------------------------------------------
New in v1.5:
- Settings tab: configure AI provider + API key, saved to config.json
- ML inference live in defender dashboard (packet classification)
- Cleaned up sidebar, no proxy config
--------------------------------------------
"""

import customtkinter as ctk
import tkinter.messagebox as messagebox
import threading
import joblib
import os
import time
import json
import numpy as np

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from recon_module import ReconScout
from agent_brain import AgentBrain
from report_manager import ReportManager
from strike_module import StrikeModule

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

PROVIDERS = ["Groq", "OpenAI", "Anthropic", "Gemini"]


class CyberVisionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Cyber-Vision v1.5 | Agentic Sentinel")
        self.geometry("1200x750")

        # ── Engines ──────────────────────────────────────────────────────────
        self.scout = ReconScout()
        self.brain = AgentBrain()
        self.reporter = ReportManager()
        self.striker = StrikeModule(
            host="192.168.56.101",
            port=55553,
            username="msf",
            password="cybervision123",
            ssl=False
        )

        # ── State ─────────────────────────────────────────────────────────────
        self.is_monitoring = False
        self.model_payload = None
        self.last_scan_data = None
        self.last_ai_analysis = ""

        self._load_ai_model()
        self._build_sidebar()
        self._build_main_container()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ─── SETUP ────────────────────────────────────────────────────────────────

    def _load_ai_model(self):
        model_path = 'models/cyber_vision_v1.pkl'
        if os.path.exists(model_path):
            try:
                self.model_payload = joblib.load(model_path)
                print("[+] Defensive AI Engine loaded.")
            except Exception as e:
                print(f"[!] Model load error: {e}")
        else:
            print("[!] No model found — defensive ML disabled.")

    def _on_close(self):
        self.striker.disconnect()
        self.destroy()

    # ─── SIDEBAR ──────────────────────────────────────────────────────────────

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(self.sidebar, text="CYBER-VISION", font=("Impact", 24), text_color="#3498db").pack(pady=30)

        ctk.CTkButton(self.sidebar, text="Dashboard",   fg_color="transparent", anchor="w", command=lambda: self._show_frame("dash")).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(self.sidebar, text="AI Defender", fg_color="transparent", anchor="w", command=lambda: self._show_frame("defense")).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(self.sidebar, text="AI Attacker", fg_color="transparent", anchor="w", command=lambda: self._show_frame("attack")).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(self.sidebar, text="Settings",    fg_color="transparent", anchor="w", command=lambda: self._show_frame("settings")).pack(pady=5, padx=10, fill="x")

        self.status_light = ctk.CTkLabel(self.sidebar, text="● System Ready", text_color="#2ecc71")
        self.status_light.pack(side="bottom", pady=20)

    # ─── MAIN CONTAINER ───────────────────────────────────────────────────────

    def _build_main_container(self):
        self.container = ctk.CTkFrame(self, corner_radius=15)
        self.container.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.frames = {}
        self._build_dashboard()
        self._build_defense_frame()
        self._build_attack_frame()
        self._build_settings_frame()
        self._show_frame("dash")

    # ─── DASHBOARD ────────────────────────────────────────────────────────────

    def _build_dashboard(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        ctk.CTkLabel(f, text="AGENT TERMINAL", font=("Consolas", 32, "bold")).pack(pady=(100, 10))
        ctk.CTkLabel(f, text="Operational Status: Nominal\nEnvironment: Windows / Python 3.x", font=("Arial", 14), text_color="gray").pack()

        # Show current provider on dashboard
        provider_text = f"AI Provider: {self.brain.provider.upper()}" if self.brain.api_key else "AI Provider: Not configured — go to Settings"
        self.provider_label = ctk.CTkLabel(f, text=provider_text, font=("Arial", 12), text_color="#3498db")
        self.provider_label.pack(pady=10)

        self.frames["dash"] = f

    # ─── DEFENDER ─────────────────────────────────────────────────────────────

    def _build_defense_frame(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")

        ctrl = ctk.CTkFrame(f, fg_color="transparent")
        ctrl.pack(fill="x", padx=20, pady=10)

        self.monitor_btn = ctk.CTkButton(ctrl, text="ENABLE SENTINEL", fg_color="#2ecc71", hover_color="#27ae60", command=self._toggle_monitor)
        self.monitor_btn.pack(side="left", padx=10)

        # ML status indicator
        ml_status = "ML Inference: ACTIVE" if self.model_payload else "ML Inference: No model loaded"
        ml_color = "#2ecc71" if self.model_payload else "#e74c3c"
        ctk.CTkLabel(ctrl, text=ml_status, font=("Arial", 11), text_color=ml_color).pack(side="left", padx=15)

        self.def_log = ctk.CTkTextbox(f, width=850, height=500, font=("Consolas", 12), border_width=1)
        self.def_log.pack(padx=20, pady=10)

        self.frames["defense"] = f

    # ─── ATTACKER ─────────────────────────────────────────────────────────────

    def _build_attack_frame(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")

        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(10, 5))

        self.target_entry = ctk.CTkEntry(top, placeholder_text="Enter Target IP (e.g. 192.168.56.101)", width=280)
        self.target_entry.pack(side="left", padx=5)

        self.scan_btn = ctk.CTkButton(top, text="Launch AI Scan", command=self._run_agentic_scan)
        self.scan_btn.pack(side="left", padx=5)

        self.report_btn = ctk.CTkButton(top, text="Export Audit", fg_color="#9b59b6", state="disabled", command=self._export_report)
        self.report_btn.pack(side="left", padx=5)

        msf = ctk.CTkFrame(f, fg_color="transparent")
        msf.pack(fill="x", padx=20, pady=(0, 10))

        self.msf_connect_btn = ctk.CTkButton(msf, text="Link Metasploit RPC", fg_color="#f39c12", hover_color="#e67e22", command=self._connect_msf)
        self.msf_connect_btn.pack(side="left", padx=5)

        self.exploit_entry = ctk.CTkEntry(msf, placeholder_text="Exploit module (e.g. exploit/windows/smb/ms17_010_eternalblue)", width=380)
        self.exploit_entry.pack(side="left", padx=5)

        self.strike_btn = ctk.CTkButton(msf, text="EXECUTE STRIKE", fg_color="#e74c3c", hover_color="#c0392b", state="disabled", command=self._trigger_exploit)
        self.strike_btn.pack(side="left", padx=5)

        self.progress_bar = ctk.CTkProgressBar(f, width=800)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)

        self.atk_log = ctk.CTkTextbox(f, width=850, height=400, font=("Consolas", 12), border_width=1)
        self.atk_log.pack(padx=20, pady=10)

        self.frames["attack"] = f

    # ─── SETTINGS ─────────────────────────────────────────────────────────────

    def _build_settings_frame(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")

        ctk.CTkLabel(f, text="AI PROVIDER SETTINGS", font=("Consolas", 22, "bold")).pack(pady=(40, 5))
        ctk.CTkLabel(f, text="Configure your AI provider and API key. Settings are saved locally.", font=("Arial", 12), text_color="gray").pack(pady=(0, 30))

        # Provider selector
        ctk.CTkLabel(f, text="Select Provider:", font=("Arial", 13, "bold")).pack(anchor="w", padx=120)
        self.provider_var = ctk.StringVar(value=self.brain.provider.capitalize() if self.brain.provider else "Groq")
        self.provider_dropdown = ctk.CTkOptionMenu(f, values=PROVIDERS, variable=self.provider_var, width=300, command=self._on_provider_change)
        self.provider_dropdown.pack(pady=5, padx=120, anchor="w")

        # Model hint label
        self.model_hint = ctk.CTkLabel(f, text=self._get_model_hint(self.provider_var.get()), font=("Arial", 11), text_color="#3498db")
        self.model_hint.pack(anchor="w", padx=120)

        # API key input
        ctk.CTkLabel(f, text="API Key:", font=("Arial", 13, "bold")).pack(anchor="w", padx=120, pady=(20, 0))
        self.api_key_entry = ctk.CTkEntry(f, placeholder_text="Paste your API key here", width=500, show="*")
        self.api_key_entry.pack(pady=5, padx=120, anchor="w")

        # Show/hide key toggle
        self.show_key_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(f, text="Show key", variable=self.show_key_var, command=self._toggle_key_visibility).pack(anchor="w", padx=120)

        # Pre-fill if key exists
        if self.brain.api_key:
            self.api_key_entry.insert(0, self.brain.api_key)

        # Where to get key links
        self.key_link = ctk.CTkLabel(f, text=self._get_key_link(self.provider_var.get()), font=("Arial", 11), text_color="gray")
        self.key_link.pack(anchor="w", padx=120, pady=(5, 20))

        # Save button
        self.save_btn = ctk.CTkButton(f, text="Save & Apply", width=200, fg_color="#2ecc71", hover_color="#27ae60", command=self._save_settings)
        self.save_btn.pack(pady=10, padx=120, anchor="w")

        self.settings_status = ctk.CTkLabel(f, text="", font=("Arial", 12))
        self.settings_status.pack(anchor="w", padx=120)

        self.frames["settings"] = f

    def _get_model_hint(self, provider):
        hints = {
            "Groq": "Model: llama-3.3-70b-versatile (fast & free)",
            "OpenAI": "Model: gpt-4o-mini",
            "Anthropic": "Model: claude-sonnet-4-6",
            "Gemini": "Model: gemini-2.0-flash"
        }
        return hints.get(provider, "")

    def _get_key_link(self, provider):
        links = {
            "Groq": "Get free key at: console.groq.com",
            "OpenAI": "Get key at: platform.openai.com/api-keys",
            "Anthropic": "Get key at: console.anthropic.com",
            "Gemini": "Get key at: aistudio.google.com/app/apikey"
        }
        return links.get(provider, "")

    def _on_provider_change(self, choice):
        self.model_hint.configure(text=self._get_model_hint(choice))
        self.key_link.configure(text=self._get_key_link(choice))

    def _toggle_key_visibility(self):
        self.api_key_entry.configure(show="" if self.show_key_var.get() else "*")

    def _save_settings(self):
        provider = self.provider_var.get().lower()
        api_key = self.api_key_entry.get().strip()

        if not api_key:
            self.settings_status.configure(text="⚠ API key cannot be empty.", text_color="#e74c3c")
            return

        success = self.brain.save_config(provider, api_key)
        if success:
            self.settings_status.configure(text="✓ Settings saved successfully!", text_color="#2ecc71")
            # Update dashboard provider label
            self.provider_label.configure(text=f"AI Provider: {provider.upper()}")
        else:
            self.settings_status.configure(text="✗ Failed to save settings.", text_color="#e74c3c")

    # ─── HELPERS ──────────────────────────────────────────────────────────────

    def _show_frame(self, name):
        for frame in self.frames.values():
            frame.grid_forget()
        self.frames[name].grid(row=0, column=0, sticky="nsew")

    def _log_atk(self, text):
        self.after(0, lambda: self.atk_log.insert("end", text))
        self.after(0, self.atk_log.see, "end")

    def _log_def(self, text):
        self.after(0, lambda: self.def_log.insert("end", text))
        self.after(0, self.def_log.see, "end")

    # ─── ML INFERENCE ─────────────────────────────────────────────────────────

    def _run_ml_inference(self, pkt):
        if not self.model_payload:
            return "NO_MODEL"
        try:
            model = self.model_payload.get("model")
            scaler = self.model_payload.get("scaler")
            classes = self.model_payload.get("class_names", {
                0: "BENIGN", 1: "DDOS", 2: "BRUTE_FORCE",
                3: "DOS", 4: "PORT_SCAN", 5: "BOT",
                6: "WEB_ATTACK", 7: "INFILTRATION"
            })

            # 5 features matching training columns:
            # Destination Port, Flow Duration, Total Fwd Packets,
            # Total Backward Packets, Packet Length Mean
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            pkt_len = len(pkt)
            fwd_pkts = 1
            bwd_pkts = 0
            pkt_mean = pkt_len

            features = np.array([[dst_port, pkt_len, fwd_pkts, bwd_pkts, pkt_mean]])

            if scaler:
                features = scaler.transform(features)

            prediction = model.predict(features)[0]
            return classes.get(int(prediction), str(prediction))

        except Exception:
            return "UNKNOWN"

    # ─── DEFENDER LOGIC ───────────────────────────────────────────────────────

    def _toggle_monitor(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_btn.configure(text="DISABLE SENTINEL", fg_color="#e74c3c")
            self.status_light.configure(text="● Sentinel Active", text_color="#e74c3c")
            threading.Thread(target=self._sniff_traffic, daemon=True).start()
        else:
            self.is_monitoring = False
            self.monitor_btn.configure(text="ENABLE SENTINEL", fg_color="#2ecc71")
            self.status_light.configure(text="● System Ready", text_color="#2ecc71")

    def _sniff_traffic(self):
        def handler(pkt):
            if self.is_monitoring and pkt.haslayer(IP):
                ts = time.strftime("%H:%M:%S")
                prediction = self._run_ml_inference(pkt)

                # Color-code by threat level
                if prediction in ["DDOS", "BRUTE_FORCE", "BOT", "INFILTRATION"]:
                    tag = f"[⚠ {prediction}]"
                elif prediction == "PORT_SCAN":
                    tag = f"[~ {prediction}]"
                else:
                    tag = f"[✓ {prediction}]"

                entry = f"[{ts}] {tag} {pkt[IP].src} → {pkt[IP].dst} | {pkt.summary()[:35]}\n"
                self._log_def(entry)

        sniff(prn=handler, store=0, timeout=1, stop_filter=lambda x: not self.is_monitoring)

    # ─── ATTACKER LOGIC ───────────────────────────────────────────────────────

    def _run_agentic_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            self._log_atk("[!] ERROR: Enter a target IP first.\n")
            return

        self.scan_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.after(0, lambda: self.progress_bar.set(0.2))
        self._log_atk(f"\n[*] RECON STARTED: {target}\n" + "-" * 50 + "\n")

        def task():
            raw = self.scout.quick_scan(target)
            self.last_scan_data = self.scout.parse_results(raw)
            self.after(0, lambda: self.progress_bar.set(0.5))
            self._log_atk(f"[+] Found {len(self.last_scan_data)} active services.\n")
            self._log_atk(f"[*] Sending to {self.brain.provider.upper()} for analysis...\n")

            self.last_ai_analysis = self.brain.analyze_scan(self.last_scan_data)
            self.after(0, lambda: self.progress_bar.set(1.0))
            self._log_atk("\n" + self.last_ai_analysis + "\n")
            self._log_atk("[+] Analysis complete. Ready to export.\n")

            self.after(0, lambda: self.scan_btn.configure(state="normal"))
            self.after(0, lambda: self.report_btn.configure(state="normal"))

        threading.Thread(target=task, daemon=True).start()

    def _export_report(self):
        target = self.target_entry.get().strip()
        if not self.last_scan_data:
            return
        path = self.reporter.generate_report(target, self.last_scan_data, self.last_ai_analysis)
        if path:
            self._log_atk(f"\n[+] Audit saved: {path}\n")

    def _connect_msf(self):
        self._log_atk("\n[*] Connecting to Metasploit RPC...\n")

        def task():
            if self.striker.connect():
                self._log_atk("[+] Metasploit RPC linked successfully!\n")
                self.after(0, lambda: self.msf_connect_btn.configure(text="MSF Connected", fg_color="#27ae60", state="disabled"))
                self.after(0, lambda: self.strike_btn.configure(state="normal"))
            else:
                self._log_atk("[!] Connection failed.\nMake sure msfrpcd is running:\n  msfrpcd -U msf -P cybervision123 -p 55553 -S -f\n")

        threading.Thread(target=task, daemon=True).start()

    def _trigger_exploit(self):
        target = self.target_entry.get().strip()
        exploit = self.exploit_entry.get().strip()

        if not target or not exploit:
            self._log_atk("[!] Enter both a target IP and exploit module name.\n")
            return

        confirmed = messagebox.askyesno(
            "SAFETY GUARDRAIL",
            f"You are about to launch an active exploit.\n\n"
            f"TARGET:  {target}\n"
            f"MODULE:  {exploit}\n\n"
            f"Do you have explicit written authorization to test this target?",
            icon="warning"
        )

        if confirmed:
            self._log_atk(f"\n[!] Guardrail passed. Launching {exploit} → {target}...\n")
            self.after(0, lambda: self.progress_bar.set(0.8))

            def run():
                result = self.striker.launch_exploit_with_guardrail(target, exploit)
                self._log_atk(f"{result}\n")
                self.after(0, lambda: self.progress_bar.set(1.0))

            threading.Thread(target=run, daemon=True).start()
        else:
            self._log_atk("[*] Strike aborted by user.\n")


if __name__ == "__main__":
    app = CyberVisionApp()
    app.mainloop()