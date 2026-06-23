# Cyber-Vision 🛡️⚔️

> An intelligent, unified **Purple Team** cybersecurity platform that bridges defensive ML traffic analysis with offensive Metasploit-powered exploitation — all from a single desktop application.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What is Cyber-Vision?

Cyber-Vision is a desktop security research tool that unifies two traditionally separate disciplines:

- **Blue Team (Defense):** Real-time network packet sniffing with live ML-powered threat classification
- **Red Team (Offense):** Automated reconnaissance, AI vulnerability analysis, and Metasploit RPC exploitation

Unlike single-purpose tools, Cyber-Vision lets a security researcher run both operations simultaneously from one interface.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Windows Host (Cyber-Vision GUI)         │
│                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ AI Defender │  │ AI Attacker │  │  Settings   │ │
│  │  (Scapy +   │  │ (Nmap +     │  │  (Provider  │ │
│  │  ML Model)  │  │  Groq/GPT)  │  │   Config)   │ │
│  └─────────────┘  └──────┬──────┘  └─────────────┘ │
└─────────────────────────┼───────────────────────────┘
                           │ TCP:55553 (RPC)
┌─────────────────────────▼───────────────────────────┐
│              Kali Linux VM (Attack Node)             │
│                   msfrpcd daemon                     │
└─────────────────────────────────────────────────────┘
                           │
┌─────────────────────────▼───────────────────────────┐
│          Target VM (e.g. Metasploitable 2)           │
└─────────────────────────────────────────────────────┘
```

---

## Features

### 🔵 AI Defender
- Live packet capture using Scapy + Npcap
- Real-time ML classification on every packet using a trained Random Forest model
- Threat labels: `BENIGN`, `DDOS`, `BRUTE_FORCE`, `DOS`, `PORT_SCAN`, `BOT`, `INFILTRATION`
- Trained on the CIC-IDS2016/2017 dataset (2.8M+ network flow records)

### 🔴 AI Attacker
- Automated Nmap reconnaissance (top 100 ports)
- AI-powered vulnerability analysis via configurable LLM provider
- Metasploit RPC integration for exploit execution
- Safety guardrail — hard blocks any exploit against public/external IPs
- Professional audit report export

### ⚙️ Settings
- Configure AI provider: **Groq**, **OpenAI**, **Anthropic**, or **Gemini**
- API key stored locally in `config.json` (never leaves your machine)

---

## Tech Stack

| Component | Technology |
|---|---|
| GUI | CustomTkinter |
| Packet Capture | Scapy + Npcap |
| ML Model | scikit-learn Random Forest |
| Reconnaissance | Nmap (subprocess) |
| AI Analysis | Groq / OpenAI / Anthropic / Gemini |
| Exploitation | pymetasploit3 (Metasploit RPC) |
| Reporting | Python standard library |

---

## Prerequisites

### Windows Host
```
Python 3.10+
Nmap (https://nmap.org/download.html)
Npcap (https://npcap.com) — for packet capture
```

### Kali Linux VM (VirtualBox/VMware)
```
Metasploit Framework
Network adapter: Host-Only
```

### Python Dependencies
```bash
pip install customtkinter scapy joblib numpy pymetasploit3 requests scikit-learn pandas
```

---

## Setup & Usage

### 1. Start Metasploit RPC on Kali
```bash
msfrpcd -U msf -P cybervision123 -p 55553 -S -f
```

### 2. Configure your AI provider
Launch the app → **Settings** tab → select provider → paste API key → Save.

Free API keys:
- **Groq** (recommended, fast & free): [console.groq.com](https://console.groq.com)
- **OpenAI**: [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- **Anthropic**: [console.anthropic.com](https://console.anthropic.com)
- **Gemini**: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

### 3. Run the app
```bash
python cyber_vision_v1.py
```

### 4. Full attack workflow
1. Go to **AI Attacker** tab
2. Enter target IP (must be a private/local network IP)
3. Click **Launch AI Scan** — Nmap scans, AI analyzes vulnerabilities
4. Click **Link Metasploit RPC** — connects to your Kali VM
5. Paste an exploit module from the AI output into the exploit field
6. Click **Execute Strike** → confirm the safety guardrail popup

### 5. Defender workflow
1. Go to **AI Defender** tab
2. Click **Enable Sentinel**
3. Watch live packets classified in real time

---

## ML Model

The defensive model is a Random Forest classifier trained on CIC-IDS2016/2017 data.

To retrain on your own data:
```bash
# Place CSV files in data/ folder
python prepare_ai_data.py   # cleans, encodes, balances dataset
python train_model.py        # trains and saves models/cyber_vision_v1.pkl
```

**Training results (current model):**
- Overall accuracy: 98.92%
- Dataset: 2.8M+ network flow records
- Classes: BENIGN, DDOS, BRUTE_FORCE, DOS, PORT_SCAN, BOT, INFILTRATION

---

## Project Structure

```
CyberVision/
├── cyber_vision_v1.py      # Master GUI application
├── agent_brain.py          # Multi-provider AI analysis engine
├── recon_module.py         # Nmap subprocess wrapper
├── strike_module.py        # Metasploit RPC controller
├── report_manager.py       # Audit report generator
├── prepare_ai_data.py      # Dataset cleaning & preparation
├── train_model.py          # Random Forest training pipeline
├── models/                 # Trained model files (not tracked by git)
├── reports/                # Generated audit reports (not tracked by git)
└── data/                   # Raw CSV datasets (not tracked by git)
```

---

## Safety & Legal

This tool is built **exclusively for authorized security testing** on networks and systems you own or have explicit written permission to test.

- The guardrail system hard-blocks all exploit attempts against public IPs
- A confirmation dialog is required before any exploit is launched
- All activity is logged with timestamps

**Never use this tool against systems you do not own or have written authorization to test.**

---

## License

MIT License — see `LICENSE` for details.