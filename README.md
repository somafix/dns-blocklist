# 🛡️ DNS Blocklist Updater with AI Learning

![Version](https://img.shields.io/badge/Version-2.1.0-blueviolet?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-SomaFix-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-GPL--3.0-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)

**A professional DNS synchronization tool** that pairs the industry-standard HaGeZi PRO++ lists with a proprietary **TrackerAI** engine. It proactively identifies new trackers before they appear in public lists.

---

## ⚡ Core Enhancements in v2.1.0

* **🧠 Advanced Heuristics** — Now detects high-entropy DGA (Domain Generation Algorithms) with enhanced regex patterns.
* **🛡️ Legitimacy Safeguards** — Built-in exceptions for critical infrastructure (`Cloudflare`, `AWS`, `Google APIs`) to prevent breaking the internet.
* **🕵️ Extended Keyword Database** — Monitors over 40+ tracking-related keywords and patterns.
* **🧹 Smart Self-Cleaning** — Automatically removes false positives if domains gain a positive reputation over time.
* **📝 Attribution & Watermarking** — Clear licensing and source tracking for open-source integrity.

---

## 🚀 Installation & Usage

### 🛠️ Setup
1. **Clone the repo:**
   ```bash
   git clone [https://github.com/SomaFix/dns-blocklist-updater.git](https://github.com/SomaFix/dns-blocklist-updater.git)
   cd dns-blocklist-updater
