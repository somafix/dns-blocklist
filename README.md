# 🛡️ AI-Enhanced DNS Sentinel 🧠

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Hardened-orange?style=for-the-badge&logo=guardedid)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**A high-performance, self-learning DNS blocklist manager.** It doesn't just download lists; it analyzes them using a custom heuristic engine to stay ahead of trackers and telemetry.

---

## 🚀 Key Capabilities

* **📡 Smart Syncing** — Automatically fetches the massive **HaGeZi PRO++** list.
* **🤖 TrackerAI Engine** — Uses Shannon entropy and pattern recognition to identify malicious domains.
* **⚖️ Reputation System** — Domains are scored dynamically. If they look suspicious (DGA, tracking keywords), they get blocked.
* **🧹 Auto-Purge** — Intelligent cleanup of false positives to keep your browsing smooth.
* **💾 Robust Backups** — Atomic file writes with `.backup` creation to ensure you never lose connectivity.

---

## 🧠 How the AI Engine Thinks

The `TrackerAI` class uses a multi-layered scoring system to evaluate domain safety:

| Metric | logic | Icon |
| :--- | :--- | :---: |
| **Entropy** | Detects random-generated strings (DGA) | 📊 |
| **Keywords** | Scans for `metrics`, `pixel`, `analytics`, etc. | 🔍 |
| **Structure** | Analyzes subdomains and TLD depth | 🏗️ |
| **History** | Tracks "first seen" and "last seen" timestamps | ⏳ |

> [!TIP]
> The engine calculates the **Shannon Entropy** of domain parts. If a domain looks like `a1b2c3d4e5.com`, the AI recognizes the high randomness and flags it!

---

## 🛠️ Quick Start

### 1️⃣ Clone the repository
```bash
git clone [https://github.com/yourusername/ai-dns-sentinel.git](https://github.com/yourusername/ai-dns-sentinel.git)
cd ai-dns-sentinel
