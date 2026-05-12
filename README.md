# 🛡️ DNS Blocklist Manager AI

![Version](https://img.shields.io/badge/version-6.1.0-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Status](https://img.shields.io/badge/status-production--ready-success.svg)
![AI](https://img.shields.io/badge/AI-Behavioral--Engine-blueviolet)

An advanced, production-ready DNS blocklist manager that leverages a **Behavioral AI engine** to enhance traditional blocking. It intelligently aggregates upstream sources, validates domain integrity, and applies a dynamic reputation-based scoring system.

---

## 🚀 Key Features

*   **🧠 Behavioral AI Engine**: Automatically calculates domain reputation based on query frequency, client diversity, TLD analysis, and CDN verification.
*   **📡 Optimized Sources**: Integrates top-tier filtered lists from **HaGeZi** and **AdGuard** (OISD removed for v6.1.0 parity).
*   **🛡️ Strict Validation**: RFC-compliant domain sanitization and comprehensive regex validation.
*   **💾 Triple-Format Export**: Generates ready-to-use lists for:
    *   **Plain Text**: `domains.txt`
    *   **AdGuard/uBlock**: `adguard_list.txt` (using `||domain^` syntax)
    *   **Hosts**: `hosts.txt` (using `0.0.0.0` prefix)
*   **📊 Integrated Health Check**: Pre-flight system diagnostics to verify connectivity, library dependencies, and disk permissions.
*   **🗄️ Persistence & Safety**: SQLite backend with WAL mode, automated PID management to prevent race conditions, and timestamped file backups.

---

## ⚙️ How the AI Works

The behavioral engine assigns a reputation score between **-10 and +10** based on several factors:

| Factor | Impact | Logic |
| :--- | :--- | :--- |
| **Frequency** | 🔴 Negative | High-intensity query spikes. |
| **Client Diversity** | 🔴 Negative | Multiple unique IPs requesting the same obscure domain. |
| **TLD Analysis** | 🔴 Negative | Domains under suspicious TLDs (e.g., `.click`, `.top`, `.xyz`). |
| **CDN/Major Org** | 🟢 Positive | Known legitimate infrastructure (Cloudflare, Google, etc.). |
| **Age/Stability** | 🟢 Positive | Domains that have been "seen" consistently over 30 days. |

---

## 🛠️ Requirements & Setup

*   **Python 3.8+**
*   **Dependencies**: `aiohttp` for async fetching. `psutil` is recommended for advanced process management.

```bash
# Install required dependencies
pip install aiohttp psutil
