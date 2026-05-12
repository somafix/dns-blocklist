# 🛡️ DNS Blocklist Manager v6.0.0

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-6.0.0-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Asyncio](https://img.shields.io/badge/performance-asyncio-red)
![No AI](https://img.shields.io/badge/AI-None-lightgrey)

A high-performance, asynchronous Python tool designed to aggregate, clean, and export DNS blocklists. This **Modernized** version focuses on raw speed, reliability, and precision without the bloat of "fake AI" logic.

---

## ✨ Key Features

*   🚀 **Fully Asynchronous:** Uses `asyncio` and `aiohttp` for lightning-fast concurrent downloads.
*   🧹 **Intelligent Cleaning:** Automatically strips comments, IP addresses, protocol prefixes (`https://`), and AdGuard-specific syntax (`||`, `^`).
*   📂 **Multi-Format Export:**
    *   **Plain List:** Standard domain-per-line (`domains.txt`).
    *   **AdGuard Home:** AdGuard-compatible format (`adguard_list.txt`).
    *   **Hosts File:** Classic system hosts format (`hosts.txt`).
*   🛡️ **Smart Filtering:** Built-in support for custom **Whitelists** and **Blacklists**.
*   💾 **Safe Backups:** Automatically creates timestamped backups of your lists before every update.
*   🔒 **Process Safety:** Uses PID file tracking to prevent multiple instances from running simultaneously.

---

## 🛠 Installation & Usage

### 📋 Prerequisites
*   Python 3.8 or higher
*   `aiohttp` library

```bash
pip install aiohttp
