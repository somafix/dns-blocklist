# 🛡️ DNS Blocklist Manager `v6.0.0`

A modern, high-performance Python tool for aggregating, cleaning, and managing DNS blocklists. Version 6.0 has been completely rewritten using **asyncio** for maximum efficiency—no "fake AI" fluff, just clean code and reliable filtering.

---

## ✨ Key Features

*   🚀 **Asynchronous Engine:** Simultaneous downloads of multiple sources via `aiohttp`.
*   🧹 **Smart Cleaning:** Automatic removal of duplicates, IP addresses, comments, and garbage prefixes (`0.0.0.0`, `||`, `https://`, etc.).
*   📊 **Multi-Format Export:** Generates lists in three formats out of the box:
    *   **Plain Domains:** A clean list of raw domains.
    *   **AdGuard Home:** Compatible with `||domain.com^` syntax.
    *   **Hosts File:** Classic `0.0.0.0 domain.com` format.
*   🛡️ **Safety First:** Built-in **Whitelist** support to prevent false positives and automated backups of previous versions.
*   📝 **Robust Logging:** Full operational history with automatic log rotation.
*   🔒 **PID Management:** Prevents multiple instances from running simultaneously to avoid data corruption.

---

## 🛠 Installation & Usage

### 1. Requirements
*   Python 3.8+
*   `aiohttp` library

```bash
pip install aiohttp
