# 🛡️ DNS Blocklist Manager AI

![Version](https://img.shields.io/badge/version-6.1.0-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Status](https://img.shields.io/badge/status-production--ready-success.svg)
![AI](https://img.shields.io/badge/AI-Behavioral--Engine-blueviolet)

An advanced, production-ready DNS blocklist manager that combines high-quality upstream sources with a **Behavioral AI engine**. It aggregates, validates, and enhances blocklists using reputation-based scoring and automated learning.

---

## 🚀 Key Features

*   **🧠 Behavioral AI Engine**: Automatically calculates domain reputation based on query frequency, client diversity, and TLD analysis.
*   **📡 Multi-Source Aggregation**: Integrates leading filters (HaGeZi, OISD, AdGuard) with priority handling.
*   **🛡️ Robust Validation**: Strict domain sanitization and RFC-compliant validation logic.
*   **💾 Triple-Format Export**: Generates lists in Plain Text, AdGuard/uBlock format (`||domain.com^`), and Standard Hosts format.
*   **📊 Integrated Health Check**: Built-in system diagnostics to verify connectivity, permissions, and dependencies before execution.
*   **🗄️ SQLite Backend**: High-performance persistence with WAL mode and automated schema migrations.
*   **🔄 Safety First**: Automatic PID management to prevent concurrent runs and timestamped backups of all generated files.

---

## 🛠️ Architecture Overview

The system operates in a linear, 5-stage pipeline:

1.  **Environment Check**: Validates network connectivity and file system permissions.
2.  **AI Training**: Simulates or processes DNS query logs to update the behavioral reputation database.
3.  **Ingestion**: Asynchronously fetches upstream blocklists using `aiohttp`.
4.  **Filtering**: Merges global lists with local `whitelist.txt`/`blacklist.txt` and applies AI-based blocking.
5.  **Export**: Writes optimized lists to multiple formats for use in Pi-hole, AdGuard Home, or Unbound.

---

## 📋 Requirements

*   **Python 3.8+**
*   **Dependencies**:
    *   `aiohttp` (Asynchronous HTTP)
    *   `sqlite3` (Built-in)
    *   `psutil` (Optional, for advanced process management)

```bash
pip install aiohttp psutil
