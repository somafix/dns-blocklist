# 🛡️ DNS Blocklist Manager

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-12.0.0-green.svg)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/)

*Production Ready v12.0.0 — High Availability DNS blocklist generator with automatic failover capabilities.*

</div>

---

## 📋 Overview

**DNS Blocklist Manager** is a robust, asynchronous Python utility designed to compile, filter, and maintain large-scale DNS blocklists formatted for hosts files (`0.0.0.0 domain`). 

It provides enterprise-grade reliability features, including automated source tracking, a built-in multi-source failover mechanism, comprehensive logging with rotation, wildcard pattern management, and strict domain validation.

---

## ✨ Key Features

- **🔄 High Availability & Failover:** Automatically tests primary blocklist sources (HaGeZi, OISD, StevenBlack, AdGuard, EasyList, etc.). If a source goes down, it seamlessly switches to an available mirror or fallback provider and caches the working state.
- **⚡ Fully Asynchronous:** Leverages `asyncio` and `aiohttp` for non-blocking, parallel fetching and high-performance processing.
- **🧹 Advanced Domain Filtering:** Cleans and normalizes entries, stripping out invalid inputs, IP addresses, wildcards, and comments while preventing duplicate entries.
- **📝 Custom Lists Support:** Seamlessly integrates standard whitelists, blacklists, and wildcard whitelist patterns (`*.example.com`).
- **📊 Detailed Statistics & Logging:** Built-in rotating file logger with visual emojis and JSON statistics output tracking filtering metrics and reduction rates.
- **🛡️ Safe Operations:** Automatically creates secure timestampsed backups of existing output files before overwriting.

---

## ⚙️ Requirements

- Python **3.11+**
- `aiohttp` package

---

## 🚀 Installation

1. Clone or download the script file.
2. Install the required external dependency:
   ```bash
   pip install aiohttp
