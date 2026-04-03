# 🏆 Autonomous DNS Blocklist Builder

### Enterprise-Grade Threat Intelligence Platform with Crash Recovery
### v4.0.5 | Pydantic-Powered | High Performance & Resiliency

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge)](https://www.python.org/)
[![Framework: Pydantic](https://img.shields.io/badge/Framework-Pydantic_V2-red?style=for-the-badge)](https://docs.pydantic.dev/)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=for-the-badge)](#-autonomous-operation)

---

## 🎯 EXECUTIVE SUMMARY

The **Autonomous DNS Blocklist Builder** (v4.0.5) is a professional-grade security solution designed to aggregate, validate, and deduplicate threat intelligence from multiple DNS sources. Built with **Pydantic V2** and **AsyncIO**, it offers a "set-and-forget" architecture for maintaining high-quality blocklists for Pi-hole, AdGuard Home, or custom Unbound/dnsmasq resolvers.

- ✅ **High-Speed Processing:** Asynchronous fetching and regex-optimized validation.
- ✅ **Crash Recovery:** Persistent state management saves progress every 100k domains.
- ✅ **Auto-Healing:** Integrated health monitor detects failures and triggers self-repair.
- ✅ **RFC Compliant:** Strict validation of domain syntax, length, and character sets.
- ✅ **Zero-Dependency Core:** Only requires standard Python security and async libraries.

---

## 🚀 KEY FEATURES

### 🤖 Autonomous Operation
The script features an integrated **Autonomous Scheduler** that manages update cycles automatically. It handles OS signals (SIGINT/SIGTERM) for graceful shutdowns and maintains a health ledger to ensure 24/7 reliability without human intervention.

### 💾 Persistent State & Recovery
Unlike standard scripts, this builder uses a **StateManager** to survive system reboots or process crashes:
- **Checkpoints:** Periodically serializes (pickles) processed domains to disk.
- **Resumption:** If interrupted, it automatically reloads the last known state to avoid re-processing massive datasets.

### 🛡️ Enterprise-Grade Fetching
- **Exponential Backoff:** Retries failed downloads with increasing delays (5s, 10s, 20s...).
- **Atomic Writes:** Uses temporary files and `os.replace` to ensure output files are never corrupted during generation.
- **Resource Management:** Hard limits on domain count and memory protection through streaming.

---

## 📁 OUTPUT FILES

The builder generates structured output in the designated `./output` directory:

| Filename | Format | Description |
| :--- | :--- | :--- |
| `blocklist.txt` | Hosts File | Standard `0.0.0.0 domain.com` format. |
| `blocklist.txt.gz` | Gzip | Compressed version for bandwidth efficiency. |

---

## ⚙️ CONFIGURATION

The application is fully configurable via **Environment Variables** (prefix `DNSBL_`):

```bash
# Example environment configuration
DNSBL_OUTPUT_DIR="./my_lists"
DNSBL_MAX_DOMAINS=2000000
DNSBL_UPDATE_INTERVAL_HOURS=6
DNSBL_HTTP_TIMEOUT=30
DNSBL_AUTO_REPAIR=True
