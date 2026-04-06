# 🛡️ DNS Security Blocklist Builder (Autonomous Edition)

### Enterprise-Grade Threat Intelligence Aggregator & Validator

**Version 5.0.0** | **Formally Verified** | **High-Availability Design**

---

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge)](https://www.python.org/)
[![Framework: Pydantic V2](https://img.shields.io/badge/Framework-Pydantic_V2-red?style=for-the-badge)](https://docs.pydantic.dev/)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production_Ready-brightgreen?style=for-the-badge)](#-autonomous-operation)

---

## 🎯 Executive Summary

The **Autonomous DNS Blocklist Builder** is a professional-grade security microservice designed to aggregate, validate, and deduplicate threat intelligence from multiple high-trust sources. Built with **Pydantic V2** and **AsyncIO**, it offers a "set-and-forget" architecture for maintaining high-quality blocklists for Pi-hole, AdGuard Home, or custom Unbound/dnsmasq resolvers.

### 🚀 Core Features

*   **🤖 Autonomous Scheduler:** Integrated engine that manages update cycles (default: every 6 hours) with graceful handling of `SIGINT` and `SIGTERM`.
*   **🛡️ Formally Verified Logic:** Multi-stage validation ensures zero IP addresses, wildcards (`*.com`), or localhost entries enter your production list.
*   **💾 State Management:** Uses a `StateManager` to survive process crashes. It saves checkpoints every 100k domains to prevent re-processing massive datasets.
*   **🔧 Auto-Healing:** An intelligent `HealthMonitor` detects consecutive failures and automatically triggers a database repair if the state becomes corrupted.
*   **🌍 Unicode & IDNA:** Full support for internationalized domain names (Punycode conversion) via the `idna` library.
*   **⚡ Resource Protection:** Uses `resource.setrlimit` to bound memory usage and prevents OOM (Out Of Memory) kills on low-resource hardware like Raspberry Pi.

---

## 📊 Technical Specifications

| Feature | Specification | Description |
| :--- | :--- | :--- |
| **Max Domains** | 10,000,000 | Configurable limit (up to 50M) |
| **Memory Limit** | 2048 MB | Hard-capped via OS-level limits |
| **Format** | Hosts (0.0.0.0) | Universal compatibility with DNS sinks |
| **Networking** | Asynchronous | Non-blocking I/O with exponential backoff |
| **Validation** | Regex + Pydantic | Strict RFC 1035/1123 compliance |

---

## ⚙️ Configuration

The application is fully configurable via **Environment Variables** (prefix `DNSBL_`):

```bash
# Example Configuration
DNSBL_MAX_DOMAINS=5000000        # Max unique domains allowed
DNSBL_UPDATE_INTERVAL_HOURS=12   # Frequency of updates
DNSBL_MAX_MEMORY_MB=1024         # Memory safety cap
DNSBL_AUTO_REPAIR=True           # Enable self-healing logic
