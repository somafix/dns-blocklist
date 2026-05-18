# DNS Blocklist Manager — Elite Edition

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-7.1.0--evolution-orange.svg?style=flat-square)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

An evolutionary, high-performance **DNS Blocklist Manager** written in asynchronous Python. It provides memory-optimized streaming compilation, smart rate limiting, automatic domain validation, and multi-format exporters (Hosts, Plain Domains, AdBlock Plus).

---

## ✨ Features

*   **⚡ Asynchronous Architecture:** Leverages `asyncio` and `aiohttp` for lightning-fast concurrent source downloads.
*   **💾 Streaming Engine:** Process millions of domains sequentially with minimal memory footprint (`~50 MB` overhead for large lists) and aggressive garbage collection (`gc.collect()`).
*   **🌐 Smart Rate Limiter:** Protects upstream sources with a sliding-window rate limiter and respects `429 Too Many Requests` HTTP response hints.
*   **🛠️ Robust Domain Validation:** Strict cleanup rules discarding IPs, regex fragments, handling comments (`#`), and matching wildcard subdomains seamlessly.
*   **🧱 Multi-Format Plugin System:** Exports simultaneously to `hosts` format (`0.0.0.0 domain.com`), standard `domains` list, and `AdBlock Plus` format (`||domain.com^`).
*   **🔄 Resilience & Safety:** Features local multi-layered TTL-based JSON caching, automatic rolling file logging, process lock via PID tracking, and graceful shutdown signal handlers (`SIGINT`/`SIGTERM`).

---

## 🏗️ Directory Structure

The manager initializes and expects the following structure relative to the runtime environment:

```text
├── .cache/                     # Local TTL cache storage
│   └── domains_cache.json
├── backup/                     # Automatic rolling blocklist backups
├── lists/
│   ├── whitelist.txt           # Exact domain exclusions
│   ├── blacklist.txt           # Explicit manual additions
│   └── wildcard_whitelist.txt  # Wildcard rules (e.g., *.ads.com, doubleclick*)
├── logs/
│   └── dns_blocker.log         # Detailed rotating logs
├── hosts.txt                   # Compiled main output (Hosts format)
└── stats.json                  # Generation breakdown metrics
