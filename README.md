# DNS Blocklist Manager

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-9.0.0--stable-green.svg?style=flat-square)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg?style=flat-square)](https://github.com/)

A lightweight, high-performance asynchronous DNS blocklist aggregator and sanitizer written in Python. Version `9.0.0-stable` is a production-hardened release featuring robust error handling, optimized file stream-flushing for handling massive target records, and a guaranteed force-refresh design that deliberately bypasses internal caching layers to fetch live blocklist datasets.

---

## Technical Highlights

*   **Native Asynchronous I/O:** Powered by `asyncio` and `aiohttp` with built-in concurrency tracking and resource semaphore controls.
*   **Guaranteed Data Freshness:** Local caching engines are completely decoupled (`ENABLE_CACHE = False`) to guarantee live upstream index acquisition on every single build cycle.
*   **Intelligent Domain Sanitation:** Automated parsing routines sanitize complex prefixes (`http://`, `https://`, `||`, loopback routing IPs) and strictly validate strings against RFC length and character boundaries.
*   **Dual-Tier Filtering:** Integrates flat absolute user whitelists/blacklists alongside an algorithmic substring matching rule-set for custom wildcard rules.
*   **Failsafe Updates:** Instantly captures operational historical data via timestamped binary file shifting before writing clean records down to storage.

---

## File Workspace Layout

The application initializes directories and manages target outputs dynamically inside the workspace root:

```text
├── hosts.txt                  # Consolidated compilation target (Format: 0.0.0.0 domain.com)
├── whitelist.txt              # User-defined absolute domain exclusions (ALWAYS allowed)
├── blacklist.txt              # User-defined absolute domain inclusions (ALWAYS blocked)
├── wildcard_whitelist.txt    # Substring matching patterns for massive infrastructure bypasses
├── stats.json                 # Post-execution analytics file containing performance details
├── backup/                    # Storage mapping location keeping historical timestamped hosts files
└── logs/                      # System events tracking file containing trace streams (dns_blocker.log)
