# DNS Blocklist Manager — Elite Edition

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-7.0.0--elite-red.svg?style=flat-square)](#)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

A professional, high-performance asynchronous DNS blocklist processor. It orchestrates multi-source downloads, performs strict domain sanitation, enforces whitelist/blacklist rules with wildcard support, caches results via time-to-live (TTL) mechanics, and exports clean blocks into standard formats (`hosts`, raw domains, or AdBlock rules).

---

## 🚀 Key Features

*   **Asynchronous Engine:** Fully non-blocking I/O powered by `asyncio` and `aiohttp` featuring configurable TCP connections, parallel download limits, and backoff retries.
*   **Advanced Sanitation:** Cleans inputs down to valid lowercase domains, dropping active IPs, handling complex AdBlock syntax (`||domain^`), and eliminating inline comments/white space.
*   **Smart Caching:** Avoids redundant network requests by using a local JSON cache managed with native TTL handling.
*   **Rule Hierarchy:** Smooth multi-tiered sorting combining source priority mapping, traditional whitelists/blacklists, and complex wildcard filtering (`*.ads.*`, `bad-actor.*`).
*   **Graceful Resilience:** Single-instance enforcement via strict PID lock management and native POSIX signal interception (`SIGINT`, `SIGTERM`) for zero corruption on forced exits.
*   **Elite Logging:** Beautiful ANSI-colored terminal formatting synchronized alongside an automated rotating file-system log engine.

---

## 📂 Directory Structure Matrix

The manager establishes and relies upon the following default hierarchy:

```text
├── backup/                  # Automated historical timestamped backups of hosts.txt
├── lists/
│   ├── whitelist.txt        # Exact domains to allow explicitly
│   ├── blacklist.txt        # Forced extra domains to block 
│   └── wildcard_whitelist.txt # Advanced filter patterns (e.g., *.google.com)
├── logs/
│   └── dns_blocker.log      # Rotating log output file (Max 10MB per file, 10 backups)
├── .cache/
│   └── domains_cache.json   # TTL governed data cache
├── hosts.txt                # Main compilation output target (standard block format)
├── domains.txt              # Companion plain domain output target
└── stats.json               # Structured analytics breakdown of runtime execution
