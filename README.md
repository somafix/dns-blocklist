# DNS Blocklist Manager

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-8.1.0--production-green.svg?style=flat-square)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg?style=flat-square)](https://apple.com)

A production-ready, highly optimized, and asynchronous DNS Blocklist Manager written in Python. It aggregates remote blocklists, sanitizes domain names, applies custom filtering rules (blacklists, whitelists, and wildcard matching), and exports data into both standard `hosts` format and plain domain lists.

---

## Key Features

*   **Asynchronous Architecture:** Built on top of `asyncio` and `aiohttp` for lightning-fast concurrent source downloads.
*   **Smart Caching Engine:** Includes a time-to-live (TTL) cache system to minimize bandwidth usage and reduce remote server load.
*   **Advanced Domain Sanitation:** Automatically strips prefixes (`http://`, `https://`, `||`, IP mappings) and strictly validates domains via regex according to RFC standards.
*   **Dynamic Filtering Rules:** Multi-tier processing using plain whitelists, blacklists, and flexible wildcard exclusion patterns.
*   **Concurrence Protection:** Built-in PID management to prevent concurrent executions of the script.
*   **Production Logging:** Outputs ANSI color-coded stream logs alongside automated rotating file backups.

---

## File and Directory Structure

The manager organizes its assets dynamically inside the workspace directory using the following hierarchy:

```text
├── blocklist.txt              # Primary generated file (hosts format: 0.0.0.0 domain.com)
├── domains.txt                # Plaintext generated list (one domain per line)
├── whitelist.txt              # User-defined domains to ALWAYS allow
├── blacklist.txt              # User-defined domains to ALWAYS block
├── wildcard_whitelist.txt    # User-defined wildcard matching rules for exemptions
├── stats.json                 # Execution runtime and reduction performance metrics
├── backup/                    # Automatically managed directory for timestamped historical blocklists
├── logs/                      # Application logging tracking history (dns_blocker.log)
└── .cache/                    # Expiry-controlled serialization directory (domains.json)
