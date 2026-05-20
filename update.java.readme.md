# 🚀 DNS Blocklist Manager (Production Elite Edition)

[![Java Version](https://img.shields.io/badge/Java-21%2B-orange.svg?style=flat-square&logo=openjdk)](https://openjdk.org/)
[![Release](https://img.shields.io/badge/Version-2.0.0-blue.svg?style=flat-square)](../../releases)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Cross__Platform-blueviolet.svg?style=flat-square)]()

`DNSBlocklistManager` is a high-performance, enterprise-grade Java utility designed to fetch, parse, clean, filter, and compile DNS blocklists. Utilizing modern Java features like **Virtual Threads** and concurrent collection types, it effortlessly compiles millions of domains into optimized formats ready for deployment in Pi-hole, AdGuard Home, or native operating system `hosts` files.

---

## ✨ Features

*   **⚡ Ultra-Fast Processing:** Uses modern Java **Virtual Threads** (`Executors.newVirtualThreadPerTaskExecutor()`) to perform concurrent non-blocking I/O fetches and handles high-volume domain filtering in parallel streams.
*   **🛠 Smart Domain Sanitization & Validation:** Automated cleanup of inputs from multiple raw blocklist formats (removes comments, processes `0.0.0.0` or `127.0.0.1` prefixes, handles AdBlock styles like `||example.com^`, and scrubs protocol schemes).
*   **💾 Intelligent Local Caching:** Built-in Serialization cache mechanism with an automatic 24-hour Time-to-Live (TTL) configuration to prevent redundant upstream bandwidth usage.
*   **🛡 Advanced Filtering Triad:** Support for custom user-defined execution control files:
    *   **Strict Whitelist** (`whitelist.txt`)
    *   **Wildcard Regex Whitelist** (`wildcard_whitelist.txt`)
    *   **Overriding Blacklist** (`blacklist.txt`)
*   **🔒 Run-Safe Execution (PID Locking):** Native process instance locking via OS-level PID check to avoid split-brain directory access or corrupted files during concurrent cron or daemon triggers.
*   **📊 Structured Performance Analytics:** Automatically exports an operational breakdown file (`stats.json`) containing download stats and unique blocking metrics.

---

## 📂 Project Structure

The manager initializes and operates within the following working directory layout:

```text
├── lists/
│   ├── whitelist.txt            # Explicitly allowed domains (skipped from blocking)
│   ├── wildcard_whitelist.txt   # RegEx patterns or direct domain matches to bypass
│   └── blacklist.txt            # Domains forced into the final generation
├── backup/
│   └── hosts_YYYYMMDD_HHMMSS.txt# Automatically versioned historical blocklists
├── .cache/
│   └── domains.ser              # Binary serial cached file for performance checks
├── hosts.txt                    # Compiled blocklist in standard 0.0.0.0 mapping format
├── domains.txt                  # Compiled blocklist containing line-by-line domain naming
└── stats.json                   # Structured JSON report with metrics and metadata
