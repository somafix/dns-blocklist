# DNS Blocklist Manager

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-8.2.0--production-green.svg?style=flat-square)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg?style=flat-square)](https://github.com/)

An asynchronous, production-ready DNS blocklist aggregator and sanitizer written in Python. Version `8.2.0` introduces targeted performance fixes for seamless `hosts.txt` updates, optimized sequential stream-flushing to handle massive domain sheets, and a default force-refresh engine to ensure you are always serving the most up-to-date threat intelligence vectors.

---

## What's New in v8.2.0

*   **Fixed Hosts Exporting:** Re-engineered write hooks targeting the dedicated `hosts.txt` output file with dynamic buffer flushes every 100k records to minimize peak RAM footprints.
*   **Bypassed Caching by Default:** Set `enable_cache` to `False` natively, clearing old schemas upon execution to prioritize fresh updates over stale metrics.
*   **Backoff Retries:** Upstream fetching now features an exponential retry backoff structure (`2 ** attempt`) to gracefully manage minor remote server throttling.

---

## File and Directory Structure

The manager dynamically organizes its workspace inside the runtime directory:

```text
├── hosts.txt                  # Primary production output file (Format: 0.0.0.0 domain.com)
├── whitelist.txt              # User-defined exceptions (domains to ALWAYS allow)
├── blacklist.txt              # User-defined inclusions (domains to ALWAYS block)
├── wildcard_whitelist.txt    # Substring matching pattern list for macro bypasses
├── stats.json                 # Output metadata and performance reduction reports
├── backup/                    # Historical rotation directory storing timestamped hosts.txt files
├── logs/                      # Rotating error and trace system logs (dns_blocker.log)
└── .cache/                    # Storage directory for schema serialization (disabled by default)
