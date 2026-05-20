# DNS Blocklist Manager

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-11.0.0-green.svg?style=flat-square)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg?style=flat-square)](https://github.com/)

A professional, enterprise-grade asynchronous DNS blocklist manager written in Python. Version `11.0.0` introduces a fully refactored OOP architecture featuring typed global configurations, pre-compiled regex engine lookups for high-throughput normalization, dedicated backup lifecycle tracking, and enhanced multi-destination log rotation.

---

## Technical Highlights in v11.0.0

*   **Centralized Config Management:** Unified runtime control via the `Config` class, offering deterministic filesystem initialization and clear directory scaffolding out of the box.
*   **High-Performance Aggregation:** Utilizes pre-compiled regular expressions (`_IP_PATTERN`, `_DOMAIN_PATTERN`) inside an optimized validation loop to drop invalid data with minimal CPU overhead.
*   **Decoupled Backup System:** Offloads archive lifecycles to an independent `BackupManager` utility, generating immutable timestamped snap-shots (`hosts_YYYYMMDD_HHMMSS.txt`) prior to modification.
*   **Resilient Context Engines:** Advanced `DataFetcher` context wrapper features structured backoff timers, custom HTTP User-Agents, and network isolation barriers protecting against sockets hanging indefinitely.
*   **Atomicity & Durability:** Employs explicit low-level file descriptor synchronization via `os.fsync()` to prevent cache corruption during unexpected hardware cut-offs.

---

## File Workspace Layout

The application initializes directories and enforces strict structural compliance within your workspace:

```text
├── hosts.txt                  # Consolidated compilation target (Format: 0.0.0.0 domain.com)
├── whitelist.txt              # User-defined domain exclusions (ALWAYS allowed)
├── blacklist.txt              # User-defined domain inclusions (ALWAYS blocked)
├── wildcard_whitelist.txt    # Substring filtering metrics to globally whitelist wildcard structures
├── stats.json                 # Post-execution statistics block detailing reduction performance
├── backup/                    # Storage mapping directory containing historical configuration archives
└── logs/                      # Dynamic log directory tracking trace histories (dns_blocker.log)
