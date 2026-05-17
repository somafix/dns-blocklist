# DNS Blocklist Manager — Production Elite Edition

![Java Version](https://img.shields.io/badge/Java-21%2B-orange?style=for-the-badge&logo=openjdk)
![Version](https://img.shields.io/badge/Version-1.0.0--elite-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen?style=for-the-badge)

A fast, highly resilient, and zero-dependency DNS blocklist downloader and processor built on modern Java. It runs asynchronous downloads via **Java Virtual Threads**, parses and cleans bad inputs, checks matches against explicit and wildcard user rules, and manages execution with a strict PID system instance lock file.

---

## 🔥 Key Features

*   **Virtual Threads Parallel Execution:** Spawns lightweight tasks via `Executors.newVirtualThreadPerTaskExecutor()` to download and process remote sources simultaneously with minimal overhead.
*   **Robust Fault Tolerance Engine:** Features a progressive exponential retry algorithm (`MAX_RETRIES = 3`) paired with automatic redirect tracking to gracefully bypass temporary server hiccups.
*   **Advanced Normalization Engine:** Strips inline comments (`#`), legacy host mappings (`0.0.0.0`, `127.0.0.1`), network rules modifiers (`||`, `^`), and protocols (`http://`, `https://`) with sub-path parsing.
*   **High Performance Multi-Tier Filtering:** Automatically reads individual local target rules:
    *   `whitelist.txt`: Keeps mission-critical paths accessible.
    *   `wildcard_whitelist.txt`: Drops patterns matching arbitrary structures (e.g., `*badstuff*`).
    *   `blacklist.txt`: Intercepts and manually locks explicit nodes.
*   **Persistent Binary Core Cache:** Avoids repetitive downloads by utilizing a fast, serialized object dump cache (`.cache/domains.txt`) with an integrated 24-hour expiration TTL window.
*   **Instance Locking via PID Tracking:** Employs explicit cross-platform environment system file verification loops to avoid parallel thread collision states, making it safe for automatic scheduled chronjob setups.

---

## 🛠 Directory Layout & Operational Spaces

The manager bootstraps and maps files into the following execution environment tree structure:

```text
├── .cache/
│   └── domains.txt              # Binary serialized object dump cache 
├── backup/
│   └── hosts_YYYYMMDD_HHMMSS.txt# Automatically versioned target system backups
├── lists/
│   ├── whitelist.txt            # Explicit safe domains (Always allowed)
│   ├── wildcard_whitelist.txt   # Dynamic safe patterns (e.g., *google*, *.internal)
│   └── blacklist.txt            # Explicit manual override blocks
├── domains.txt                  # Raw newline-separated unique domain lists
├── hosts.txt                    # Standard 0.0.0.0 hosts configuration mapping
└── stats.json                   # Output breakdown telemetry data metrics
