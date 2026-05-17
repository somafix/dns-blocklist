# DNS Blocklist Manager — Enterprise Elite Edition

![Java Version](https://img.shields.io/badge/Java-21%2B-orange?style=for-the-badge&logo=openjdk)
![Version](https://img.shields.io/badge/Version-8.0.0--elite-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)

An advanced, production-grade DNS blocklist aggregator and orchestrator written in modern Java. It efficiently fetches blocklists from multiple remote feeds concurrently, performs deep cleaning and structured validation, applies fine-grained filtering rules, and exports high-performance assets into various targeting syntax formats.

---

## 🔥 Key Features

*   **Virtual Threads Engine:** Leveraging modern Java concurrency architecture to pull multiple large remote lists concurrently with high throughput.
*   **Resilient Networking (Circuit Breaker & Exponential Backoff):** Embedded defensive fallback states prevents hung lookups on unstable third-party data providers.
*   **Multi-Tier Filtering Pipeline:** Built-in exact matches (`whitelist.txt`, `blacklist.txt`) and high-speed Wildcard pattern evaluation.
*   **Clean Parsing & Normalization Engine:** Auto-strips host file bindings, protocol schemes (`http://`), trailing slashes, inline comments, and invalid multi-dot domains with smart LRU cache lookup memoization.
*   **Structured Logging & Metrics Matrix:** Generates beautiful colorized console terminal outputs alongside JSON-formatted logs for automated audit compliance logging solutions. Includes single instance file locking via system PID guards.
*   **Polyglot Format Distribution:** Compiles parsed rules instantly into multiple native network formats (`HOSTS`, raw `DOMAINS`, `ADBLOCK` rules, `DNSMASQ`, and `UNBOUND` routing configurations).

---

## 🛠 File Infrastructure Blueprint

The manager dynamically bootstraps the following operational workspace layouts automatically upon launch:

```text
├── .cache/
│   └── domains_cache.json       # TTL cached remote lists mapping
├── backup/
│   └── hosts_YYYYMMDD_HHMMSS.txt# Pre-build file system recovery snap
├── lists/
│   ├── whitelist.txt            # Explicit safe domains (Always allowed)
│   ├── wildcard_whitelist.txt   # Generative safe patterns (e.g., *.google.*)
│   └── blacklist.txt            # Forced manual target bans
├── logs/
│   └── dns_blocker.log          # Rotated structured audit files
├── hosts.txt                    # Main compilation payload (Output)
└── stats.json                   # Aggregated JSON runtime telemetry metrics
