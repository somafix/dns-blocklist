# 🛡️ UpDate Blocklister v1.0.0
### High-Performance Enterprise Domain Filtering & Validation

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-checked-green.svg)
![Security](https://img.shields.io/badge/security-bandit-yellow.svg)
![Standards](https://img.shields.io/badge/RFC-1034%2F1035-blue.svg)

**UpDate Blocklister** is a production-ready utility designed for mission-critical network environments. It automates the fetching, RFC-compliant validation, and multi-format export of domain blocklists. Engineered for performance, it utilizes a thread-safe producer-consumer model to handle millions of records with minimal latency.

---

## 🏗️ Technical Architecture

The system is partitioned into modular components designed for maximum reliability and scalability:

1.  **Strict Domain Validator:** An RFC 1034/1035 compliant engine featuring an **LRU Cache (100k entries)** to drastically reduce regex overhead during massive batch processing.
2.  **Multithreaded Domain Processor:** A core orchestration layer utilizing a thread-safe `queue.Queue` and worker pool. It ensures data integrity via `RLock` synchronization and prevents memory exhaustion with a 10M record ceiling.
3.  **Concurrent Source Aggregator:** Uses `ThreadPoolExecutor` to perform non-blocking I/O when fetching remote blocklists, supporting both plain-text lists and standard Hosts-file formats.
4.  **Extensible Output Formatter:** Native generation of configuration files for high-performance DNS resolvers including **dnsmasq** and **Unbound**.

---

## 🛡️ Quality Assurance & Security

This codebase is pre-configured to pass rigorous enterprise audit suites:

*   **Ruff:** Validates code style and ensures optimal linting performance.
*   **Mypy:** Enforces strict static typing for architectural predictability.
*   **Bandit:** Scans for common Python-specific security vulnerabilities.
*   **Pytest:** Facilitates unit testing with comprehensive coverage metrics.
*   **Pip-audit:** Monitors the dependency tree for known CVEs.

---

## 🚀 Deployment & Usage

### 1. Automated Fetching
Aggregates domains from default enterprise-grade sources and outputs a dnsmasq configuration:
```bash
python update_blocklist.py --fetch --output /etc/dnsmasq.d/blocklist.conf
