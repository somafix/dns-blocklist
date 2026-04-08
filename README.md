# 🛡️ DNSBL Builder v1.0.0
### High-Performance Domain Blocklist Generator

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-checked-green.svg)
![Security](https://img.shields.io/badge/security-bandit-yellow.svg)
![Standards](https://img.shields.io/badge/RFC-1034%2F1035-blue.svg)

**DNSBL Builder** is a production-ready utility designed to aggregate, validate, and format domain-based blocklists. It utilizes a thread-safe worker pool and LRU-cached validation logic to process millions of domains with minimal resource overhead.

---

## 🏗️ Core Architecture

The system is built on four pillars of reliability:

1.  **RFC-Compliant Validator:** A strict implementation of RFC 1034/1035 domain rules with an LRU cache (100k entries) to eliminate redundant regex overhead.
2.  **Concurrent Processor:** A thread-safe `DomainProcessor` with a bounded queue and graceful shutdown mechanisms to manage system load.
3.  **Aggregator Engine:** Parallel fetching of remote sources via `ThreadPoolExecutor` with support for both plain-text and Hosts-style formats.
4.  **Multi-Target Formatter:** Native support for `dnsmasq`, `unbound`, and standard plain-text output formats.

---

## 🛡️ Security & Quality Audit

The codebase is optimized for modern CI/CD pipelines and supports the following audit toolchain:

*   **Ruff:** High-speed linting and automated formatting.
*   **Mypy:** Static type analysis for internal consistency.
*   **Bandit:** Automated security scanning for common Python vulnerabilities.
*   **Pytest:** Unit testing with coverage reporting.
*   **Pip-audit:** Dependency vulnerability assessment.

---

## 🚀 Quick Start

### Basic Generation
Run the builder to fetch default sources and output a `dnsmasq` configuration:
```bash
python dnsbl_builder.py --fetch --output /etc/dnsmasq.d/blocklist.conf
