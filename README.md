# UpDate Blocklister 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Bandit](https://img.shields.io/badge/security-bandit-black.svg)](https://github.com/PyCQA/bandit)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type_checked-mypy-blue.svg)](http://mypy-lang.org/)

**UpDate Blocklister** is a production-ready Python utility designed to fetch, validate, and convert domain blocklists into various DNS server formats. It features high-performance concurrent processing, RFC-compliant domain validation, and zero external dependencies for the core logic.

---

## 🚀 Features

*   **RFC 1034/1035 Compliance:** Strict validation of domain names (length, characters, and formatting).
*   **High Performance:** Thread-safe concurrent domain processing using a worker pool and bounded queues.
*   **Multiple Formats:** Exports to `dnsmasq`, `unbound`, and `plain` text lists.
*   **Efficient Memory Usage:** Utilizes `lru_cache` for domain validation and optimized sets for de-duplication.
*   **Security Focused:** Built to pass `bandit` security audits and `mypy` static type checking.

---

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/youruser/update-blocklister.git](https://github.com/youruser/update-blocklister.git)
   cd update-blocklister
