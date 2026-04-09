# UpDate Blocklister 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type_checked-mypy-blue.svg)](https://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-black.svg)](https://github.com/PyCQA/bandit)

**UpDate Blocklister** is a production-ready Python tool designed to fetch, validate, and convert domain blocklists into various DNS server formats. It features high-performance concurrent processing and strict RFC compliance.

---

## ✨ Key Features

*   **RFC 1034/1035 Compliance:** Strict domain validation (labels, length, characters).
*   **High Performance:** Concurrent domain processing using a thread-safe worker pool.
*   **Multiple Formats:** Exports to `dnsmasq`, `unbound`, and `plain` text lists.
*   **Smart Fetching:** Supports standard hosts file formats and plain domain lists from URLs.
*   **Production Grade:** Built-in LRU caching, graceful shutdown, and comprehensive logging.

---

## 🛠️ Audit Stack

This codebase is optimized for and tested with:
*   **Ruff:** Formatting and linting.
*   **Mypy:** Static type checking.
*   **Bandit:** Security vulnerability scanning.
*   **Pip-audit:** Dependency vulnerability checking.
*   **Pytest:** Unit testing and coverage.

---

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/youruser/update-blocklister.git](https://github.com/youruser/update-blocklister.git)
    cd update-blocklister
    ```

2.  **Set the Environment Variable:**
    The application requires a license key to run in production mode:
    ```bash
    export LICENSE_KEY="OK-2026"
    ```

---

## 📖 Usage

### Basic Command
Fetch default sources and save as a dnsmasq config:
```bash
python3 blocklister.py --fetch --output blocklist.conf
