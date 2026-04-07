# DNS Security Blocklist Builder (Enterprise Edition)

![Version](https://img.shields.io/badge/version-6.0.0-blue.svg)
![Security](https://img.shields.io/badge/OWASP-Compliant-green.svg)
![Verification](https://img.shields.io/badge/Formal%20Verification-Complete-brightgreen.svg)
![License](https://img.shields.io/badge/License-MIT-black.svg)
![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)

An enterprise-grade, autonomous DNS blocklist engine designed for high-security environments. This tool orchestrates the collection, validation, and distribution of domain-based security intelligence while adhering to strict memory safety and cryptographic integrity standards.

---

## 🛡️ Security & Compliance

This implementation is built with a "Security-First" philosophy, incorporating several advanced protection layers:

*   **OWASP Top 10 (2021) Compliance**: Dedicated enforcement layer for injection prevention (A03), broken access control (A01), and SSRF prevention (A10).
*   **Formal Verification**: Core domain validation and memory management logic use formal invariants to ensure mathematical correctness.
*   **Cryptographic Integrity**:
    *   **AES-256-GCM**: Encrypted state management for cached domains.
    *   **SHA3-256**: High-collision-resistance hashing for output verification.
    *   **Constant-Time Comparisons**: Prevention of timing attacks during token/checksum validation.
*   **Memory Safety**: Runtime monitoring (via `psutil`) and hard limits to prevent OOM (Out Of Memory) crashes in containerized environments.

---

## 🚀 Key Features

*   **Autonomous Operation**: Built-in graceful scheduler with signal handling (`SIGINT`, `SIGTERM`).
*   **Circuit Breaker Pattern**: Protects the system from hanging or failing due to unresponsive upstream sources.
*   **Token Bucket Rate Limiting**: Ensures polite fetching to avoid IP blacklisting.
*   **Punycode Support**: Full IDNA (RFC 5891) support for internationalized domain names.
*   **Atomic I/O**: Write-ahead-log style updates to ensure the blocklist is never corrupted during a disk failure.

---

## 🏗️ Architecture



The system consists of five primary components:
1.  **SecureFetcher**: Handles HTTP(S) requests with SSRF protection and hardened TLS settings.
2.  **DomainValidator**: A regex-based engine verified against formal DNS grammars.
3.  **SecureStateManager**: Manages encrypted persistence of the domain database.
4.  **SecureDomainProcessor**: The central engine that enforces uniqueness and capacity limits.
5.  **OutputGenerator**: Produces standard `0.0.0.0` hosts files, Gzip archives, and SHA3 manifests.

---

## 📥 Installation

### Prerequisites
- Python 3.9 or higher
- `aiohttp`, `pydantic`, `cryptography`, `idna`, `psutil`

```bash
pip install aiohttp pydantic cryptography idna psutil
