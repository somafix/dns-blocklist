# 🛡️ DNS Security Blocklist Builder 

### **Next-Gen Threat Intelligence & AI/ML Domain Filtering**
**Version 17.2.0** • *High-Concurrency Async Engine* • *Enterprise-Grade Security*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic-V2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge&logo=shield-check)](#-security-hardening)
[![AI](https://img.shields.io/badge/AI_Detection-Enabled-9B51E0?style=for-the-badge&logo=openai)](#-aiml-smart-categorization)

---

## 🎯 Project Overview

**DNS Security Blocklist Builder** is a high-performance orchestration tool designed to aggregate, validate, and categorize threat intelligence feeds at scale. Version **v17.2.0** introduces a streamlined **All-in-One** architecture, consolidating disparate sources into a single, intelligent blocklist with automated AI/ML infrastructure detection.

> [!TIP]
> Unlike standard bash scripts, this engine leverages **Pydantic V2** for rigorous data validation and **AsyncIO** for parallel processing of millions of domains without blocking execution.

---

## 🔥 Key Innovations in v17.2.0

### 🤖 AI/ML Smart Categorization
Built-in heuristic analysis identifies Artificial Intelligence infrastructure. The engine automatically tags domains belonging to LLM services (OpenAI, Anthropic, Gemini, etc.), allowing granular control over AI tool access in corporate or home environments.

### ⚡ Async Processing Engine
Powered by `aiohttp` and `aiofiles`, the processing pipeline is non-blocking and highly efficient. Handling over **2,000,000 domains** takes minimal time, while memory usage is optimized via Python slots and efficient hash-set deduplication.

### 📂 Unified "All-in-One" Output
No more fragmented files. Everything is consolidated into `blocklist.txt`, enriched with rich metadata:
* **Source Attribution:** Track exactly which feed a domain originated from.
* **Category Tagging:** Every entry is marked as `ADS`, `MALWARE`, `TRACKING`, or `AI_ML`.
* **Visual Semantics:** Integrated emojis for human-readable logs and file audits.

---

## 🛠 Architecture & Tech Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Core Logic** | `Asyncio` / `Python 3.8+` | Event-driven high-speed execution |
| **Data Validation** | `Pydantic V2` | Strict schema and type safety |
| **Networking** | `aiohttp` (Async) | Concurrent non-blocking I/O |
| **Persistence** | `aiofiles` + `Gzip` | Atomic writes & native compression |
| **Resilience** | `Tenacity` | Exponential backoff retry logic |

---

## 📁 Output Anatomy

The generated file is fully compatible with **Pi-hole**, **AdGuard Home**, **pfSense**, and **Unbound**.

```text
# DNS Security Blocklist - All-in-One
# Total unique domains: 1,842,901
# --------------------------------------------------
# Stats: 🤖 AI_ML: 1.2k | 💀 MALWARE: 84k | 👁️ TRACKING: 210k

0.0.0.0 api.openai.com # 🤖 AI_ML
0.0.0.0 doubleclick.net # 📢 ADS
0.0.0.0 track.analytics-data.io # 👁️ TRACKING

🚀 Quick Start Guide
Prerequisites
 * Python 3.8 or higher
 * Recommended: Virtual Environment (venv)
1. Installation
pip install aiohttp aiofiles tenacity pydantic pydantic-settings tqdm

2. Execution
# Simply run the builder script
python blocklist_builder.py

3. Advanced Configuration
Customize the engine via environment variables (prefixed with DNSBL_):
 * DNSBL_PERFORMANCE_MAX_DOMAINS_TOTAL: Domain limit (default: 2M).
 * DNSBL_AI_ENABLED: Toggle AI detection (default: True).
 * DNSBL_OUTPUT_COMPRESSED: Create .gz archive (default: True).
🛡️ Security Hardening
 * Anti-SSRF Protection: Prevents requests to local/private network ranges (RFC 1918), neutralizing potential network scanning via source feeds.
 * Domain Sanitization: Strict RFC 1035/1123 compliance. Invalid characters and malformed strings are stripped automatically.
 * SSL/TLS Verification: Mandatory certificate validation for all upstream intelligence sources.
 * ETag/Cache Optimization: Efficiently handles bandwidth by only downloading modified sources.
📊 Trusted Upstream Sources
The default configuration aggregates the industry's "Gold Standard" feeds:
 * OISD (Big) — Highly curated, zero false-positives list.
 * AdAway — Industry leader for mobile-focused ad blocking.
 * URLhaus — Real-time malware and ransomware infrastructure data.
 * StevenBlack — World's largest community-driven hosts aggregator.
⚖️ License
Distributed under the MIT License. Engineered for security researchers, system administrators, and privacy advocates.
DNS Security Blocklist Builder — Because privacy is a right, not a feature.

