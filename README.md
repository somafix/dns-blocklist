# 🛡️ DNS Security Blocklist Builder 

### **Next-Gen Threat Intelligence & AI/ML Domain Filtering**
**Version 17.2.1** • *High-Concurrency Async Engine* • *Production Ready*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic-V2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge&logo=shield-check)](#)

---

## 🎯 Project Overview

**DNS Security Blocklist Builder** is a high-performance orchestration tool designed to aggregate, validate, and categorize threat intelligence feeds into a single, clean security manifest.

Version **v17.2.1** is a "Fixed Production" release focused on data purity. It implements a sophisticated parsing engine that strips out IP addresses, local hosts, and syntax noise common in raw public feeds.

> [!IMPORTANT]
> **What's new in v17.2.1:** 
> * Added **GoodbyeAds-YouTube** and **GoodbyeAds Ultimate** integration.
> * Fixed parsing: Automatically handles AdBlock-style prefixes like `||`, `@@`, and `^`.
> * Strict Regex Validation: Eliminates malformed domains and junk entries.

---

## 🔥 Key Features

### 🛠 Smart Extraction & Cleaning
Unlike basic bash scripts, this engine performs deep inspection of every line:
* **Anti-IP Filtering:** Automatically skips IPv4/IPv6 addresses, ensuring only FQDNs enter the list.
* **Format Normalization:** Converts to lowercase, strips trailing dots, and removes inline comments.
* **Localhost Shield:** Protects critical infrastructure names (localhost, broadcasthost, etc.) from accidental blocking.

### 🤖 AI/ML Smart Categorization
Built-in heuristic analysis identifies Artificial Intelligence infrastructure. The engine automatically tags domains from **OpenAI, Anthropic, Gemini, Midjourney**, and more as `AI_ML`, allowing granular control over AI tool access.

### ⚡ High-Performance Async Engine
Leveraging `AsyncIO` and `aiohttp`, the pipeline processes millions of domains in seconds.
* **Smart Caching:** Full support for `ETag` and `If-Modified-Since` headers to save bandwidth.
* **Memory Optimization:** Uses Python slots and efficient hash-sets for deduplication without bloating RAM.
* **Atomic Writes:** Ensures your production blocklist is never corrupted during the update process.

---

## 📂 Output Anatomy

The generated `blocklist.txt` is fully compatible with **Pi-hole**, **AdGuard Home**, **pfSense (Unbound)**, and **Mikrotik**.

```text
# DNS Security Blocklist - v17.2.1 FIXED
# Total unique domains: 1,842,901
# Stats: 🤖 AI_ML: 1.2k | 💀 MALWARE: 84k | 👁️ TRACKING: 210k

0.0.0.0 api.openai.com # AI_ML
0.0.0.0 doubleclick.net # ADS
0.0.0.0 track.analytics-data.io # TRACKING
0.0.0.0 malware-site.biz # MALWARE
