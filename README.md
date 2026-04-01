# 🛡️ DNS Security Blocklist Builder (All-in-One)

### Enterprise-Grade Threat Intelligence & AI/ML Domain Filtering
### v17.2.0 | Production-Ready | High-Performance Async Architecture

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge)](https://www.python.org/)
[![Security: HARDENED](https://img.shields.io/badge/Security-HARDENED-red?style=for-the-badge)](#-security-hardening)
[![Performance: MAXIMUM](https://img.shields.io/badge/Performance-MAXIMUM-brightgreen?style=for-the-badge)](#-performance-tier)
[![AI Detection: AI/ML](https://img.shields.io/badge/AI_Detection-AI%2FML_PATTERNS-purple?style=for-the-badge)](#-aiml-detection)
[![Output: blocklist.txt](https://img.shields.io/badge/Output-blocklist.txt-blue?style=for-the-badge)](#-output-files)

---

## 🎯 EXECUTIVE SUMMARY

Version **17.2.0** is a completely reimagined tool for creating consolidated DNS blocklists. All the power of previous versions is now packed into a streamlined process that generates a single, metadata-enriched `blocklist.txt` file.

### Key Features:
- ✅ **All-in-One Output**: Entire result in one `blocklist.txt` file with integrated comments and categories.
- ✅ **AI/ML Category**: Specialized detection of domains related to Artificial Intelligence (ChatGPT, Claude, Gemini, etc.).
- ✅ **Pydantic V2 Integration**: Strict "on-the-fly" validation of configuration and data models.
- ✅ **Smart Categorization**: Automatic tagging for `ADS`, `TRACKING`, `MALWARE`, and `AI_ML`.
- ✅ **Async Persistence**: Fully asynchronous network and file system operations (`aiohttp`, `aiofiles`).
- ✅ **Gzip Native**: Automatic compression of the final list to save bandwidth.

---

## 📁 OUTPUT FILES

### Main Blocklist
**Filename:** `blocklist.txt`  
**Format:** Standard `hosts` file (`0.0.0.0 domain.com`) with enhanced comments.  
**Compatibility:** Pi-hole, AdGuard Home, dnsmasq, Unbound, and most DNS firewalls.

**Example Content:**
```text
# DNS Security Blocklist - All-in-One
# Generated: 2026-04-01T10:11:00Z
# Total domains: 1,245,302
# Category breakdown:
#   🤖 AI_ML: 1,240
#   💀 MALWARE: 45,201
#   👁️ TRACKING: 180,432

0.0.0.0 chatgpt.com # 🤖 AI_ML
0.0.0.0 analytics.google.com # 👁️ TRACKING
0.0.0.0 doubleclick.net # 📢 ADS
0.0.0.0 malware-site.xyz # 💀 MALWARE
