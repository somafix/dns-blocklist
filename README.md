# 🛡️ DNS Security Blocklist Builder 

### **Zero-Config • Fully Autonomous • AI-Powered Security**
**Version 17.2.1 (Autonomous Edition)** • *High-Concurrency Async Engine*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic-V2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Self-Installing](https://img.shields.io/badge/Dependencies-Auto--Install-green?style=for-the-badge&logo=unrealengine)](#)

---

## 🎯 Project Overview

The **DNS Security Blocklist Builder** is an enterprise-grade orchestration tool designed to aggregate, validate, and categorize global threat intelligence into a single, optimized manifest.

The **Autonomous Edition** is built for "Set and Forget" operation. It removes the need for manual environment preparation by managing its own lifecycle—from dependency installation to final compression.

> [!IMPORTANT]
> **Zero Manual Intervention:** The script features a self-bootstrapping layer. It detects missing libraries (`aiohttp`, `pydantic`, `tenacity`, `numpy`, etc.) and installs them via `pip` automatically before execution.

---

## 🔥 Key Features

### 🚀 Self-Bootstrapping Engine
No more `pip install -r requirements.txt`. On launch, the script:
* **Environment Scan:** Checks for all required Python packages.
* **Auto-Repair:** Silently installs missing dependencies in the background.
* **Workspace Setup:** Automatically initializes cache directories and output paths.

### 🤖 AI/ML Infrastructure Detection
Integrated heuristic analysis identifies domains used by Artificial Intelligence services (OpenAI, Anthropic, Gemini, Midjourney, etc.). These are tagged as `AI_ML`, giving you granular control over AI tool access in your network.

### ⚡ Production-Grade Cleansing
* **Strict Validation:** Strips AdBlock noise (`||`, `^`), removes IP addresses, and ignores local network hostnames.
* **Duplicate Suppression:** Efficiently de-duplicates millions of domains using high-performance sets.
* **Resource Efficient:** Powered by `AsyncIO` for non-blocking I/O and optimized for low memory footprint.

---

## 📂 Output Anatomy

The script generates a unified `blocklist.txt` (and a compressed `.gz` version) compatible with **Pi-hole**, **AdGuard Home**, **pfSense**, and **Mikrotik**.

```text
# DNS Security Blocklist
# Generated: 2026-04-02T16:32:00Z
# Total domains: 1,842,901
# Category breakdown:
#   AI_ML: 1,240
#   MALWARE: 84,120
#   TRACKING: 210,050

0.0.0.0 api.openai.com # AI_ML
0.0.0.0 doubleclick.net # ADS
0.0.0.0 track.analytics-data.io # TRACKING
