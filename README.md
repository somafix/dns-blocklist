# 🛡️ DNS Blocklist Manager v4.0.1
### *Autonomous Tracker Blocking with AI-Powered Reputation Scoring*

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-4caf50?style=for-the-badge)
![AI-Powered](https://img.shields.io/badge/Engine-AI--Heuristics-blueviolet?style=for-the-badge&logo=google-gemini&logoColor=white)
![Stability](https://img.shields.io/badge/Status-Production--Ready-success?style=for-the-badge)

---

## 📖 Overview

**DNS Blocklist Manager** is a sophisticated network privacy tool that goes beyond simple host aggregation. It implements a heuristic analysis engine to detect hidden trackers, telemetry endpoints, and suspicious domains using pattern recognition and behavioral scoring.

Unlike static blacklists, this system "learns" by analyzing domain entropy, frequency of appearance, and structural anomalies, creating a dynamic defense layer for your network.

---

## ✨ Key Features

* **🧠 AI Heuristic Engine**: Scores domains based on Shannon entropy, suspicious keywords (e.g., `telemetry`, `analytics`), and DGA-like (Domain Generation Algorithm) patterns.
* **📉 Reputation Lifecycle**: Implements a credit-based system. Domains are automatically blocked or "paroled" based on their calculated reputation over time.
* **⚡ High-Performance Async**: Built on `aiohttp`, allowing the system to process hundreds of thousands of entries concurrently without blocking.
* **💾 Smart ETag Caching**: Minimizes bandwidth usage by utilizing `ETag` and `Last-Modified` headers to skip redundant downloads.
* **🛡️ Self-Healing Database**: Features automatic reputation decay and false-positive cleanup to ensure the blocklist stays lean and accurate.
* **📝 Enterprise Logging**: Advanced logger with GZIP rotation support and configurable backup retention.

---

## 🛠 Architecture & Logic

The system is modularized into specialized components:

| Component | Responsibility |
| :--- | :--- |
| **`TrackerAI`** | The "Brain". Handles scoring, reputation decay, and learning persistence. |
| **`DNSCache`** | Performance optimizer that caches analysis results to reduce CPU cycles. |
| **`ETagCache`** | Manages HTTP conditional headers and local mirror storage. |
| **`Logger`** | Handles event tracking with automated rotation and compression. |

### Scoring Heuristics
- **Entropy Analysis**: Detects randomized, machine-generated subdomains.
- **Keyword Detection**: Flags industry-standard tracking terminology.
- **Pattern Matching**: Identifies common ad-server naming conventions.
- **Frequency Weighting**: Domains seen across multiple lists gain higher suspicion weight.

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.8+ installed.

### 2. Install Dependencies
```bash
pip install aiohttp
