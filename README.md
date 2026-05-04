# DNS Blocklist Manager v3.0

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Version](https://img.shields.io/badge/version-3.0.0-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Security](https://img.shields.io/badge/AI-Self--Learning-purple)

A high-performance, autonomous DNS blocklist management system. This tool merges popular blocklists and uses a built-in **Self-Learning AI Tracker** to identify and block suspicious domains (trackers, telemetry, and ads) based on pattern analysis and entropy scoring.

## 🚀 Key Features

* **Autonomous Analysis:** Uses heuristic analysis and Shannon entropy to detect suspicious domain names automatically.
* **Reputation System:** Maintains a local database (`ai_trackers.json`) where domains gain or lose reputation over time.
* **Smart Whitelisting:** Prevents blocking of critical infrastructure (Cloudflare, AWS, Google APIs) via a built-in exception list and a custom `ai_whitelist.txt`.
* **Multi-threaded Engine:** High-speed processing using `ThreadPoolExecutor` for both downloads and domain analysis.
* **Log Rotation:** Automatic log management with GZIP compression to save disk space.
* **DNS Caching:** Internal cache to speed up repeated domain evaluations.

## 🛠 How It Works



The script follows a 4-step process:
1.  **Download:** Fetches the latest hosts files from verified sources (Hagezi, StevenBlack).
2.  **Analysis:** Scans domains for suspicious patterns (e.g., long hex strings, tracking keywords, high character entropy).
3.  **Training:** Updates the local AI database. If a domain consistently looks like a tracker, it is added to the `ai_custom_blocklist.txt`.
4.  **Generation:** Merges all sources into a single, optimized `hosts.txt` file ready for use.

## 📋 Requirements

* Python 3.8 or higher
* `requests` library

To install dependencies:
```bash
pip install requests
