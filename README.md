# AI-Enhanced DNS Blocklist Manager 🛡️🧠

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/yourusername/yourrepo/graphs/commit-activity)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

A Python-based utility that synchronizes professional DNS blocklists and enhances them using a self-learning heuristic engine (TrackerAI) to identify and block suspicious tracking domains.

## 🌟 Features

* **Upstream Sync:** Automatically fetches and parses the [HaGeZi PRO++](https://github.com/hagezi/dns-blocklists) blocklist.
* **Self-Learning Engine (TrackerAI):** Analyzes domain patterns using entropy calculation and keyword analysis.
* **Reputation System:** Domains gain or lose "reputation points" based on their structure and recurrence.
* **Automatic Cleanup:** Self-pruning logic for false positives and stale entries.
* **Safety First:** Supports whitelisting and creates backups before modifying files.
* **Validation:** Strict domain validation following RFC standards.

## 🛠 How It Works

The script combines static blocklists with an intelligent heuristic analyzer:

1.  **Entropy Analysis:** Identifies procedurally generated domains (DGA) commonly used by trackers.
2.  **Keyword Matching:** Scans for suspicious patterns like `analytics`, `pixel`, `adserver`, etc.
3.  **Persistence:** Maintains a local JSON database (`ai_trackers.json`) to track the history and reputation of domains.
4.  **Auto-Block:** If a domain's reputation falls below the threshold ($\text{score} \le -3$), it is automatically added to the custom blocklist.

## 🚀 Getting Started

### Prerequisites
* Python 3.8 or higher
* `requests` library

### Installation
1. Clone this repository:
   ```bash
   git clone [https://github.com/yourusername/ai-dns-blocklist.git](https://github.com/yourusername/ai-dns-blocklist.git)
   cd ai-dns-blocklist
