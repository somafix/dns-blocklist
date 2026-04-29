# AI-Powered DNS Blocklist Generator

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

An intelligent script that combines industry-standard DNS blocklists with a **self-learning AI engine** to detect and block trackers, telemetry, and suspicious domains.

## 🚀 Overview

This tool fetches the [HaGeZi PRO++](https://github.com/hagezi/dns-blocklists) blocklist and augments it using a local heuristic "AI" analyzer. It evaluates domains based on entropy, suspicious patterns, and reputation history to create a personalized, evolving `hosts.txt` file.

## 🧠 Smart Features

* **Entropy Analysis**: Detects algorithmically generated domains (DGA) by calculating the information density of domain segments.
* **Reputation System**: Maintains a local JSON database (`ai_trackers.json`) that tracks domain "behavior" over time.
* **Heuristic Engine**: Scores domains based on:
    * Subdomain depth.
    * Presence of suspicious keywords (analytics, metrics, pixel, etc.).
    * Abnormal character patterns (excessive digits, underscores, or long strings).
    * Non-standard TLD structures.
* **Automated Backups**: Automatically creates a `hosts.backup` before applying updates.

## 🛠 Installation

1. **Clone the repository**:
   ```bash
   git clone [https://github.com/yourusername/your-repo-name.git](https://github.com/yourusername/your-repo-name.git)
   cd your-repo-name
