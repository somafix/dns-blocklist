# DNS Blocklist Manager v4.0.1

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Build](https://img.shields.io/badge/version-4.0.1-orange)

An autonomous tracker blocking system with **AI-driven reputation scoring**. This tool aggregates high-quality blocklists and uses a heuristic engine to identify and "learn" new suspicious domains based on patterns, entropy, and frequency.

---

## 🚀 Key Features

* **AI Reputation Engine**: Tracks domain reputation over time. Domains that repeatedly exhibit suspicious behavior are automatically added to a local blocklist.
* **Heuristic Analysis**: Analyzes domains for high entropy, suspicious keywords (e.g., `analytics`, `telemetry`, `pixel`), and tracking patterns.
* **Smart Caching**: Utilizes `ETag` and `Last-Modified` headers to avoid redundant downloads, saving bandwidth.
* **Self-Healing**: Automatic reputation decay and cleanup of false positives over time.
* **Performance Optimized**: Asynchronous downloading using `aiohttp` and internal DNS caching for scoring.
* **Robust Logging**: Includes log rotation and GZIP compression for old logs.

---

## 🛠 How It Works

1.  **Fetch**: Downloads domains from configured sources (Hagezi, StevenBlack, etc.).
2.  **Score**: Each domain is passed through a heuristic engine:
    * **Entropy Check**: Identifies randomized DGA-like (Domain Generation Algorithm) strings.
    * **Keyword Matching**: Flags strings associated with tracking and ads.
    * **Structure Analysis**: Checks for suspicious subdomains and unusual TLDs.
3.  **Learn**: The `TrackerAI` module updates its internal JSON database. If a domain's reputation falls below a certain threshold, it is permanently blocked.
4.  **Generate**: Merges all sources into a clean `hosts.txt` file ready for use in Pi-hole, AdGuard, or system-level blocking.

---

## 📂 Project Structure

| File | Description |
| :--- | :--- |
| `hosts.txt` | The final generated blocklist. |
| `ai_trackers.json` | The "brain" — stores reputation, frequency, and timestamps. |
| `ai_custom_blocklist.txt` | Domains identified and blocked by the AI. |
| `ai_whitelist.txt` | User-defined safe domains (overrides AI blocking). |
| `etag_cache.json` | Metadata for conditional HTTP downloads. |

---

## ⚙️ Configuration

You can find the `CONFIG` dictionary at the top of the script to tune the behavior:

```python
CONFIG = {
    "reputation_threshold": 5.0,    # Score to reach for unblocking
    "reputation_block_at": -3.0,   # Score to reach for blocking
    "reputation_decay": 0.05,      # Periodic score normalization
    "max_file_size_mb": 50,        # Limit for downloaded lists
}
