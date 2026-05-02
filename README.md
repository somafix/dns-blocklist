# 🛡️ AI-Enhanced DNS Blocklist Updater

![Version](https://img.shields.io/badge/version-2.3.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Status](https://img.shields.io/badge/status-active-brightgreen)

An advanced DNS blocklist manager that combines the industry-standard **HaGeZi Pro++** list with a **local AI-driven heuristics engine**. It learns to identify and block new trackers based on entropy, suspicious patterns, and reputation scoring.

---

## ✨ Key Features

* **Dual-Layer Protection**: Integrates the comprehensive [HaGeZi Pro++](https://github.com/hagezi/dns-blocklists) blocklist.
* **AI Heuristics Engine**: Analyzes domains using Shannon entropy, keyword scoring, and pattern matching to catch zero-day trackers.
* **Reputation System**: Remembers domain behavior over time. Persistent "suspicious" domains are permanently blocked, while false positives are automatically rehabilitated.
* **Self-Cleaning**: Features an auto-cleanup mechanism for stale or redeemed domains after 30 days.
* **Safety First**: Built-in whitelist and exceptions for critical services (Cloudflare, AWS, Google APIs, etc.) to prevent breakage.
* **Atomic Updates**: Uses temporary files and backups to ensure your `hosts.txt` is never corrupted during an update.

---

## 🚀 How It Works

The script follows a sophisticated logic flow to ensure maximum privacy with minimum breakage:

1.  **Download**: Fetches the latest HaGeZi Pro++ list.
2.  **Analyze**: Runs a heuristic analysis on the top 10,000 most suspicious domains.
3.  **Learn**: 
    * Domains with high entropy (random-looking strings) or tracking keywords gain negative reputation.
    * Once a domain hits a threshold score ($\le -3$), it is added to the `ai_custom_blocklist.txt`.
4.  **Consolidate**: Merges the main list with AI-learned domains.
5.  **Output**: Generates a standard `hosts.txt` file ready for use in Pi-hole, AdGuard Home, or system-level blocking.

---

## 🛠️ Configuration

The script uses several local files to manage its state:

| File | Description |
| :--- | :--- |
| `hosts.txt` | The final generated blocklist (0.0.0.0 format). |
| `ai_trackers.json` | The AI "brain" containing reputation and history. |
| `ai_custom_blocklist.txt` | Domains identified and blocked by the AI. |
| `ai_whitelist.txt` | User-defined domains that should never be blocked. |

---

## 📦 Installation & Usage

### Prerequisites
* Python 3.7 or higher
* `requests` library

```bash
pip install requests
