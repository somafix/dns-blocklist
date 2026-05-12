# DNS Blocklist Manager

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue?logo=python)
![Version](https://img.shields.io/badge/version-6.0.0-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A high-performance, asynchronous Python utility designed to aggregate, clean, and format DNS blocklists. It merges multiple sources, applies custom filters, and exports the results into several industry-standard formats.

## 🚀 Features

*   **Asynchronous Fetching:** Uses `aiohttp` for concurrent downloads, making the process significantly faster.
*   **Smart Cleaning:** Automatically strips prefixes (`0.0.0.0`, `||`, `http://`), removes comments, and validates domain structures using Regex.
*   **Multiple Export Formats:**
    *   **Plain Domain List:** Standard `domains.txt`.
    *   **AdGuard/uBlock:** `adguard_list.txt` using the `||domain.com^` syntax.
    *   **Hosts File:** `hosts.txt` mapped to `0.0.0.0`.
*   **Custom Filtering:** Local `whitelist.txt` and `blacklist.txt` support to fine-tune your results.
*   **Safety First:** 
    *   **Automatic Backups:** Existing lists are backed up to the `/backup` folder with timestamps before every run.
    *   **PID Locking:** Prevents multiple instances from running simultaneously.
    *   **Logging:** Detailed rotating logs stored in `/logs`.
