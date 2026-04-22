# ADBlock Hosts Updater

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Sources](https://img.shields.io/badge/sources-9-blueviolet.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

A powerful, zero-dependency Python utility that aggregates multiple high-reputation blocklists into a single, optimized `hosts.txt` file. This script provides robust protection against advertisements, tracking servers, pop-ups, and known malicious/hacked domains.

## Features

* **Comprehensive Coverage:** Aggregates feeds from 9 major reputable sources, including StevenBlack, Anudeep, and specialized malware databases.
* **Intelligent Parsing:** Uses Regular Expressions to validate and normalize entries, ensuring they conform to the standard `0.0.0.0 domain.com` format.
* **Deduplication:** Automatically handles overlaps between lists, ensuring the generated file is compact and performant.
* **Zero-Dependency:** Uses standard Python libraries only. No need to install `pip` packages.
* **Automated Export:** Generates a clean, sorted, and timestamped file ready for system-level use.

## Included Sources

The script fetches and merges data from the following authoritative lists:

* **StevenBlack (Base + Variants):** The industry standard for ad/tracking blocking.
* **Anudeep (Adservers):** Highly curated list of advertising and tracking servers.
* **Anti-popads:** Specialized blocking for intrusive pop-ups.
* **hostsVN:** Optimized list for regional threats and ads.
* **Ultimate Hosts Blacklist:** Focused on active malware, phishing, and hacked websites.
* **Someonewhocares & KADhosts:** Additional community-verified entries.

## Usage

1.  Ensure you have **Python 3** installed.
2.  Run the script from your terminal:

    ```bash
    python3 update_hosts.py
    ```

3.  Upon completion, the script will generate a `hosts.txt` file in the same directory.

## Configuration

To add or remove specific blocklists, simply modify the `SOURCES` list at the top of the `update_hosts.py` file:

```python
SOURCES = [
    "URL_1",
    "URL_2",
    # Add or remove URLs here
]
