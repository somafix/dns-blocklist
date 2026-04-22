# ADBlock Hosts Updater

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

A lightweight Python utility designed to aggregate, sanitize, and merge multiple community-maintained hosts lists into a single, optimized `hosts.txt` file. This is ideal for system-level blocking of advertisements, tracking scripts, and malicious domains.

## Features

* **Multi-Source Aggregation:** Fetches data from multiple reputable sources (StevenBlack, someonewhocares, KADhosts).
* **Intelligent Parsing:** Uses Regular Expressions to validate entries and strip out junk comments or malformed lines.
* **Deduplication:** Automatically removes duplicate domain entries using Python sets.
* **Optimized Output:** Sorts all entries alphabetically to ensure the file is clean and manageable.
* **Standard Library Only:** No external dependencies required (no `pip install` needed).

## How It Works

1.  **Fetch:** The script iterates through the `SOURCES` list, downloading raw content from each URL.
2.  **Parse:** It filters lines using regex to ensure only valid `0.0.0.0` or `127.0.0.1` formatted domain entries are captured.
3.  **Merge & Clean:** All entries are placed into a set to enforce uniqueness.
4.  **Export:** Generates a new `hosts.txt` file with a timestamp and total entry count header.

## Usage

1.  Ensure you have **Python 3** installed.
2.  Save your script as `update_hosts.py`.
3.  Run the script from your terminal:

    ```bash
    python3 update_hosts.py
    ```

4.  Upon completion, you will find a generated `hosts.txt` file in the same directory.

## Configuration

You can add or remove sources by modifying the `SOURCES` list at the top of the script:

```python
SOURCES = [
    "URL_TO_HOSTS_FILE_1",
    "URL_TO_HOSTS_FILE_2",
    # ...
]
