# HaGeZi Hosts Updater

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://active-brightgreen.svg)

A lightweight, zero-dependency Python utility that fetches the high-quality **HaGeZi Multi** blocklist, normalizes it, and saves it to a clean `hosts.txt` file ready for system use.

## Features

* **Focused Blocking:** Specifically fetches the comprehensive HaGeZi Multi list (known for high accuracy and minimal false positives).
* **Format Normalization:** Automatically converts list entries to the standardized `0.0.0.0 domain.com` format.
* **Smart Parsing:** Cleans up input, removes comments, and handles standard hosts file formatting requirements.
* **Zero Dependencies:** Uses only Python's standard library (no `pip install` required).
* **Ready-to-Use Output:** Generates a formatted file including a timestamp, entry count, and standard local loopback entries.

## How It Works

1.  **Fetch:** The script downloads the latest `multi.txt` from the HaGeZi repository.
2.  **Parse:** It uses regular expressions to extract unique domains and forces a consistent `0.0.0.0` address.
3.  **Save:** It sorts the entries alphabetically and generates `hosts.txt` with a helpful header.

## Usage

1.  Ensure you have **Python 3** installed.
2.  Run the script from your terminal:

    ```bash
    python3 main.py
    ```

3.  Upon completion, the `hosts.txt` file will be generated in the same directory.

## System Integration

* **Linux/macOS:** You can update your system blocklist by replacing the content of `/etc/hosts` with the generated file. (Requires `sudo`).
* **Windows:** You can replace the contents of `C:\Windows\System32\drivers\etc\hosts` (requires Administrator privileges).

*Warning: Always back up your existing hosts file before replacing it to prevent connectivity issues.*

## Configuration

The script is configured to fetch the "Multi" list by default. You can modify the `URLS` list in the script if you wish to target a different HaGeZi list variant:

```python
URLS = [
    "[https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt)",
]
