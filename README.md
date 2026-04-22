# Hosts Update Script

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-brightgreen.svg)

A lightweight, zero-dependency Python utility that automatically fetches, normalizes, and saves blocklists to a clean `hosts.txt` file ready for system use.

## Features

* **Format Normalization:** Automatically converts entries to the standardized `0.0.0.0 domain.com` format.
* **Smart Parsing:** Cleans up input, removes comments, and handles standard hosts file formatting requirements.
* **Zero Dependencies:** Uses only Python's standard library (no `pip install` required).
* **Ready-to-Use Output:** Generates an alphabetical, sorted file with a header containing a timestamp and the total count of blocked entries.

## How It Works

1. **Fetch:** The script downloads the blocklist from the configured URL.
2. **Parse:** It uses regular expressions to extract unique domains and forces a consistent `0.0.0.0` address format.
3. **Save:** It sorts the entries and generates `hosts.txt` with a helpful header.

## Usage

1. Ensure you have **Python 3** installed.
2. Run the script from your terminal:

    ```bash
    python3 main.py
    ```

3. Upon completion, the `hosts.txt` file will be generated in the same directory.

## System Integration

* **Linux/macOS:** You can update your system blocklist by replacing the content of `/etc/hosts` with the generated file (requires `sudo`).
* **Windows:** You can replace the contents of `C:\Windows\System32\drivers\etc\hosts` (requires Administrator privileges).

*Warning: Always make a backup of your existing hosts file before replacing it to prevent connectivity issues.*

## Configuration

You can change the blocklist source by editing the `URLS` list at the top of the script:

```python
URLS = [
    "YOUR_URL_HERE",
]
