# DNS Blocklist Processor

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![Requests](https://img.shields.io/badge/dependency-requests-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Overview
A lightweight Python utility designed to fetch, filter, and normalize the **HaGeZi Pro++ DNS Blocklist**. This script automates the process of retrieving the raw blocklist, cleaning it by removing duplicates and invalid entries, and generating a local `hosts.txt` file configured for system-wide ad and tracker blocking.

## Features
* **Automated Fetching:** Automatically downloads the latest blocklist from the HaGeZi repository.
* **Data Cleaning:** Filters out comments, empty lines, and malformed domain entries using Regex.
* **Deduplication:** Ensures all blocked domains are unique using Python sets.
* **Ready-to-use Format:** Exports a clean `hosts.txt` file with the standard `0.0.0.0` prefix.

## Requirements
* Python 3.x
* `requests` library

## Installation
1. Ensure you have Python 3 installed.
2. Install the required `requests` library via pip:
   ```bash
   pip install requests
