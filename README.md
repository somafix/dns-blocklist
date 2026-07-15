# DNS Blocklist Manager

![Version](https://img.shields.io/badge/version-11.0.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-production-brightgreen.svg)

A professional, high-performance tool designed to aggregate, filter, and generate custom DNS blocklists in `hosts` format.

## Features

*   **Asynchronous Processing:** High-speed network operations using `aiohttp` for parallel downloads.
*   **Custom Filtering:** Support for individual whitelisting, blacklisting, and wildcard domain filtering.
*   **Production Ready:** Includes robust logging with file rotation, automatic backup management, and detailed build statistics.
*   **Reliable:** Built-in retry mechanisms and rigorous domain validation.
*   **Lightweight:** No external databases required; works directly with text-based list management.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd dns-blocklist-manager
    ```

2.  **Install dependencies:**
    ```bash
    pip install aiohttp
    ```

## Usage

Run the script directly from your terminal:

```bash
python3 main.py
