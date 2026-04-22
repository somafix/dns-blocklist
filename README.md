[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DNS Blocklist](https://img.shields.io/badge/DNS%20Blocklist-HaGeZi%20PRO%2B%2B-orange)](https://github.com/hagezi/dns-blocklists)

# DNS Blocklist Downloader

> Downloads, parses, and processes HaGeZi Multi PRO++ DNS blocklist with automatic deduplication.

## 🎯 Features

- Fetches latest blocklist from HaGeZi GitHub
- Domain validation with regex filtering
- Automatic deduplication
- Hosts file format output (`0.0.0.0 domain`)
- Timestamped metadata
- Only requires `requests` library

## 📋 Requirements

- Python 3.7+
- `requests` library

## 🚀 Quick Start

```bash
# Install dependencies
pip install requests

# Run
python dns_blocklist_downloader.py
```

Output: `hosts.txt` with 200k+ unique domains

## 📝 How It Works

1. Downloads blocklist from HaGeZi GitHub
2. Parses and validates domains (regex: `^[a-z0-9\.\-]+$`)
3. Removes duplicates using Python sets
4. Generates sorted hosts file with metadata

## 🔧 Configuration

Edit top of script:
```python
URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt"
OUTPUT_FILE = "hosts.txt"
```

## 📖 Use Cases

- Pi-hole integration
- AdGuard Home filters
- Local DNS servers (Windows/macOS/Linux)
- Network-wide ad blocking
- Privacy enhancement

## 🔐 Security

- HTTPS-only downloads
- Regex validation prevents injection
- No external execution
- Trusted official source

## 🔄 Automation

**Linux/macOS Cron:**
```bash
0 2 * * * /usr/bin/python3 /path/to/dns_blocklist_downloader.py
```

**Windows Task Scheduler:**
- Trigger: Daily 2:00 AM
- Program: `python.exe`
- Arguments: `C:\path\to\dns_blocklist_downloader.py`

## 📜 License

MIT License

## 🔗 Resources

- [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists)
- [Pi-hole](https://pi-hole.net/)
- [AdGuard Home](https://adguard.com/adguard-home/overview.html)
