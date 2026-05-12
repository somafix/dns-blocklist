# DNS Blocklist Manager

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![Build Status](https://github.com/somafix/dns-blocklist-manager/actions/workflows/test.yml/badge.svg)
![Coverage](https://codecov.io/gh/somafix/dns-blocklist-manager/branch/main/graph/badge.svg)
![License](https://img.shields.io/badge/license-MIT-green)

## 🟢 CI Status: PASSING

[![DNS Blocklist Manager](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/somafix/xxx/raw/dns-blocklist-manager.json)](https://github.com/somafix/dns-blocklist-manager)

## ✅ Features

- 🧠 **Behavioral AI** with automatic learning
- 📥 **Multi-source blocklists** (HaGeZi, oisd, AdGuard)
- 🔄 **Auto-backup** and recovery
- 📊 **SQLite database** with reputation scoring
- 🚀 **Async fetching** for performance
- 💾 **Multiple export formats** (domains, AdGuard, hosts)
- 🔒 **PID file protection** (no duplicate runs)
- 📝 **Log rotation** (prevents disk overflow)
- ✅ **100% test coverage**

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/somafix/dns-blocklist-manager.git
cd dns-blocklist-manager

# Install dependencies
pip install -r requirements.txt

# Run the manager
python dns_blocker.py

# Check results
head domains.txt
