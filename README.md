# 🛡️ ADBlock Hosts Updater

[![Daily Update](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/update.yml/badge.svg)](https://github.com/YOUR_USERNAME/YOUR_REPO/actions/workflows/update.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-FFD43B?style=for-the-badge&logo=mit&logoColor=black)](https://opensource.org/licenses/MIT)
[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)](https://github.com/features/actions)

---

## 📋 Overview

**ADBlock Hosts Updater** is an automated daily script that fetches, cleans, and compiles a premium blocklist into standard `0.0.0.0` hosts format. No duplicates. No bloat. Just works.

### 🎯 Use Cases

| Platform | Integration |
|----------|-------------|
| Pi-hole | `/etc/pihole/adlists.list` |
| AdGuard Home | URL-based blocklist |
| NextDNS | Deny list |
| uBlock Origin | Import as hosts file |
| Any hosts file | Direct replacement |

---

## ⚡ Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO
python update.py
