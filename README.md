# HaGeZi DNS Blocklist Downloader

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-orange.svg)](https://www.python.org/dev/peps/pep-0008/)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()
[![GitHub](https://img.shields.io/badge/GitHub-HaGeZi-181717.svg)](https://github.com/hagezi/dns-blocklists)

## 📋 Overview

A robust Python script to download, validate, and process the **HaGeZi Multi PRO++ DNS Blocklist** from GitHub. The script converts the source blocklist into a clean `hosts` format file with duplicate removal, domain validation, and automatic backup functionality.

## ✨ Features

- 🔄 **Automatic download** from official HaGeZi GitHub repository
- ✅ **RFC-compliant domain validation** (length, characters, segments)
- 🗑️ **Duplicate removal** using Python sets
- 📁 **Atomic file writing** with temporary files (prevents corruption)
- 💾 **Automatic backup** of previous version
- 🔍 **MD5 hash comparison** to skip identical updates
- ⏱️ **Timeout handling** (30 seconds)
- 📏 **File size limit** (50 MB maximum)
- 🌐 **Proper User-Agent header** (avoids GitHub blocking)
- 📊 **Detailed statistics** (domains found, invalid lines)
- 🛡️ **Comprehensive error handling** (network, HTTP, timeout)

## 🚀 Installation

```bash
# Clone or download the script
wget https://raw.githubusercontent.com/your-repo/hagezi-downloader.py

# Install required dependency
pip install requests
