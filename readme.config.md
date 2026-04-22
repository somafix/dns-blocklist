# 🛡️ personalDNSfilter Configuration

![Version](https://img.shields.io/badge/version-3.x-blue)
![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-Proprietary-green)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

[![DNS](https://img.shields.io/badge/DNS-over--TLS-1f8acb)](https://www.zenz-solutions.de/personaldnsfilter-wp/)
[![Ad Blocking](https://img.shields.io/badge/Ad%20Blocking-Active-red)](https://github.com/somafix/dns-blocklist)
[![Android](https://img.shields.io/badge/Android-VPN%20%7C%20Root-3DDC84)](https://www.zenz-solutions.de/personaldnsfilter-wp/)

> ⚠️ **WARNING! FOR EXPERTS ONLY!**  
> This is personalDNSfilter configuration! Only edit this file if you are an expert!


## ✨ Features

| Feature | Status | Description |
|---------|--------|-------------|
| DNS-over-TLS | ✅ | Encrypted DNS with Cloudflare & Quad9 |
| Ad Blocking | ✅ | Multiple blocklists support |
| IPv4/IPv6 | ✅ | Dual stack support |
| Local Resolver | ✅ | Built-in DNS resolver |
| Traffic Logging | ⚙️ | Optional with rotation |
| Remote Control | ⚙️ | Configurable via keyphrase |

## 🚀 Quick Start

### Basic Configuration
```ini
# Enable DNS detection and filtering
detectDNS = true
filterActive = true

# DNS servers (DoT)
fallbackDNS = 1.1.1.2::853::DoT::security.cloudflare-dns.com; 9.9.9.9::853::DoT::dns.quad9.net

# Local resolver
enableLocalResolver = true
localResolverTTL = 600
