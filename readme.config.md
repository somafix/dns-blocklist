# personalDNSfilter Configuration & Generator

![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Android%20|%20Windows%20|%20Linux-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-DoT%20|%20DoH-orange?style=for-the-badge)

A high-performance DNS filtering solution based on the **personalDNSfilter** core, optimized for large-scale blocklists. This repository contains the production configuration and the Go-based engine used to aggregate and shard massive domain lists.

## 🛠 DNS Configuration Features

* **Secure Upstream**: Pre-configured with Cloudflare (Security) and Quad9 via **DNS over TLS (DoT)**.
* **Dual-Stack Support**: Full IPv4 and IPv6 compatibility (`ipVersionSupport = 46`).
* **Smart Routing**: Automatic detection of underlying network DNS with VPN-tunneling for Android.
* **Performance Tuning**: 
    * 30-second request timeouts for reliable list updates.
    * 20,000 entry LRU cache for filtered and allowed hosts.
    * Local resolver enabled for instant IP mapping.

## 📋 Blocklist Sources

The generator aggregates domains from the following high-authority sources:

| ID | Source Name | Category | Status |
| :--- | :--- | :--- | :--- |
| `stevenblack` | StevenBlack Hosts | Security | ✅ Active |
| `someonewhocares` | SomeoneWhoCares | Ads/Zero | ✅ Active |
| `anudeepnd` | AnudeepND Blacklist | Tracking | ✅ Active |
| `polishfilters` | KADhosts | Regional | ✅ Active |
| `adaway` | AdAway | General Ads | ⏹ Optional |

## 🚀 Engine Specifications (Go v5.0)

The underlying generator uses an advanced sharding logic to handle millions of domains without high memory overhead:

1.  **Concurrent Fetching**: Uses a worker pool to download multiple sources simultaneously.
2.  **Disk Sharding**: Splits massive datasets into 100 shards based on SHA256 hashes.
3.  **External Merge Sort**: Uses a heap-based multi-way merge to produce a perfectly sorted `blocklist.txt`.
4.  **Automatic TTL**: Disk cache with 24-hour TTL and ETag validation to minimize bandwidth.

## ⚙️ Installation & Usage

### 1. Generate the Blocklist
If you are using the Go engine, compile and run:
```bash
go build -o blockgen main.go
./blockgen
