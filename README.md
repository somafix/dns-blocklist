# 🏆 Dynamic DNS Blocklist Builder

### Enterprise-Grade Threat Intelligence Platform  
### v6.0.1 | Async Architecture | Maximum Security & Performance

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge)](https://www.python.org/)
[![Security: HARDENED](https://img.shields.io/badge/Security-HARDENED-red?style=for-the-badge)]()
[![Performance: MAX](https://img.shields.io/badge/Performance-MAXIMUM-brightgreen?style=for-the-badge)]()
[![Version: 6.0.1](https://img.shields.io/badge/Version-6.0.1-blue?style=for-the-badge)]()

---

## 🎯 EXECUTIVE SUMMARY

Enterprise-grade asynchronous DNS blocklist builder with full configuration control, observability, and modular architecture.

- ✅ Fully async (aiohttp + asyncio)
- ✅ YAML + CLI configuration
- ✅ Source filtering (include/exclude) — FIXED
- ✅ LRU-cached domain validation
- ✅ Prometheus metrics (optional)
- ✅ Health check server
- ✅ Multi-format output (hosts/dnsmasq/unbound)
- ✅ Gzip compression
- ✅ Clean SOLID architecture

---

## 🚀 KEY FEATURES

### Performance
- ⚡ Concurrent downloads (10 sources)
- ⚡ ~10K domains/sec processing
- ⚡ Batch processing (10K)
- ⚡ Low memory footprint
- ⚡ Async I/O everywhere

### Security
- 🔒 Domain validation (RFC compliant)
- 🔒 Resource limits (memory / CPU / size)
- 🔒 SSL verification control
- 🔒 Trusted sources whitelist
- 🔒 Source filtering (include/exclude)

### Observability
- 📊 Prometheus metrics (optional)
- 📊 Build metrics (speed, memory, sources)
- 📊 Health check HTTP server
- 📊 Structured logging

---

## 📊 CHANGELOG v6.0.1

- FIX: include_sources / exclude_sources added
- FIX: source filtering logic
- ADD: YAML config support
- ADD: Health check server
- ADD: Prometheus metrics
- ADD: Output compression (gzip)
- ADD: Multi-format output
- ADD: Build metrics system
- ADD: Optional dependency loader
- IMPROVED: Full async refactor

---

## 🧠 ARCHITECTURE

SecurityBlocklistBuilder  
├── SourceManager  
│   ├── SourceFetcher (async HTTP)  
│   └── SourceParser (multi-format)  
├── DomainValidator (LRU cache)  
├── DomainProcessor (deduplication)  
├── OutputGenerator (formats + gzip)  
├── MetricsCollector  
└── HealthCheckServer  

---

## ⚙️ CONFIGURATION (YAML)

```yaml
max_domains: 500000
timeout_seconds: 30
max_retries: 3

include_sources: []
exclude_sources: []

output_path: dynamic-blocklist.txt
output_format: hosts
output_compression: false

metrics_enabled: false
health_check_enabled: true
```

---

## 🖥 CLI

```bash
python3 blocklist_builder.py
```

Options:
```
--config config.yaml
--output output.txt
--format hosts|dnsmasq|unbound|domains
--max-domains 500000
--include StevenBlack OISD
--exclude AdAway
--list-sources
-v
```

---

## 📦 OUTPUT FORMATS

hosts:
```
0.0.0.0 example.com
```

dnsmasq:
```
address=/example.com/0.0.0.0
```

unbound:
```
local-zone: "example.com" always_nxdomain
```

---

## 📡 HEALTH CHECK

```
http://127.0.0.1:8080
```

Response:
```
{"status":"healthy","version":"6.0.1"}
```

---

## 📊 METRICS

Enable:
```yaml
metrics_enabled: true
metrics_port: 9090
```

---

## 🌐 SOURCES

- StevenBlack  
- OISD  
- AdAway  
- URLhaus  
- ThreatFox  
- CERT.PL  
- SomeoneWhoCares  

---

## ⚡ PERFORMANCE

- Async concurrent downloads  
- Batch size: 10K  
- LRU cache  
- Complexity: O(n)  

---

## 🛠 DEPLOYMENT

- Cron  
- Docker  
- GitHub Actions  
- VPS  
- Serverless  

---

## 📁 OUTPUT FILES

- dynamic-blocklist.txt  
- dynamic-blocklist.txt.backup  
- dynamic-blocklist.txt.gz  

---

## 🔐 SECURITY CONFIG

- max_domains  
- memory_limit_mb  
- timeout_seconds  
- trusted_sources  
- allowed_domains  
- blocked_domains  

---

## 📌 QUICK START

```bash
python3 blocklist_builder.py
```

---

## 📝 LICENSE

MIT

---

## 🧾 VERSION

6.0.1 — Async Refactored + Config-Driven + Metrics + Health Checks
