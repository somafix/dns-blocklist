# 🛡️ DNS Blocklist Manager

![Version](https://img.shields.io/badge/version-4.0.0-00e5ff?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11+-00e5ff?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-2ed573?style=flat-square)
![Domains](https://img.shields.io/badge/sources-2_blocklists-ffa502?style=flat-square)
![Async](https://img.shields.io/badge/async-aiohttp-a855f7?style=flat-square)
![CI](https://img.shields.io/github/actions/workflow/status/somafix/dns-blocklist/update.yml?style=flat-square&label=auto-update)
![Last Update](https://img.shields.io/github/last-commit/somafix/dns-blocklist?style=flat-square&label=last+update)

> Autonomous DNS blocklist builder with self-learning AI reputation engine, async downloading, ETag caching, and multi-format output.

---

## ✨ Features

- **Async downloader** — parallel fetching via `aiohttp` with `TCPConnector`
- **ETag / Last-Modified caching** — skips re-downloading unchanged lists (304 Not Modified)
- **AI reputation engine** — frequency-weighted scoring with daily decay
- **Self-learning blocklist** — domains auto-added/removed based on reputation history
- **DNS in-memory cache** — TTL-based cache with hit rate tracking
- **Entropy analysis** — detects randomly generated domains (DGA)
- **Log rotation** — gzip-compressed log backups
- **Atomic writes** — `tempfile` + `shutil.move` prevents partial writes
- **Whitelist support** — never block legitimate domains
- **GitHub Actions ready** — runs on schedule every 12 hours

---

## 📦 Sources

| # | Source | Description |
|---|--------|-------------|
| 1 | [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) | Pro Plus — ads, trackers, malware |
| 2 | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | Fakenews + gambling + porn |

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install aiohttp aiofiles requests

# Run
python update.py
```

Output: `hosts.txt` — ready to use as a system hosts file or DNS blocklist.

---

## 🤖 AI Reputation Engine

The engine assigns each domain a reputation score that evolves over time:

| Event | Score delta |
|-------|-------------|
| Domain flagged as suspicious | `-(1.0 + frequency × 0.3)` |
| Domain seen in whitelist | `+1.0` |
| Domain passes all checks | `+0.5` |
| Daily decay (every run) | `× 0.95` |

**Block threshold:** reputation ≤ `-3.0`  
**Unblock threshold:** reputation ≥ `+5.0`  
**Frequency bonus:** capped at `3.0` — the more often a domain appears, the faster it gets blocked.  
**Decay:** domains that stop appearing gradually recover reputation over time.

---

## 🔍 Suspicion Scoring

Each domain is scored across multiple signals:

```
Subdomain depth > 5              +2
Segment length > 20 chars        +1
Numeric sequence (5+ digits)     +2
Underscore in segment            +1
High entropy (≥15 chars, >3.5)   +2
Suspicious keyword match         +2
Regex pattern match              +1 each
Short non-standard SLD (≤3 chr)  +2
```

**Threshold:** score ≥ 4 → suspicious  
**Exceptions:** `cloudflare`, `amazonaws`, `googleapis`, `github`, `cdn`, `cloudfront`, `akamaiedge`, `fastly`, `stackpath`

---

## 📁 File Structure

```
dns-blocklist/
├── update.py                  # Main script
├── hosts.txt                  # Generated blocklist (hosts format)
├── hosts.backup               # Previous version backup
├── ai_trackers.json           # Reputation database
├── ai_custom_blocklist.txt    # AI-learned domains
├── ai_whitelist.txt           # Whitelisted domains (user-managed)
├── etag_cache.json            # HTTP ETag/Last-Modified cache
└── dns_blocker.log            # Rotating log file
```

---

## ⚙️ Configuration

All settings are in the `CONFIG` dict at the top of `update.py`:

```python
CONFIG = {
    "urls": [...],               # Blocklist sources
    "timeout": 30,               # HTTP timeout (seconds)
    "max_file_size_mb": 50,      # Max download size
    "max_domains_to_analyze": 100_000,
    "cleanup_days": 30,          # Remove unseen domains after N days
    "reputation_block_at": -3.0, # Block threshold
    "reputation_threshold": 5.0, # Unblock threshold
    "reputation_decay": 0.05,    # Daily decay factor
    "frequency_weight": 0.3,     # Frequency penalty weight
    "dns_cache_ttl": 3600,       # In-memory cache TTL (seconds)
}
```

---

## 📋 Whitelist

Add domains to `ai_whitelist.txt` (one per line) to prevent them from ever being blocked:

```
# ai_whitelist.txt
example.com
my-trusted-domain.net
```

---

## 🔄 GitHub Actions

Auto-updates every 12 hours via `.github/workflows/update.yml`:

```yaml
on:
  schedule:
    - cron: '0 */12 * * *'
  workflow_dispatch:
```

Commits updated `hosts.txt` and `ai_trackers.json` automatically with `[skip ci]`.

---

## 📊 Output Format

```
# DNS Blocklist Manager v4.0.0
# Generated: 2025-01-01 12:00:00
# Total domains: 1,234,567
# ==========================================

0.0.0.0 ads.example.com
0.0.0.0 tracker.evil.net
...
```

Compatible with: **hosts file**, **personalDNSfilter**, **AdGuard Home**, **Pi-hole** (hosts format).

---

## 📈 Changelog

### v4.0.0
- **NEW** Replaced `requests` + `ThreadPoolExecutor` with `asyncio` + `aiohttp`
- **NEW** ETag / Last-Modified HTTP caching (304 Not Modified support)
- **FIX** `validate_domain` — single-character segments now pass correctly
- **FIX** Encapsulation — `_is_suspicious_domain` → public `score_domain()`
- **ARCH** Frequency-weighted reputation with daily decay
- **PERF** Removed nested thread pool executors

### v3.0.0
- Initial public release with AI reputation engine
- DNS in-memory cache with TTL
- Log rotation with gzip compression
- Atomic file writes

---

## 👤 Author

**somafix** — [github.com/somafix](https://github.com/somafix)

---

*Auto-updated every 12 hours by GitHub Actions.*
