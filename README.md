<div align="center">

<h1>🛡️ DNS Blocklist Manager</h1>

<p>Autonomous DNS blocklist builder with a self-learning AI reputation engine,<br>async HTTP fetching, ETag caching, and atomic output.</p>

[![Version](https://img.shields.io/badge/version-4.0.0-0ea5e9?style=flat-square)](https://github.com/somafix/dns-blocklist/releases)
[![Python](https://img.shields.io/badge/python-3.11+-0ea5e9?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-22c55e?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/somafix/dns-blocklist/update.yml?style=flat-square&label=auto-update&logo=github-actions&logoColor=white)](https://github.com/somafix/dns-blocklist/actions)
[![Last Commit](https://img.shields.io/github/last-commit/somafix/dns-blocklist?style=flat-square&label=updated)](https://github.com/somafix/dns-blocklist/commits)
[![aiohttp](https://img.shields.io/badge/async-aiohttp-a855f7?style=flat-square)](https://docs.aiohttp.org/)
[![Schedule](https://img.shields.io/badge/schedule-every_12h-f59e0b?style=flat-square)](https://github.com/somafix/dns-blocklist/actions)

</div>

---

## Overview

DNS Blocklist Manager downloads, merges, and analyzes multiple DNS blocklists from trusted upstream sources. It runs a heuristic + entropy-based scoring engine on every domain and maintains a persistent reputation database that learns across runs — automatically promoting frequently suspicious domains into a custom AI-generated blocklist and rehabilitating domains that stop appearing over time.

The output is a single `hosts.txt` file in standard `0.0.0.0 <domain>` format, compatible with any DNS-based filtering tool.

---

## Features

| | Feature | Details |
|---|---------|---------|
| ⚡ | **Async downloader** | Parallel fetching via `aiohttp` + `TCPConnector(limit=20)` |
| 💾 | **ETag / Last-Modified caching** | Sends `If-None-Match` / `If-Modified-Since`; skips re-download on `304 Not Modified` |
| 🧠 | **AI reputation engine** | Per-domain float score with frequency weighting and daily exponential decay |
| 🔁 | **Self-healing blocklist** | Domains auto-promoted and auto-removed based on score history |
| 🔍 | **Entropy-based DGA detection** | Flags algorithmically generated domains via Shannon entropy analysis |
| 🗄️ | **In-memory DNS cache** | TTL-based lookup cache with hit rate reporting |
| 🔒 | **Atomic file writes** | `tempfile` → `shutil.move` — no partial writes on crash |
| 📜 | **Log rotation** | Gzip-compressed rolling logs with configurable backup count |
| ✅ | **Whitelist** | User-managed `ai_whitelist.txt` — whitelisted domains are never blocked |
| 🤖 | **GitHub Actions** | Fully automated — commits updated blocklist every 12 hours |

---

## Upstream Sources

| # | Repository | List | Coverage |
|---|-----------|------|----------|
| 1 | [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) | `pro.plus` | Ads, trackers, malware, phishing |
| 2 | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | `fakenews-gambling-porn` | Fakenews, gambling, adult content |

Additional sources can be added to `CONFIG["urls"]` in `update.py`.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/somafix/dns-blocklist.git
cd dns-blocklist

# 2. Install dependencies
pip install aiohttp aiofiles requests

# 3. Run
python update.py
```

On first run, `etag_cache.json` and `dns_blocker.log` are created automatically.

**Output:** `hosts.txt` — ready to deploy as a system hosts file or import into any DNS filter.

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                      update.py                          │
│                                                         │
│  [1] Async fetch  ──►  merge_blocklists_async()         │
│       ↓ ETag 304?  ──►  serve from local cache          │
│                                                         │
│  [2] Score domains  ──►  TrackerAI.score_domain()       │
│       heuristics + entropy + keyword + regex patterns   │
│                                                         │
│  [3] Train AI  ──►  TrackerAI.analyze_batch()           │
│       update reputation + frequency + decay             │
│       auto-add to custom blocklist if rep ≤ -3.0        │
│                                                         │
│  [4] Write output  ──►  write_hosts_file()              │
│       upstream domains ∪ AI-learned domains             │
│       atomic write via tempfile + shutil.move           │
└─────────────────────────────────────────────────────────┘
```

---

## AI Reputation Engine

Each domain carries a float reputation score, persisted in `ai_trackers.json` across runs.

### Score Events

| Event | Delta |
|-------|-------|
| Domain flagged as suspicious | `−(1.0 + min(frequency × 0.3, 3.0))` |
| Domain passes all checks | `+0.5` |
| Domain found in whitelist | `+1.0` |
| Every run (decay) | `score × 0.95` |

### Thresholds

| Threshold | Value | Effect |
|-----------|-------|--------|
| Block | `≤ −3.0` | Domain added to `ai_custom_blocklist.txt` |
| Unblock | `≥ +5.0` | Domain removed from custom blocklist |
| Stale cleanup | `> 30 days unseen` + `score > −2` | Domain removed automatically |

**Frequency bonus** is capped at `3.0` — a domain appearing across multiple upstream lists accumulates penalty faster.  
**Decay** ensures domains that stop appearing are not blocked indefinitely.

---

## Suspicion Scoring

`score_domain()` evaluates each domain against structural, lexical, and statistical signals:

```
Signal                                  Points
──────────────────────────────────────────────
Subdomain depth > 5 labels              +2
Any segment length > 20 chars           +1
Numeric sequence ≥ 5 digits in segment  +2
Underscore present in segment           +1
Segment ≥ 15 chars AND entropy > 3.5   +2
Suspicious keyword match                +2
Regex pattern match (per pattern)       +1
Non-standard SLD length ≤ 3 chars       +2
──────────────────────────────────────────────
Threshold: score ≥ 4  →  suspicious
```

**CDN / infrastructure exceptions** (always trusted):
`cloudflare` · `amazonaws` · `googleapis` · `github` · `cdn` · `cloudfront` · `akamaiedge` · `fastly` · `stackpath`

---

## Configuration

All tuneable parameters live in the `CONFIG` dict at the top of `update.py`:

```python
CONFIG = {
    # Sources
    "urls": [...],                  # List of upstream blocklist URLs

    # Network
    "timeout": 30,                  # Per-request timeout (seconds)
    "max_file_size_mb": 50,         # Hard cap on response body size

    # Analysis
    "max_domains_to_analyze": 100_000,

    # Reputation
    "reputation_block_at": -3.0,    # Score at which domain is blocked
    "reputation_threshold": 5.0,    # Score at which domain is unblocked
    "reputation_decay": 0.05,       # Multiplicative decay per run (× 0.95)
    "frequency_weight": 0.3,        # Per-occurrence penalty multiplier
    "min_reputation": -10.0,
    "max_reputation": 10.0,

    # Cleanup
    "cleanup_days": 30,             # Days before stale domains are removed

    # Cache
    "dns_cache_ttl": 3600,          # In-memory DNS cache TTL (seconds)
    "enable_dns_cache": True,

    # Logging
    "enable_log_rotation": True,
    "max_log_size_mb": 10,
    "backup_count": 3,
}
```

---

## File Structure

```
dns-blocklist/
├── update.py                   # Entry point
├── hosts.txt                   # Output — merged blocklist (hosts format)
├── hosts.backup                # Backup of previous hosts.txt
├── ai_trackers.json            # Reputation DB (reputation, frequency, last_seen)
├── ai_custom_blocklist.txt     # AI-learned domains (auto-managed)
├── ai_whitelist.txt            # User-managed whitelist
├── etag_cache.json             # Auto-generated — HTTP conditional request cache
└── dns_blocker.log             # Auto-generated — rotating log
```

`etag_cache.json` and `dns_blocker.log` are created on first run and do not need to be committed unless ETag persistence across CI runs is desired.

---

## Whitelist

Create `ai_whitelist.txt` in the repo root to protect domains from being blocked:

```
# ai_whitelist.txt — one domain per line, # for comments
example.com
trusted-analytics.internal
```

Whitelisted domains are removed from the custom blocklist immediately on next run and their reputation is increased.

---

## Output Format

```
# DNS Blocklist Manager v4.0.0
# Generated: 2025-01-01 12:00:00
# Total domains: 1,234,567
# ==========================================

0.0.0.0 ads.example.com
0.0.0.0 tracker.evil.net
```

**Compatible with:**

| Tool | Format |
|------|--------|
| System hosts file | ✅ Native |
| [Pi-hole](https://pi-hole.net/) | ✅ Hosts format |
| [AdGuard Home](https://adguard.com/adguard-home/) | ✅ Hosts format |
| [personalDNSfilter](https://www.zenz-solutions.de/personaldnsfilter-ce/) | ✅ Hosts format |
| [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) | ✅ Hosts format |

---

## GitHub Actions

The workflow runs automatically every 12 hours and on manual dispatch:

```yaml
on:
  schedule:
    - cron: '0 */12 * * *'
  workflow_dispatch:
```

After each run, the following files are committed back to the repository:

```
hosts.txt
hosts.backup
ai_custom_blocklist.txt
ai_trackers.json
```

Commits are tagged `[skip ci]` to prevent recursive workflow triggers.

---

## Changelog

<details>
<summary><strong>v4.0.0</strong> — Full async rewrite</summary>

- `NEW` Replaced `requests` + `ThreadPoolExecutor` I/O with `asyncio` + `aiohttp`
- `NEW` ETag / Last-Modified HTTP caching — `304 Not Modified` support with local content cache
- `NEW` Frequency-weighted reputation scoring with exponential daily decay
- `NEW` `frequency` field added to `ai_trackers.json`
- `FIX` `validate_domain` — single-character segments (`a.bc`) now validate correctly
- `FIX` `_is_suspicious_domain` renamed to public `score_domain()` — encapsulation restored
- `PERF` Removed nested `ThreadPoolExecutor` in `batch_analyze` — replaced with `async` / `run_in_executor`
- `ARCH` Compiled suspicious patterns into module-level `re.compile()` list — not recompiled per domain

</details>

<details>
<summary><strong>v3.0.0</strong> — Initial release</summary>

- AI reputation engine with persistent JSON database
- DNS in-memory cache with TTL
- Log rotation with gzip compression
- Atomic file writes via `tempfile` + `shutil.move`
- Signal handlers for graceful shutdown

</details>

---

## Dependencies

```
aiohttp>=3.9
aiofiles>=23.0
requests>=2.31
```

```bash
pip install aiohttp aiofiles requests
```

---

<div align="center">

Made by **[somafix](https://github.com/somafix)**

</div>
