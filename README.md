# 🚀 Secure Blocklist Aggregator (Go)

![Go](https://img.shields.io/badge/Go-1.18%2B-00ADD8?logo=go)
![Concurrency](https://img.shields.io/badge/Concurrency-Enabled-blue)
![Security](https://img.shields.io/badge/Security-Hardened-critical)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Production-success)
![Network](https://img.shields.io/badge/HTTP-Safe%20Fetch-orange)

---

## 📌 Overview
High-performance concurrent blocklist aggregator with security filtering, SSRF protection, rate limiting, and strict domain validation.

---

## ⚙️ Features

- Concurrent fetching from multiple sources
- SSRF protection via URL scheme validation
- Response size limiting (50MB cap)
- Rate limiting between requests
- Strict domain validation (RFC-like rules)
- Blocks wildcards, IDN, local/internal domains
- Buffered I/O for high performance
- Deduplication via hash map
- Atomic-safe concurrent workers
- Graceful timeout handling (3 min global)

---

## 🔒 Security Model

### Protected against:
- SSRF (scheme + URL parsing validation)
- Oversized payload attacks
- Malformed scanner input exhaustion
- Redirect loops (max 5 redirects)
- Invalid or unsafe domain injection

### Domain filtering:
- No wildcards (`*`)
- No Unicode / IDN domains
- No `.local`, `.lan`, `.internal`, `.localhost`
- No invalid label patterns
- No IP-like or path-based entries

---

## 🌐 Sources

- StevenBlack hosts
- someonewhocares.org zero hosts
- anudeepND adservers blacklist
- PolishFiltersTeam KADhosts

---

## 🧠 Architecture

### Pipeline
1. Context-limited execution (`3m timeout`)
2. Worker goroutines per source
3. Rate-limited fetch layer
4. Safe HTTP client with redirect control
5. Streamed parsing (`bufio.Scanner`)
6. Domain validation layer
7. Concurrent aggregation (`map[string]struct{}`)
8. Sorted final output
9. Buffered disk write

---

## 🚀 Run

```bash
go run main.go
