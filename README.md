# 🚀 Blocklist Generator v4.0 (Production Grade Go)

![Go](https://img.shields.io/badge/Go-1.18%2B-00ADD8?logo=go)
![Version](https://img.shields.io/badge/Version-4.0-blue)
![Status](https://img.shields.io/badge/Status-Production%20Ready-success)
![Concurrency](https://img.shields.io/badge/Concurrency-Worker%20Pool-blue)
![Security](https://img.shields.io/badge/Security-Hardened-critical)
![Cache](https://img.shields.io/badge/Cache-Disk%20Enabled-orange)
![Performance](https://img.shields.io/badge/Performance-Optimized-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Overview
High-performance production-grade blocklist generator with caching, retry logic, gzip support, external sorting, sharding, and memory-safe processing for large-scale datasets.

---

## ⚙️ Key Features

### ⚡ Performance
- Worker pool concurrency
- Buffered I/O (256KB)
- Streaming processing (no full memory load)
- Sharded external sorting (100 shards)
- Heap-based multi-way merge
- Adaptive strategy (in-memory vs external sort)

### 🔒 Security
- SSRF protection (URL scheme validation)
- Input sanitization & strict domain validation
- Wildcard blocking
- IDN rejection (Unicode filter)
- IP detection blocking
- Internal domain filtering (.local, .localhost)
- Response size limiting (50MB)

### 🌐 Network Optimization
- GZIP compression support
- ETag-aware caching
- Retry mechanism with exponential backoff
- Rate limiting per request
- Redirect chain protection

### 💾 Caching System
- Disk-based cache (Gob serialization)
- SHA256 key hashing
- TTL expiration control (24h)
- Automatic cache reuse

### 📊 Scalability
- Handles >500,000 domains via external sort
- Sharded temp file pipeline
- Memory-safe merge strategy

---

## 🧠 Architecture

### Pipeline

1. Context + signal cancellation
2. Worker pool execution
3. Rate-limited fetching
4. HTTP fetch with retry + gzip + cache
5. Domain extraction + validation
6. Deduplication (global set)
7. Temp file aggregation
8. Sorting strategy selection:
   - Small dataset → in-memory sort
   - Large dataset → external sharded sort
9. Final SHA256 integrity hashing

---

## 🧱 Components

### 📡 Fetch Engine
- `fetchSource()` → HTTP + gzip + parsing
- `fetchWithRetry()` → retry + cache layer

### 🧹 Validation Layer
- RFC-style domain regex validation
- IP detection filtering
- Reserved domain blocking
- Character set restrictions

### 💽 Cache Layer
- DiskCache (Gob-based)
- TTL expiration
- SHA256 filename hashing

### 🔀 External Sort Engine
- Hash-based sharding
- Per-shard sorting
- Dedup inside shards
- Heap-based k-way merge

---

## 🚀 Run

```bash
go run main.go
