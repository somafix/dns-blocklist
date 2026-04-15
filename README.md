# Blocklist Generator v5.0

![Go Version](https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

A high-performance, production-ready blocklist aggregator written in Go. It fetches domain lists from multiple sources, deduplicates them, and performs memory-efficient external sorting to handle millions of entries without crashing.

## 🚀 Features

* **Parallel Fetching**: Uses worker pools and goroutines to fetch sources concurrently.
* **Intelligent Caching**: Local disk cache with TTL and ETag support to reduce bandwidth and bypass rate limits.
* **Hybrid Sorting**: 
    * **In-Memory**: Fast sorting for small datasets (< 500k domains).
    * **External Sharded Sort**: Multi-way merge sort using disk shards for massive datasets to maintain low memory footprint.
* **Robust Validation**: Strict domain validation using regex, length checks, and TLD filtering.
* **Resilience**: Built-in retry logic with exponential backoff and graceful shutdown via OS signals.
* **Memory Optimized**: Uses `bufio` scanners, `sync.Pool`-like structures, and streaming IO.

## 🛠 Installation

1. Ensure you have **Go 1.18+** installed.
2. Clone the repository:
   ```bash
   git clone [https://github.com/youruser/blocklist-generator.git](https://github.com/youruser/blocklist-generator.git)
   cd blocklist-generator
