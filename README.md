# Blocklist Generator

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)]()

A high-performance, memory-efficient blocklist generator written in Go. This tool fetches, parses, cleans, and merges domain lists from multiple sources into a single, sorted output file. 

Designed for scalability, it handles large datasets using **external merge sort** and ensures reliability through robust error handling and concurrent processing.

---

## 🚀 Key Features

* **Concurrent Processing:** Fetches multiple remote blocklists simultaneously using worker pools.
* **Memory Efficiency:** * Implements **External Merge Sort** to handle datasets exceeding system RAM.
    * Uses `bufio` with custom buffer sizes for optimized I/O operations.
* **Security Focused:**
    * **SSRF Protection:** Validates URLs to prevent server-side request forgery by blocking private IP ranges.
    * **Zip-Bomb Protection:** Limits decompression ratios for GZIP streams and enforces response size limits.
* **Caching Mechanism:** Disk-based caching (using `gob`) to reduce bandwidth consumption and improve subsequent run times.
* **Robustness:**
    * Graceful shutdown handling for safe termination.
    * Retry logic with exponential backoff for network stability.
    * Detailed logging via `slog` and observability interfaces.

## 🛠 Architecture Highlights

### Fetching Pipeline
The `Fetcher` component ensures that incoming data is sanitized:
1.  **Validation:** Checks schemes and resolves IPs to prevent SSRF.
2.  **Streaming:** Uses `io.LimitReader` and `gzip.Reader` with safe limits to prevent memory exhaustion.
3.  **Filtering:** Extracts domains using robust regex and checks against known unsafe patterns (e.g., local IPs, invalid formats).

### Sorting Strategy
The application dynamically selects a sorting strategy:
* **In-Memory Sort:** Used for smaller lists.
* **External Merge Sort:** Triggered when the domain count exceeds `externalSortThreshold` (default: 500,000). It splits the data into shards, sorts them individually, and merges them using a min-heap to ensure an $O(n \log n)$ performance.

## ⚙️ Configuration

The application is configured via the `Config` struct. Key parameters include:

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `WorkerCount` | 4 | Concurrent fetchers |
| `ShardCount` | 100 | Number of shards for external sort |
| `CacheTTL` | 24h | How long to keep cached data |
| `MaxResponseSize` | 50MB | Max allowed size per downloaded file |
| `MaxRetries` | 3 | Retries for failed requests |

## 📦 Getting Started

### Prerequisites
* Go 1.21 or higher

### Installation
Clone the repository and build:

```bash
git clone <your-repo-url>
cd blocklist-generator
go build -o blocklist-gen main.go
