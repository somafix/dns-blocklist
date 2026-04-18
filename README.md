# Blocklist Generator v5.0

![Go](https://img.shields.io/badge/Language-Go-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Performance](https://img.shields.io/badge/Engine-High_Performance-red.svg)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)

A high-performance, concurrent, and memory-efficient domain blocklist generator. This tool aggregates domain lists from multiple URLs, performs robust deduplication, validates entries, and utilizes external merge sorting to process massive datasets without consuming excessive system memory.

## 🚀 Key Features

* **High Concurrency:** Uses a worker-pool pattern to fetch multiple sources simultaneously.
* **External Merge Sort:** Built-in disk-based sorting algorithm for handling datasets exceeding 500k+ domains efficiently.
* **Disk Caching:** Caches remote responses using GOB encoding to save bandwidth and reduce execution time on subsequent runs.
* **Memory Optimized:** Built with memory management in mind; streams large files rather than loading them entirely into RAM.
* **Smart Validation:** Filters out invalid domains, IP addresses, and non-DNS compliant strings using strict regex patterns.
* **Zero Dependencies:** Built entirely with the Go Standard Library.

## 🛠 How it Works

1.  **Fetcher:** Downloads host files with retry logic, Gzip support, and timeout control.
2.  **Deduplication:** Uses a thread-safe `DomainSet` to ensure unique entries across all sources.
3.  **Processing:** If the dataset is large, the `Sorter` switches to an **External Merge Sort** strategy, partitioning data into shards on disk before merging them.
4.  **Cleanup:** Automatically validates domains and removes malformed entries (e.g., `localhost` pointers, invalid characters).

## ⚙️ Configuration

The project is configured via the `Config` struct in the `run()` function. You can tune the following parameters:

| Parameter | Description |
| :--- | :--- |
| `Sources` | Slice of URLs to fetch blocklists from. |
| `WorkerCount` | Number of concurrent downloaders. |
| `MaxResponseSize` | Protection against oversized files. |
| `EnableCache` | Toggles disk-based caching. |
| `ShardCount` | Number of shards used for external sorting. |
| `CacheTTL` | Time-to-live for cached files. |

## 🏗 Building & Running

Ensure you have [Go](https://golang.org/dl/) installed.

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd <project-folder>
