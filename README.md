# Blocklist Generator

A high-performance utility written in Go designed to aggregate, clean, normalize, and sort domain blocklists from multiple remote sources. This tool is optimized for efficiency, utilizing concurrency and external sorting algorithms to handle large-scale datasets with minimal memory footprint.

![Go Version](https://img.shields.io/github/go-mod/go-version/user/repo)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/build-passing-brightgreen)

## Features

* **Concurrent Fetching**: Fetches multiple blocklist sources in parallel using a worker pool.
* **Memory Efficient**: Uses external sorting (sharding and chunking) to process millions of domains without exhausting system RAM.
* **Intelligent Caching**: Includes a persistent disk-based cache (using GOB encoding) to speed up subsequent runs and reduce network bandwidth.
* **Robust Validation**: Automatically filters out private IP blocks, invalid domains, and non-ASCII characters.
* **Highly Configurable**: Fine-tune performance via environment variables to suit your infrastructure needs.
* **Graceful Handling**: Supports context-aware timeouts, retries with backoff, and signal handling for safe shutdowns.

## Configuration

You can configure the behavior of the generator using the following environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `BLOCKLIST_SOURCES` | Comma-separated list of URLs to fetch | *Standard default lists* |
| `BLOCKLIST_OUTPUT` | Destination file path | `blocklist.txt` |
| `BLOCKLIST_TEMP_DIR` | Directory for temporary sorting files | System Temp |
| `BLOCKLIST_MAX_RESPONSE_SIZE_MB` | Max size for a single download | 50 |
| `BLOCKLIST_REQUEST_TIMEOUT_SEC` | Timeout for HTTP requests | 30 |
| `BLOCKLIST_TIMEOUT_MIN` | Total execution timeout | 5 |
| `BLOCKLIST_RATE_LIMIT_MS` | Delay between requests | 200 |
| `BLOCKLIST_MAX_RETRIES` | Number of retries per source | 3 |
| `BLOCKLIST_RETRY_BACKOFF_SEC` | Base seconds for exponential backoff | 2 |
| `BLOCKLIST_WORKERS` | Number of concurrent fetch workers | 4 |
| `BLOCKLIST_BUFFER_SIZE_KB` | Buffer size for I/O operations | 256 |
| `BLOCKLIST_ENABLE_CACHE` | Enable/Disable disk caching | `true` |
| `BLOCKLIST_CACHE_TTL_HOURS` | Time-to-live for cache entries | 24 |
| `BLOCKLIST_ENABLE_GZIP` | Enable GZIP compression for requests | `true` |
| `BLOCKLIST_SHARDS` | Number of shards for external sort | 100 |
| `BLOCKLIST_CHUNK_SIZE` | Chunk size for internal memory sort | 500,000 |

## How It Works

1.  **Fetching**: The app initializes a worker pool to fetch domains from provided URLs. It handles retries with exponential backoff and respects rate limits.
2.  **Cleaning & Normalization**: As domains are streamed, the app strips prefixes (like `0.0.0.0`), removes comments, validates domain syntax, and rejects private IP addresses or malformed entries.
3.  **Collection**: Unique domains are collected into a memory-safe set.
4.  **Sorting**:
    * If the list is small, it performs an in-memory sort.
    * If the list exceeds the `externalSortThreshold`, it performs an **External Merge Sort**:
        * **Sharding**: Spreads data into smaller temporary files based on a hash.
        * **Chunking**: Reads, sorts, and saves chunks of data for each shard.
        * **Merging**: Uses a min-heap to stream merge the sorted chunks into the final output file.

## Usage

Ensure you have Go installed (1.20+ recommended), then run:

```bash
go run main.go
