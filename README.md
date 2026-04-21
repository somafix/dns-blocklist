# Blocklist Generator

A high-performance utility written in Go designed to aggregate, clean, normalize, and sort domain blocklists from multiple remote sources.

![Go Version](https://img.shields.io/github/go-mod/go-version/YOUR_USERNAME/YOUR_REPO)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Build Status](https://img.shields.io/github/actions/workflow/status/YOUR_USERNAME/YOUR_REPO/main.yml?branch=main)

## Features

* **Concurrent Fetching**: Fetches multiple blocklist sources in parallel using a worker pool.
* **Memory Efficient**: Uses external sorting (sharding and chunking) to process millions of domains without exhausting system RAM.
* **Intelligent Caching**: Includes a persistent disk-based cache (using GOB encoding) to speed up subsequent runs and reduce network bandwidth.
* **Robust Validation**: Automatically filters out private IP blocks, invalid domains, and non-ASCII characters.
* **Highly Configurable**: Fine-tune performance via environment variables.

## Configuration

| Variable | Description | Default |
| :--- | :--- | :--- |
| `BLOCKLIST_SOURCES` | Comma-separated list of URLs | *Standard lists* |
| `BLOCKLIST_OUTPUT` | Destination file path | `blocklist.txt` |
| `BLOCKLIST_WORKERS` | Number of concurrent fetch workers | 4 |
| `BLOCKLIST_ENABLE_CACHE` | Enable/Disable disk caching | `true` |

## How It Works

1.  **Fetching**: Worker pool fetches domains with retries/exponential backoff.
2.  **Cleaning**: Strips prefixes, removes comments, validates domain syntax, and rejects private IP addresses.
3.  **Sorting**: Uses **External Merge Sort** (Sharding -> Chunking -> Streaming Merge) to handle datasets of any size with low RAM usage.

## Usage

```bash
# Run with defaults
go run main.go

# Run with custom config
BLOCKLIST_WORKERS=8 BLOCKLIST_OUTPUT=my_list.txt go run main.go
