# Blocklist Generator

![Go Version](https://img.shields.io/github/go-mod/go-version/user/repo?logo=go)
![Build Status](https://img.shields.io/github/actions/workflow/status/user/repo/main.yml?branch=main)
![License](https://img.shields.io/github/license/user/repo)
![Version](https://img.shields.io/badge/version-6.0-blue)

A high-performance, memory-efficient utility written in Go designed to aggregate, clean, de-duplicate, and sort domain blocklists from multiple remote sources.

## Features

* **Concurrent Fetching:** Uses worker pools to download multiple blocklists simultaneously, optimizing total execution time.
* **External Merge Sort:** Built-in ability to switch from in-memory sorting to an external disk-based merge sort when dealing with large datasets, preventing OOM (Out-of-Memory) errors.
* **Smart Caching:** Disk-based caching using `gob` encoding to reduce network usage and speed up repeated runs.
* **Domain Validation:** Robust regex-based filtering to ensure only valid, non-malicious domains are included in the final output.
* **GZIP Support:** Automatically handles compressed sources to save bandwidth.
* **Graceful Shutdown:** Context-aware handling ensures the application cleans up temporary files and exits cleanly on signals (SIGINT/SIGTERM).

## Configuration

The application is configured via environment variables. If no environment variables are provided, it defaults to a set of pre-defined community-maintained blocklists.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `BLOCKLIST_OUTPUT` | Path to the final output file | `blocklist.txt` |
| `BLOCKLIST_TEMP_DIR` | Directory for temporary sorting files | System Temp |
| `BLOCKLIST_WORKERS` | Number of concurrent fetchers | `4` |
| `BLOCKLIST_SHARDS` | Number of shards for external sorting | `100` |

## Technical Highlights

### Fetching Logic
The `Fetcher` struct utilizes a configurable `http.Client` with specific limits on idle connections and timeouts, ensuring stability. It automatically detects ETag headers to minimize data transfer if caching is enabled.

### Sorting Strategy
The application employs a dual-strategy sorting mechanism:
1.  **In-Memory Sort:** Used when the number of domains is below the `externalSortThreshold` (500,000 domains).
2.  **External Sort:** When the threshold is exceeded, the application shards domains into temporary files, sorts them individually in parallel, and merges them using a heap-based approach.

## Usage

1.  **Install dependencies** (Standard library only).
2.  **Run the application**:

```bash
go run main.go
