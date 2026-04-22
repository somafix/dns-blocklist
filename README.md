# Blocklist Generator

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)](https://github.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Concurrency](https://img.shields.io/badge/concurrency-worker--pool-blue.svg)](https://golang.org)
[![Cache](https://img.shields.io/badge/cache-disk--based-orange.svg)]()

A high-performance, concurrent blocklist generator written in Go that aggregates domain lists from multiple sources, deduplicates them, and produces a clean, sorted list of domains.

## 🚀 Features

- **Concurrent Processing** - Fetches multiple blocklist sources simultaneously using worker pools
- **Disk Caching** - Caches fetched lists locally with TTL (24 hours default)
- **Automatic Decompression** - Handles gzipped responses automatically
- **Domain Validation** - Validates and normalizes domain names according to RFC standards
- **Deduplication** - Removes duplicate domains across all sources
- **Graceful Shutdown** - Handles SIGINT and SIGTERM signals gracefully
- **Configurable** - All settings can be controlled via environment variables
- **Memory Efficient** - Streams large files without loading entire content into memory
- **IPv4 Filtering** - Automatically filters out IP addresses (only domains allowed)

## 📋 Requirements

- Go 1.21 or higher (for compilation)
- Internet connection to fetch blocklist sources
- Sufficient disk space for cache (depends on source sizes)

## 🔧 Installation

### From Source

```bash
git clone https://github.com/yourusername/blocklist-generator.git
cd blocklist-generator
go build -o blocklist-generator
