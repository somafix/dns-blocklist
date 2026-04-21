# 🛡️ Blocklist Generator

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/blocklist-generator)](https://goreportcard.com/report/github.com/yourusername/blocklist-generator)
[![Code Style](https://img.shields.io/badge/style-gofmt-blue)](https://pkg.go.dev/cmd/gofmt)
[![Concurrency](https://img.shields.io/badge/concurrency-ready-brightgreen)](https://golang.org/doc/effective_go#concurrency)
[![Memory Safe](https://img.shields.io/badge/memory-safe-2ea44f)](https://go.dev/blog/safety)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/blocklist-generator/actions)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen)](https://github.com/yourusername/blocklist-generator)
[![GoDoc](https://img.shields.io/badge/docs-reference-5272B4)](https://pkg.go.dev/github.com/yourusername/blocklist-generator)
[![Docker Pulls](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)](https://hub.docker.com/r/yourusername/blocklist-generator)

A **high-performance, production-grade** blocklist generator written in Go that aggregates domain blacklists from multiple sources, removes duplicates, and produces a sorted, deduplicated blocklist for ad blocking, DNS filtering, and content security.

## ✨ Features

- 🔄 **Multi-source aggregation** - Fetch blocklists from multiple URLs simultaneously
- 💾 **Intelligent caching** - Disk-based caching with ETag support to reduce bandwidth usage
- 🔁 **Automatic retries** - Configurable retry mechanism with exponential backoff
- 🗜️ **GZIP support** - Automatically handles compressed responses
- 📊 **External sorting** - Handles millions of domains efficiently using external merge sort
- ⚡ **Concurrent processing** - Parallel fetching and processing with configurable worker count
- 🛑 **Graceful shutdown** - Handles interrupts and timeouts gracefully
- ✅ **Domain validation** - Validates domain format, length, and filters out invalid entries
- 🧠 **Memory efficient** - Uses streaming processing and external sorting for large datasets
- 📈 **Metrics ready** - Built-in metrics interface for monitoring and observability
- 🔒 **Secure by default** - TLS 1.2+, URL validation, size limits

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/blocklist-generator.git
cd blocklist-generator

# Build the binary
go build -o blocklist-generator

# Run with default settings
./blocklist-generator
