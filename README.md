# Blocklist Generator

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/blocklist-generator?style=flat-square)](https://goreportcard.com/report/github.com/yourusername/blocklist-generator)
[![Code Style](https://img.shields.io/badge/style-gofmt-blue?style=flat-square)](https://pkg.go.dev/cmd/gofmt)

[![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/blocklist-generator/go.yml?style=flat-square)](https://github.com/yourusername/blocklist-generator/actions)
[![Security](https://img.shields.io/badge/security-A+-brightgreen?style=flat-square)](https://github.com/yourusername/blocklist-generator/security)
[![Performance](https://img.shields.io/badge/performance-optimized-success?style=flat-square)](https://github.com/yourusername/blocklist-generator)

> **Production-ready blocklist aggregator** — Fetches, deduplicates, and sorts domain blocklists from multiple sources with enterprise-grade reliability.

## 🚀 Features

- **Multi-source aggregation** — Fetches from multiple blocklist URLs simultaneously
- **Automatic deduplication** — Removes duplicate domains across all sources
- **External sorting** — Handles millions of domains with disk-based sorting
- **GZIP compression** — Automatic decompression of compressed responses
- **Intelligent caching** — Disk-based cache with TTL to reduce network requests
- **Rate limiting** — Respects source servers with configurable delays
- **Retry logic** — Exponential backoff with jitter for transient failures
- **Security validation** — SSRF protection, private IP blocking, domain sanitization
- **Graceful shutdown** — Handles SIGTERM/SIGINT signals properly
- **JSON logging** — Structured logging for production monitoring

## 📋 Prerequisites

- **Go 1.21+** (uses `slog` for structured logging)
- Network access to blocklist sources

## 🔧 Installation

### From Source

```bash
git clone https://github.com/yourusername/blocklist-generator.git
cd blocklist-generator
go build -o blocklist-generator
