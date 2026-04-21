# 🛡️ Blocklist Generator

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-6.0-blue)
![Go Report Card](https://img.shields.io/badge/go%20report-A+-brightgreen)
![Code Style](https://img.shields.io/badge/style-gofmt-blue)
![Concurrency](https://img.shields.io/badge/concurrency-ready-brightgreen)
![Memory Safe](https://img.shields.io/badge/memory-safe-2ea44f)
![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?logo=docker)
![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-ready-2088FF?logo=github-actions)

A **high-performance, memory-efficient** utility written in Go designed to aggregate, clean, de-duplicate, and sort domain blocklists from multiple remote sources. Perfect for ad blocking, DNS filtering, and content security applications.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔄 **Concurrent Fetching** | Uses worker pools to download multiple blocklists simultaneously, optimizing total execution time |
| 📊 **External Merge Sort** | Built-in ability to switch from in-memory sorting to an external disk-based merge sort when dealing with large datasets, preventing OOM errors |
| 💾 **Smart Caching** | Disk-based caching using `gob` encoding to reduce network usage and speed up repeated runs |
| ✅ **Domain Validation** | Robust regex-based filtering to ensure only valid, non-malicious domains are included |
| 🗜️ **GZIP Support** | Automatically handles compressed sources to save bandwidth |
| 🛑 **Graceful Shutdown** | Context-aware handling ensures clean exit on signals (SIGINT/SIGTERM) with temporary file cleanup |
| 🔒 **Secure by Default** | TLS 1.2+, URL validation, size limits, and safe temp file handling |
| 📈 **Metrics Interface** | Built-in metrics support for monitoring and observability |

## 🚀 Quick Start

### Local Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/blocklist-generator.git
cd blocklist-generator

# Run directly
go run main.go

# Build binary
go build -o blocklist-generator
./blocklist-generator
