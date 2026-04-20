# Blocklist Generator

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/blocklist-generator)](https://goreportcard.com/report/github.com/yourusername/blocklist-generator)
[![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

A high-performance, concurrent blocklist generator that aggregates multiple ad-blocking sources, deduplicates domains, and produces a sorted, unique blocklist for DNS filtering, Pi-hole, or other ad-blocking solutions.

## Features

- 🚀 **High Performance** - Concurrent fetching with worker pools
- 💾 **Memory Efficient** - External sorting for large datasets (>500k domains)
- 🔄 **Smart Caching** - Disk-based caching with ETag support
- 📦 **GZIP Support** - Automatic decompression of compressed responses
- 🎯 **Domain Validation** - RFC-compliant domain name validation
- ⚡ **Parallel Processing** - Multi-shard sorting and merging
- 🔁 **Automatic Retries** - Configurable retry logic with exponential backoff
- 🛡️ **Graceful Shutdown** - Proper cleanup and timeout handling
- 📊 **Metrics Support** - Pluggable metrics interface for monitoring
- 🎨 **Configurable** - Extensive environment variable configuration

## Quick Start

### Prerequisites

- Go 1.21 or higher

### Installation

```bash
git clone https://github.com/yourusername/blocklist-generator.git
cd blocklist-generator
go build -o blocklist-generator
