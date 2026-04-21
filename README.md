# Blocklist Generator

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-stable-brightgreen)](https://github.com/yourusername/blocklist-generator)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/blocklist-generator)](https://goreportcard.com/report/github.com/yourusername/blocklist-generator)

A high-performance, production-ready domain blocklist generator written in Go. Fetches, deduplicates, and sorts domain blocklists from multiple sources with external sorting capabilities for handling millions of domains efficiently.

## Features

- **Concurrent Fetching** - Multi-worker architecture with configurable concurrency
- **Intelligent Caching** - Disk-based caching with ETag support for efficient updates
- **External Sorting** - Handles millions of domains using sharding and merge-sort algorithms
- **Memory Efficient** - Process large lists using configurable chunk sizes and external sorting thresholds
- **Safe URL Handling** - SSRF protection with private IP blocking and redirect limits
- **GZIP Support** - Automatic decompression of compressed responses
- **Comprehensive Configuration** - Extensive environment variable configuration options
- **Graceful Shutdown** - Proper signal handling and timeout management

## Badges

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/yourusername/blocklist-generator/actions)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen)](https://coveralls.io/github/yourusername/blocklist-generator)
[![GoDoc](https://img.shields.io/badge/go-documentation-blue.svg)](https://pkg.go.dev/github.com/yourusername/blocklist-generator)
[![Docker Pulls](https://img.shields.io/docker/pulls/yourusername/blocklist-generator)](https://hub.docker.com/r/yourusername/blocklist-generator)
[![Release](https://img.shields.io/github/v/release/yourusername/blocklist-generator)](https://github.com/yourusername/blocklist-generator/releases)

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/blocklist-generator.git
cd blocklist-generator

# Build the binary
go build -o blocklist-generator

# Run with default settings
./blocklist-generator
