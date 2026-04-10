# 🚀 Blocklist Aggregator (Go)

![Go Version](https://img.shields.io/badge/Go-1.18%2B-00ADD8?logo=go)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)
![Build](https://img.shields.io/badge/Build-Passing-brightgreen)

## 📌 Overview
This tool aggregates multiple public host blocklists, extracts domains, filters them, and generates a unified `blocklist.txt`.

## ⚙️ Features
- Pulls multiple remote blocklists
- Parses multiple formats (hosts / plain domain lists)
- Filters invalid domains
- Deduplicates automatically
- Sorts output alphabetically
- Saves optimized `blocklist.txt`

## 📥 Sources
- StevenBlack hosts
- someonewhocares.org zero hosts
- anudeepND blacklist
- PolishFiltersTeam KADhosts

## 🧠 How it works
1. Downloads each source via HTTP client (30s timeout)
2. Reads line-by-line stream
3. Extracts valid domains using regex filtering
4. Normalizes and deduplicates via map
5. Sorts final dataset
6. Writes output to file

## 🧪 Output
- File: `blocklist.txt`
- Format: one domain per line

## 🚀 Run

```bash
go run main.go
