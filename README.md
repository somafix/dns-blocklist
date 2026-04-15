🚀 Blocklist Generator v5.0

"Go Version" (https://img.shields.io/badge/Go-1.20%2B-blue)
"Build" (https://img.shields.io/badge/build-passing-brightgreen)
"Performance" (https://img.shields.io/badge/performance-optimized-orange)
"License" (https://img.shields.io/badge/license-MIT-lightgrey)
"Concurrency" (https://img.shields.io/badge/concurrency-safe-blueviolet)

Production-grade blocklist aggregator written in Go.

Efficiently downloads, validates, deduplicates, and sorts massive domain blocklists from multiple sources — with support for caching, retries, gzip, and external sorting for large datasets.

---

✨ Features

- ⚡ High-performance concurrent fetching
- 🔁 Retry with exponential backoff
- 📦 Disk cache with TTL + ETag support
- 🧠 Smart deduplication (thread-safe)
- 🗜️ Transparent GZIP handling
- 📊 Progress tracking
- 🧹 Strict domain validation
- 🧩 External sorting (for millions of domains)
- 💾 Memory-efficient processing
- 🛑 Graceful shutdown (SIGINT / SIGTERM)

---

🏗 Architecture Overview

          +----------------------+
          |   Sources (URLs)     |
          +----------+-----------+
                     |
                     v
        +--------------------------+
        | Concurrent Fetch Workers |
        +------------+-------------+
                     |
                     v
        +--------------------------+
        | Validation + Dedup (Set) |
        +------------+-------------+
                     |
                     v
        +--------------------------+
        | Temp File (Raw Domains)  |
        +------------+-------------+
                     |
         +-----------+-----------+
         |                       |
         v                       v
 In-Memory Sort         External Sharded Sort
 (small datasets)       (large datasets)
         |                       |
         +-----------+-----------+
                     |
                     v
          +----------------------+
          |   Final Blocklist    |
          +----------------------+

---

⚙️ Configuration

All parameters are centralized in "Config":

Field| Description
"Sources"| List of blocklist URLs
"WorkerCount"| Number of concurrent fetchers
"MaxRetries"| Retry attempts per source
"CacheTTL"| Cache lifetime
"ShardCount"| Number of shards for external sort
"ChunkSize"| Sorting chunk size
"MaxResponseSize"| Max download size per source
"RequestTimeout"| Per-request timeout
"TotalTimeout"| Global execution timeout

---

🚀 Usage

1. Clone repository

git clone https://github.com/yourname/blocklist-generator.git
cd blocklist-generator

2. Run

go run main.go

3. Output

blocklist.txt

---

📈 Performance

- Handles millions of domains
- Automatic strategy switch:
  - "< 500K" → in-memory sort
  - ">= 500K" → external sharded sort
- Minimal memory footprint due to:
  - streaming I/O
  - chunked sorting
  - heap-based merge

---

🧪 Example Sources

- StevenBlack hosts
- SomeoneWhoCares
- AdGuard-style lists
- Custom domain feeds

---

🔒 Security Considerations

- Input validation prevents malformed domains
- Response size limits mitigate memory abuse
- Context-based cancellation avoids hanging requests
- No execution of remote content (read-only parsing)

---

🧠 Key Implementation Details

External Sorting

- SHA256-based sharding
- Chunk-based sorting
- Heap merge (k-way merge)

Caching

- File-based ("gob")
- Keyed via SHA256
- TTL invalidation

Concurrency

- Worker pool with semaphore
- Atomic progress tracking
- Context-aware cancellation

---

📊 Example Output

🚀 Blocklist Generator v5.0 - Production Ready
📥 Progress: 100.0%

📊 Total unique: 1,234,567
💾 Memory: 120.45 MB allocated

🔄 External sort with 100 shards...

✅ Done in 12.3s:
   • Domains: 1234567
   • Size: 18.42 MB
   • SHA256: a1b2c3d4e5f67890

---

📦 Output Guarantees

- ✅ Sorted
- ✅ Deduplicated
- ✅ Valid domains only
- ✅ Deterministic result

---

🛠 Future Improvements

- Incremental updates
- Bloom filter pre-check
- Distributed fetching
- CLI flags / config file
- Metrics export (Prometheus)

---

📄 License

MIT License

---

👨‍💻 Author

Engineered for high-load, real-world usage.

---

⚠️ Notes

If you're processing very large datasets (10M+ domains):

- Increase "ShardCount"
- Tune "ChunkSize"
- Ensure fast disk (SSD recommended)

---

🧩 TL;DR

This is not just a script.

It’s a production-grade pipeline for building blocklists at scale.
