# DNS Blocklist Processor

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Overview
A minimal, dependency-free Python utility that fetches, cleans, and normalizes DNS blocklists into a ready-to-use `hosts` format.

Designed for automation pipelines, CI jobs, and local system-wide ad/tracker blocking.

## Key Idea
Raw blocklists are messy:
- comments
- duplicates
- invalid domains
- inconsistent formats

This script turns them into a clean, deterministic output.

---

## Features

- **Zero Dependencies**  
  Uses only Python standard library (`urllib`, `re`)

- **Deterministic Output**  
  Same input → same result (important for CI/CD)

- **Strict Filtering**
  - removes comments
  - skips invalid domains
  - ignores malformed lines

- **Deduplication (O(n))**
  Uses `set` for fast uniqueness

- **Hosts Format Ready**
  ```
  0.0.0.0 example.com
  ```

- **Timeout & Headers Handling**
  Safe HTTP fetching (no hanging requests)

---

## Data Source

Currently using:

- HaGeZi DNS Blocklist (Pro++)

---

## Installation

```bash
git clone https://github.com/your-repo/dns-blocklist-processor.git
cd dns-blocklist-processor
```

No dependencies required.

---

## Usage

```bash
python3 script.py
```

---

## Output

Generates:

```
hosts.txt
```

Example:

```
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.org
0.0.0.0 malware.site
```

---

## How It Works

```
[ URL ]
   ↓
[ Fetch (urllib) ]
   ↓
[ Line Parsing ]
   ↓
[ Regex Validation ]
   ↓
[ Deduplication (set) ]
   ↓
[ hosts.txt ]
```

---

## Configuration

Inside the script:

```python
URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
]

TIMEOUT = 30
OUTPUT = "hosts.txt"
```

---

## Performance Notes

- Time complexity: **O(n)**
- Memory: proportional to number of unique domains
- No unnecessary allocations
- No repeated string scanning

---

## Use Cases

- System-wide ad blocking (`/etc/hosts`)
- DNS filtering pipelines
- CI/CD automation (GitHub Actions)
- Embedded / low-resource environments

---

## Example (Linux)

```bash
sudo cp hosts.txt /etc/hosts
```

---

## Security Notes

- No external code execution
- No shell calls
- Input is strictly validated via regex
- Network requests are bounded by timeout

---

## License

MIT License
