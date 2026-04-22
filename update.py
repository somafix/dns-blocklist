#!/usr/bin/env python3

import urllib.request
import re
from datetime import datetime, timezone

URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt"
OUTPUT = "hosts.txt"

try:
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
except Exception as e:
    print(f"Error: {e}")
    exit(1)

hosts = set()
for line in raw.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    match = re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", line)
    if match:
        hosts.add(f"0.0.0.0 {match.group(1)}")

with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    f.write(f"# Total: {len(hosts)}\n\n")
    f.write("127.0.0.1 localhost\n\n")
    f.writelines(f"{h}\n" for h in sorted(hosts))

print(f"Done: {len(hosts)} entries")