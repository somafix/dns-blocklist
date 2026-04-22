#!/usr/bin/env python3

import urllib.request
import re
from datetime import datetime, timezone

URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt"
OUTPUT = "hosts.txt"

print("Downloading...")
try:
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        hosts = set()
        total_lines = 0
        for line in resp:
            total_lines += 1
            if total_lines % 100000 == 0:
                print(f"  Processed {total_lines} lines, found {len(hosts)} hosts...")
            
            try:
                line = line.decode("utf-8", errors="replace").strip()
            except:
                continue
                
            if not line or line.startswith("#"):
                continue
            
            match = re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9._-]+\.[a-zA-Z0-9.-]+)$", line)
            if match:
                hosts.add(f"0.0.0.0 {match.group(1)}")
                
except Exception as e:
    print(f"Error: {e}")
    exit(1)

print(f"Writing {len(hosts)} entries...")
with open(OUTPUT, "w", encoding="utf-8") as f:
    f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    f.write(f"# Total: {len(hosts)}\n\n")
    f.write("127.0.0.1 localhost\n\n")
    f.write("\n".join(sorted(hosts)))
    f.write("\n")

print(f"Done: {len(hosts)} entries")