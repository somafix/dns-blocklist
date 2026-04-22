#!/usr/bin/env python3
"""
ADBlock Hosts Updater
"""

import os
import re
import urllib.request
import urllib.error
from datetime import datetime
from typing import Set

SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts",
]

def fetch_url(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Error loading {url}: {e}")
        return ""

def parse_hosts(content: str) -> Set[str]:
    lines = set()
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", line)
        if match:
            lines.add(f"0.0.0.0 {match.group(2)}")
        else:
            dom_match = re.match(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", line)
            if dom_match:
                lines.add(f"0.0.0.0 {dom_match.group(1)}")
    return lines

def main():
    print("Updating blocklist...")
    all_entries = set()
    
    for url in SOURCES:
        print(f"Fetching: {url}")
        content = fetch_url(url)
        if content:
            entries = parse_hosts(content)
            print(f"  Got {len(entries)} entries")
            all_entries.update(entries)
    
    if not all_entries:
        print("ERROR: No entries fetched")
        return
    
    sorted_entries = sorted(all_entries)
    
    header = f"""# ADBlock Hosts List
# Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
# Total entries: {len(sorted_entries)}

127.0.0.1 localhost
::1 localhost

"""
    
    with open("hosts.txt", "w", encoding="utf-8") as f:
        f.write(header)
        for line in sorted_entries:
            f.write(line + "\n")
    
    print(f"Done! Saved {len(sorted_entries)} entries to hosts.txt")

if __name__ == "__main__":
    main()
