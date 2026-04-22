#!/usr/bin/env python3

import urllib.request
import re
from datetime import datetime, timezone
from typing import Set


URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; HostsFetcher/1.0)"}
TIMEOUT = 30
OUTPUT = "hosts.txt"


def fetch(url: str) -> str:
    """Fetch content from URL with error handling."""
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except urllib.error.URLError as e:
        print(f"FAIL {url}: {e}")
        return ""
    except Exception as e:
        print(f"FAIL {url}: Unexpected error: {e}")
        return ""


def extract_hosts(raw: str) -> Set[str]:
    """Extract valid hosts from blocklist content."""
    hosts: Set[str] = set()
    
    # Compile regex patterns for performance
    ip_domain_pattern = re.compile(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")
    domain_pattern = re.compile(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")
    
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        ip_domain_match = ip_domain_pattern.match(line)
        if ip_domain_match:
            hosts.add(f"0.0.0.0 {ip_domain_match.group(2)}")
            continue

        domain_match = domain_pattern.match(line)
        if domain_match:
            hosts.add(f"0.0.0.0 {domain_match.group(1)}")

    return hosts


def save(hosts: Set[str]) -> None:
    """Save hosts to output file with header."""
    sorted_hosts = sorted(hosts)
    
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# HaGeZi Multi Normal\n")
        f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Total: {len(sorted_hosts)}\n")
        f.write("# \n")
        f.write("127.0.0.1 localhost\n")
        f.write("127.0.0.1 localhost.localdomain\n")
        f.write("::1 localhost\n\n")
        
        for line in sorted_hosts:
            f.write(f"{line}\n")


def main() -> None:
    """Main execution function."""
    print("> fetching hosts from HaGeZi blocklist...")
    raw = fetch(URLS[0])
    
    if not raw:
        print("ERROR: Empty response received")
        return

    hosts = extract_hosts(raw)
    
    if not hosts:
        print("ERROR: No valid hosts extracted")
        return
        
    save(hosts)
    print(f"> Success: {len(hosts)} entries saved to {OUTPUT}")


if __name__ == "__main__":
    main()
