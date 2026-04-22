#!/usr/bin/env python3

import urllib.request
import re
from datetime import datetime, timezone
from typing import Set
import subprocess
import sys


URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; HostsFetcher/1.0)"}
TIMEOUT = 30
OUTPUT = "hosts.txt"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"FAIL {url}: {e}")
        return ""


def extract_hosts(raw: str) -> Set[str]:
    hosts: Set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            hosts.add(f"0.0.0.0 {parts[1]}")
        elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", line):
            hosts.add(f"0.0.0.0 {line}")
    return hosts


def main() -> None:
    raw = fetch(URLS[0])
    if not raw:
        sys.exit(1)
    
    hosts = extract_hosts(raw)
    sorted_hosts = sorted(hosts)
    
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Total: {len(sorted_hosts)}\n\n")
        f.writelines(f"{line}\n" for line in sorted_hosts)
    
    subprocess.run(["git", "config", "user.name", "GitHub Actions"], check=False)
    subprocess.run(["git", "config", "user.email", "actions@github.com"], check=False)
    subprocess.run(["git", "add", OUTPUT], check=False)
    subprocess.run(["git", "commit", "-m", f"Update {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"], check=False)
    subprocess.run(["git", "pull", "--rebase"], check=False)
    subprocess.run(["git", "push"], check=False)


if __name__ == "__main__":
    main()