#!/usr/bin/env python3

import urllib.request
import re
from datetime import datetime


URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
]

HEADERS = {"User-Agent": "Mozilla/5.0"}
TIMEOUT = 30
OUTPUT = "hosts.txt"


def fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"FAIL {url}: {e}")
        return ""


def extract_hosts(raw: str) -> set:
    hosts = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        ip_domain = re.match(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", line)
        if ip_domain:
            hosts.add(f"0.0.0.0 {ip_domain.group(2)}")
            continue

        only_domain = re.match(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", line)
        if only_domain:
            hosts.add(f"0.0.0.0 {only_domain.group(1)}")

    return hosts


def save(hosts: set) -> None:
    sorted_hosts = sorted(hosts)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(f"# HaGeZi Multi Normal\n")
        f.write(f"# Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Total: {len(sorted_hosts)}\n\n")
        f.write("127.0.0.1 localhost\n\n")
        f.writelines(f"{line}\n" for line in sorted_hosts)


def main() -> None:
    print("> fetching")
    raw = fetch(URLS[0])
    if not raw:
        print("ERROR: empty response")
        return

    hosts = extract_hosts(raw)
    save(hosts)
    print(f"> done: {len(hosts)} entries -> {OUTPUT}")


if __name__ == "__main__":
    main()