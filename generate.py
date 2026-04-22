#!/usr/bin/env python3
import requests
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://urlhaus.abuse.ch/downloads/hostfile/",
    "https://phishing.army/download/phishing_army_blocklist.txt",
]

DOMAIN_REGEX = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')

def fetch(url):
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "blocklist/1.0"})
        domains = set()
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                domain = parts[1].lower().rstrip('.')
            elif len(parts) == 1 and '.' in parts[0]:
                domain = parts[0].lower().rstrip('.')
            else:
                continue
            if DOMAIN_REGEX.match(domain) and '..' not in domain:
                domains.add(domain)
        print(f"Fetched {len(domains)} from {url}", file=sys.stderr)
        return domains
    except Exception as e:
        print(f"Failed {url}: {e}", file=sys.stderr)
        return set()

def main():
    all_domains = set()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fetch, url): url for url in SOURCES}
        for future in as_completed(futures):
            all_domains.update(future.result())
    
    domains = sorted(all_domains)
    with open('blocklist.txt', 'w') as f:
        f.write('\n'.join(domains))
    
    print(f"Generated {len(domains)} unique domains", file=sys.stderr)

if __name__ == '__main__':
    main()
