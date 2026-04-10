#!/usr/bin/env python3
"""Domain blocklist updater - Production grade"""

import urllib.request
import urllib.error
import time
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Optional

SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fake-news-gambling-porn/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
]

def fetch_url(url: str, retries: int = 3) -> Optional[str]:
    """Fetch URL with retries and backoff"""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'BlocklistUpdater/1.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode('utf-8', errors='ignore')
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            if attempt == retries - 1:
                print(f"✗ {url}: {e}", file=sys.stderr)
                return None
            time.sleep(2 ** attempt)  # Exponential backoff
    return None

def parse_hosts(content: str) -> Set[str]:
    """Extract domains from hosts file"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line[0] in '#;![':
            continue
        
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1'):
            domain = parts[1].lower().rstrip('.')
        elif len(parts) == 1 and '.' in parts[0]:
            domain = parts[0].lower().rstrip('.')
        else:
            continue
        
        # Валидация
        if domain and len(domain) < 253 and '..' not in domain:
            if re.match(r'^[a-z0-9.-]+$', domain):
                domains.add(domain)
    
    return domains

def main():
    print(f"🚀 Fetching {len(SOURCES)} blocklists...")
    
    all_domains: Set[str] = set()
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fetch_url, url): url for url in SOURCES}
        
        for future in as_completed(futures):
            url = futures[future]
            content = future.result()
            if content:
                domains = parse_hosts(content)
                all_domains.update(domains)
                print(f"  ✓ {domains:>6,} domains from {url.split('/')[-1][:30]}")
    
    # Сохраняем результат
    output_path = Path('blocklist.txt')
    output_path.write_text('\n'.join(sorted(all_domains)))
    
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"\n✅ Done: {len(all_domains):,} domains, {size_mb:.1f} MB")

if __name__ == "__main__":
    main()
