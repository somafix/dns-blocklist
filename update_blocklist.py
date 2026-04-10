#!/usr/bin/env python3
import argparse
import urllib.request
import re
import sys
from pathlib import Path

def fetch_sources(sources):
    domains = set()
    for url in sources:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
            
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
                if domain and '..' not in domain and len(domain) < 253:
                    if re.match(r'^[a-z0-9.-]+$', domain):
                        domains.add(domain)
        except Exception as e:
            print(f"Error: {url} - {e}", file=sys.stderr)
    return domains

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-f", "--format", choices=['dnsmasq', 'plain'], default='plain')
    args = parser.parse_args()
    
    if args.fetch:
        sources = [
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fake-news-gambling-porn/hosts",
            "https://someonewhocares.org/hosts/zero/hosts",
            "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
            "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        ]
        domains = fetch_sources(sources)
        
        if args.format == 'plain':
            output = '\n'.join(sorted(domains))
        else:
            output = '\n'.join(f"address=/{d}/0.0.0.0" for d in sorted(domains))
        
        Path(args.output).write_text(output)
        print(f"Saved {len(domains)} domains to {args.output}")

if __name__ == "__main__":
    main()