#!/usr/bin/env python3
import urllib.request
import re
import sys
from pathlib import Path

# Источники
SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fake-news-gambling-porn/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
]

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Ошибка {url}: {e}")
        return None

def parse_hosts(content):
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
        if domain and '..' not in domain and len(domain) < 253:
            if re.match(r'^[a-z0-9.-]+$', domain):
                domains.add(domain)
    return domains

def main():
    # Аргументы командной строки
    output_file = None
    for i, arg in enumerate(sys.argv):
        if arg == '-o' and i+1 < len(sys.argv):
            output_file = sys.argv[i+1]
    
    if not output_file:
        output_file = 'blocklist.txt'
    
    print("🚀 Загрузка...")
    
    all_domains = set()
    for url in SOURCES:
        print(f"  {url.split('/')[-1][:40]}...")
        content = fetch_url(url)
        if content:
            domains = parse_hosts(content)
            all_domains.update(domains)
            print(f"    +{len(domains)} доменов (всего: {len(all_domains)})")
    
    # Сохраняем
    sorted_domains = sorted(all_domains)
    with open(output_file, 'w') as f:
        f.write('\n'.join(sorted_domains))
    
    size_mb = Path(output_file).stat().st_size / (1024 * 1024)
    print(f"\n✅ Готово!")
    print(f"📊 Доменов: {len(sorted_domains):,}")
    print(f"💾 Размер: {size_mb:.1f} МБ")
    print(f"📁 Файл: {output_file}")

if __name__ == "__main__":
    main()