import requests
import re
from datetime import datetime

URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt"
OUTPUT_FILE = "hosts.txt"

print(f"Загружаю {URL}...")
response = requests.get(URL)
response.raise_for_status()

domains = set()

for line in response.text.splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    
    parts = line.split()
    if len(parts) >= 2:
        domain = parts[1].lower()
        if re.match(r'^[a-z0-9\.\-]+$', domain) and len(domain) > 3:
            domains.add(domain)

with open(OUTPUT_FILE, "w") as f:
    f.write("# HaGeZi Multi PRO++ DNS Blocklist\n")
    f.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("# Источник: https://github.com/hagezi/dns-blocklists\n\n")
    
    for domain in sorted(domains):
        f.write(f"0.0.0.0 {domain}\n")

print(f"Готово! Сохранено {len(domains)} уникальных доменов в {OUTPUT_FILE}")
