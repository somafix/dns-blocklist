import requests
import re

# Прямая ссылка на HaGeZi Multi PRO++ (формат hosts)
url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt"

print(f"Загружаю {url}...")
response = requests.get(url)
response.raise_for_status()  # Если ссылка битая — упадёт с ошибкой

lines = response.text.splitlines()

# Множество для уникальных доменов (автоматически убирает дубли)
unique_domains = set()

for line in lines:
    line = line.strip()
    
    # Пропускаем пустые строки и комментарии
    if not line or line.startswith('#'):
        continue
    
    # Формат hosts: "0.0.0.0 domain.com" или "127.0.0.1 domain.com"
    parts = line.split()
    if len(parts) >= 2:
        domain = parts[1].lower()  # Берём домен, приводим к нижнему регистру
        
        # Базовая проверка: домен не должен быть мусором
        if re.match(r'^[a-z0-9\.\-]+$', domain) and len(domain) > 3:
            unique_domains.add(domain)

# Сортируем и записываем в hosts.txt
with open("hosts.txt", "w") as f:
    f.write("# HaGeZi Multi PRO++ DNS Blocklist\n")
    f.write("# Обновлено: " + __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
    f.write("# Источник: https://github.com/hagezi/dns-blocklists\n\n")
    
    for domain in sorted(unique_domains):
        f.write(f"0.0.0.0 {domain}\n")

print(f"Готово! Сохранено {len(unique_domains)} уникальных доменов в hosts.txt")