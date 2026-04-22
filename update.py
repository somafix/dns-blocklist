import requests
import re
from datetime import datetime
import hashlib
import os
import sys
import tempfile
import shutil

URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt"
OUTPUT_FILE = "hosts.txt"
BACKUP_FILE = "hosts.backup"

TIMEOUT = 30
MAX_FILE_SIZE = 50 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

def get_file_hash(filename):
    if not os.path.exists(filename):
        return None
    with open(filename, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

print(f"Загружаю {URL}...")

try:
    response = requests.get(
        URL, 
        timeout=TIMEOUT,
        headers={'User-Agent': USER_AGENT},
        stream=True
    )
    response.raise_for_status()
    
    content_length = int(response.headers.get('content-length', 0))
    if content_length > MAX_FILE_SIZE:
        print(f"ОШИБКА: Файл слишком большой ({content_length} байт)")
        sys.exit(1)
        
except requests.exceptions.Timeout:
    print(f"ОШИБКА: Таймаут ({TIMEOUT} сек). Сервер не отвечает.")
    sys.exit(1)
except requests.exceptions.ConnectionError:
    print("ОШИБКА: Нет соединения с интернетом или GitHub недоступен.")
    sys.exit(1)
except requests.exceptions.HTTPError as e:
    print(f"ОШИБКА: HTTP {e.response.status_code} - {e.response.reason}")
    sys.exit(1)
except Exception as e:
    print(f"ОШИБКА при загрузке: {e}")
    sys.exit(1)

domains = set()
bad_lines = 0
total_lines = 0

with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
    for line in response.iter_lines(decode_unicode=True):
        if line is None:
            continue
        total_lines += 1
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        parts = line.split()
        if len(parts) < 2:
            bad_lines += 1
            continue
            
        domain = parts[1].lower()
        
        if not domain or len(domain) > 253:
            bad_lines += 1
            continue
            
        segments = domain.split('.')
        valid = True
        for seg in segments:
            if not seg or len(seg) > 63:
                valid = False
                break
            if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', seg) and len(seg) > 1:
                valid = False
                break
            if seg.startswith('-') or seg.endswith('-'):
                valid = False
                break
        if not valid:
            bad_lines += 1
            continue
            
        if len(domain) <= 3 and domain not in ['com', 'net', 'org']:
            bad_lines += 1
            continue
            
        domains.add(domain)
    
    tmp_file.write("# HaGeZi Multi PRO++ DNS Blocklist\n")
    tmp_file.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    tmp_file.write(f"# Источник: {URL}\n")
    tmp_file.write(f"# Всего строк: {len(domains)}\n")
    tmp_file.write(f"# Пропущено некорректных: {bad_lines}\n\n")
    
    for domain in sorted(domains):
        tmp_file.write(f"0.0.0.0 {domain}\n")
    
    tmp_path = tmp_file.name

if len(domains) == 0:
    print("ОШИБКА: Не найдено ни одного домена. Файл не сохранён.")
    os.unlink(tmp_path)
    sys.exit(1)

if os.path.exists(OUTPUT_FILE):
    old_hash = get_file_hash(OUTPUT_FILE)
    shutil.copy2(OUTPUT_FILE, BACKUP_FILE)
    shutil.move(tmp_path, OUTPUT_FILE)
    new_hash = get_file_hash(OUTPUT_FILE)
    
    if old_hash == new_hash:
        print(f"ПРЕДУПРЕЖДЕНИЕ: Новый файл идентичен старому (хеш {old_hash})")
    else:
        print(f"Файл изменён: {old_hash} -> {new_hash}")
else:
    shutil.move(tmp_path, OUTPUT_FILE)

print(f"\nГОТОВО!")
print(f"✅ Уникальных доменов: {len(domains)}")
print(f"⚠️  Пропущено строк: {bad_lines} из {total_lines}")
print(f"📁 Сохранено в: {OUTPUT_FILE}")

if os.path.exists(BACKUP_FILE):
    print(f"💾 Бэкап сохранён в: {BACKUP_FILE}")
