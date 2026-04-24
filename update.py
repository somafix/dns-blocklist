import requests
import re
from datetime import datetime
import hashlib
import os
import sys
import tempfile
import shutil
import json
import math
from collections import defaultdict

# Источники
URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt"
AI_BLOCKLIST_FILE = "ai_custom_blocklist.txt"
OUTPUT_FILE = "hosts.txt"
BACKUP_FILE = "hosts.backup"
AI_DB_FILE = "ai_trackers.json"

TIMEOUT = 30
MAX_FILE_SIZE = 50 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ============ ИИ-МОДУЛЬ ============
class TrackerAI:
    def __init__(self):
        self.db_file = AI_DB_FILE
        self.blocklist_file = AI_BLOCKLIST_FILE
        self.reputation = defaultdict(float)
        self.ai_custom_domains = set()
        self.load_db()
        self.load_custom_blocklist()
    
    def load_db(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    data = json.load(f)
                    self.reputation = defaultdict(float, data.get('reputation', {}))
                print(f"🤖 ИИ загрузил базу репутаций: {len(self.reputation)} доменов")
            except:
                print("🤖 ИИ создаёт новую базу репутаций")
    
    def load_custom_blocklist(self):
        if os.path.exists(self.blocklist_file):
            try:
                with open(self.blocklist_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if line.startswith('0.0.0.0 '):
                                domain = line[8:]
                            else:
                                domain = line
                            self.ai_custom_domains.add(domain.lower())
                print(f"🤖 ИИ загрузил свой блоклист: {len(self.ai_custom_domains)} доменов")
            except Exception as e:
                print(f"⚠️ Не удалось загрузить ИИ-блоклист: {e}")
    
    def save_custom_blocklist(self):
        with open(self.blocklist_file, 'w') as f:
            f.write(f"# AI Self-Learning Blocklist\n")
            f.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Всего доменов: {len(self.ai_custom_domains)}\n\n")
            for domain in sorted(self.ai_custom_domains):
                f.write(f"0.0.0.0 {domain}\n")
    
    def calculate_entropy(self, s):
        if not s:
            return 0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum([p * math.log(p) / math.log(2) for p in prob])
    
    def is_suspicious_domain(self, domain):
        score = 0
        parts = domain.split('.')
        if len(parts) > 5:
            score += 2
        for part in parts[:-2]:
            if len(part) > 20:
                score += 1
            if re.search(r'\d{5,}', part):
                score += 2
            if self.calculate_entropy(part) > 4.0:
                score += 2
            if re.search(r'[_]', part):
                score += 1
        
        suspicious_keywords = [
            'track', 'analytics', 'metrics', 'stat', 'pixel', 'tag',
            'click', 'adserver', 'doubleclick', 'googlead', 'facebook',
            'criteo', 'taboola', 'outbrain', 'exelator', 'adsrv',
            'ssp', 'dsp', 'rtb', 'bid', 'impression', 'beacon', 'counter'
        ]
        domain_lower = domain.lower()
        for kw in suspicious_keywords:
            if kw in domain_lower:
                score += 1
        
        main_part = parts[-2] if len(parts) >= 2 else parts[0]
        if len(main_part) <= 3 and main_part not in ['com', 'net', 'org', 'ru', 'cn']:
            score += 2
        
        return score >= 5
    
    def analyze_and_remember(self, domain):
        if domain in self.ai_custom_domains:
            return True
        
        if domain in self.reputation:
            if self.reputation[domain] <= -3:
                self.ai_custom_domains.add(domain)
                return True
        
        if self.is_suspicious_domain(domain):
            self.reputation[domain] -= 2
            self.ai_custom_domains.add(domain)
            print(f"   🤖 ИИ добавил: {domain}")
            return True
        else:
            self.reputation[domain] += 0.5
            return False
    
    def get_custom_blocklist(self):
        return self.ai_custom_domains
    
    def save_all(self):
        with open(self.db_file, 'w') as f:
            json.dump({'reputation': dict(self.reputation)}, f, indent=2)
        self.save_custom_blocklist()
# ============ КОНЕЦ ИИ-МОДУЛЯ ============

def get_file_hash(filename):
    if not os.path.exists(filename):
        return None
    with open(filename, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def download_blocklist(url, description):
    print(f"Загружаю {description} из {url}...")
    domains = set()
    try:
        response = requests.get(
            url, 
            timeout=TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            stream=True
        )
        response.raise_for_status()
        
        for line in response.iter_lines(decode_unicode=True):
            if line is None:
                continue
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            domain = parts[1].lower()
            
            if not domain or len(domain) > 253:
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
                continue
                
            domains.add(domain)
        
        print(f"   ✅ Загружено {len(domains)} доменов")
        return domains
        
    except Exception as e:
        print(f"   ❌ Ошибка загрузки {description}: {e}")
        return set()

# ============ ОСНОВНАЯ ЛОГИКА ============
print("=" * 50)
print("DNS-блоклист с самообучающимся ИИ")
print("=" * 50)

ai = TrackerAI()

main_domains = download_blocklist(URL, "HaGeZi PRO++")

if len(main_domains) == 0:
    print("ОШИБКА: Не удалось загрузить основной блоклист.")
    sys.exit(1)

ai_domains = ai.get_custom_blocklist()
print(f"\n🤖 ИИ уже заблокировал ранее: {len(ai_domains)} доменов")

print(f"\n🧠 ИИ анализирует {len(main_domains)} доменов...")
new_ai_blocks = 0
for domain in main_domains:
    if ai.analyze_and_remember(domain):
        new_ai_blocks += 1

all_domains = main_domains.union(ai_domains)

ai.save_all()
print(f"\n💾 ИИ сохранил свой блоклист: {len(ai.get_custom_blocklist())} доменов")
if new_ai_blocks > 0:
    print(f"   ✨ Новых добавлено: {new_ai_blocks}")

print(f"\n📝 Записываю итоговый блоклист...")
with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp_file:
    tmp_file.write("# DNS Blocklist: HaGeZi PRO++ + AI Self-Learning\n")
    tmp_file.write(f"# Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    tmp_file.write(f"# Доменов из HaGeZi: {len(main_domains)}\n")
    tmp_file.write(f"# Доменов от ИИ: {len(ai_domains)}\n")
    tmp_file.write(f"# Всего: {len(all_domains)}\n\n")
    
    for domain in sorted(all_domains):
        tmp_file.write(f"0.0.0.0 {domain}\n")
    
    tmp_path = tmp_file.name

if os.path.exists(OUTPUT_FILE):
    old_hash = get_file_hash(OUTPUT_FILE)
    shutil.copy2(OUTPUT_FILE, BACKUP_FILE)
    shutil.move(tmp_path, OUTPUT_FILE)
    new_hash = get_file_hash(OUTPUT_FILE)
    
    if old_hash == new_hash:
        print(f"⚠️ Файл не изменился (хеш {old_hash})")
    else:
        print(f"📊 Файл изменён: {old_hash} -> {new_hash}")
else:
    shutil.move(tmp_path, OUTPUT_FILE)

print(f"\n{'='*50}")
print(f"✅ ГОТОВО!")
print(f"   • HaGeZi: {len(main_domains)} доменов")
print(f"   • ИИ-блоклист: {len(ai_domains)} доменов")
print(f"   • ВСЕГО: {len(all_domains)} доменов")
print(f"📁 {OUTPUT_FILE}")
print("="*50)
