#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder
Собирает новые трекеры, телеметрию и малварь из живых источников
и генерирует hosts-файл для personalDNSfilter.

Оптимизировано под актуальную конфигурацию personalDNSfilter:
- Источники синхронизированы с конфигом
- Удалены неиспользуемые источники
"""

import re
import urllib.request
import urllib.error
import json
import os
from datetime import datetime, timezone
from time import perf_counter
from collections import defaultdict
from typing import Set, Dict

# ─── Конфигурация ──────────────────────────────────────────────────────────
CACHE_FILE = ".download_cache.json"
OUTPUT_FILE = "dynamic-blocklist.txt"
TIMEOUT = 30

# ─── Источники угроз (синхронизировано с personalDNSfilter) ───────────────
SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "name": "StevenBlack Unified",
        "category": "ads_malware",
    },
    {
        "url": "https://adaway.org/hosts.txt",
        "name": "AdAway",
        "category": "ads",
    },
    {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt",
        "name": "HaGeZi Ultimate",
        "category": "ads_tracking_malware",
    },
]

# ─── Вайтлист ──────────────────────────────────────────────────────────────
WHITELIST = {
    "localhost", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback",
}

# ─── Регулярные выражения ──────────────────────────────────────────────────
DOMAIN_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w\-\.]+)", re.MULTILINE)

# ─── Кэширование ───────────────────────────────────────────────────────────
def load_cache() -> Dict:
    """Загружает кэш ETag/Last-Modified."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_cache(cache: Dict):
    """Сохраняет кэш."""
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

def fetch(url: str, cache: Dict) -> tuple:
    """
    Загружает текст с поддержкой кэширования.
    Возвращает: (текст, использован_кэш)
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "dns-blocklist-builder/3.0"},
    )
    
    cache_entry = cache.get(url, {})
    if "etag" in cache_entry:
        req.add_header("If-None-Match", cache_entry["etag"])
    if "last_modified" in cache_entry:
        req.add_header("If-Modified-Since", cache_entry["last_modified"])
    
    new_cache_entry = {}
    text = ""
    used_cache = False
    
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            new_cache_entry["etag"] = resp.headers.get("ETag")
            new_cache_entry["last_modified"] = resp.headers.get("Last-Modified")
            text = resp.read().decode("utf-8", errors="ignore")
            
    except urllib.error.HTTPError as e:
        if e.code == 304:
            print(f"   💾 Использован кэш")
            used_cache = True
            text = cache_entry.get("content", "")
            new_cache_entry = cache_entry
        else:
            print(f"   ⚠️  HTTP {e.code}")
            return "", False
    except Exception as e:
        print(f"   ⚠️  Ошибка: {e}")
        return "", False
    
    if not used_cache and text:
        new_cache_entry["content"] = text
        new_cache_entry["cached_at"] = datetime.now(timezone.utc).isoformat()
    
    cache[url] = new_cache_entry
    return text, used_cache

# ─── Обработка доменов ─────────────────────────────────────────────────────
def extract_domains(text: str) -> Set[str]:
    """Извлекает домены из hosts-файла."""
    domains = set()
    for match in DOMAIN_RE.finditer(text):
        domain = match.group(1).lower().strip()
        if domain and "." in domain:
            domains.add(domain)
    return domains

def is_valid_domain(domain: str) -> bool:
    """Базовая валидация домена."""
    if domain in WHITELIST:
        return False
    if len(domain) > 253:
        return False
    if domain.startswith("-") or domain.endswith("-"):
        return False
    if "." not in domain:
        return False
    return True

# ─── Статистика ────────────────────────────────────────────────────────────
class StatsCollector:
    def __init__(self):
        self.source_stats = []
        self.total_time = 0.0
        
    def add_source_result(self, name: str, raw_count: int, valid_count: int, 
                         time_sec: float, used_cache: bool):
        self.source_stats.append({
            "name": name,
            "raw": raw_count,
            "valid": valid_count,
            "time": time_sec,
            "cached": used_cache,
        })
        
    def print_summary(self, total_domains: int):
        """Выводит итоговую сводку."""
        print(f"\n{'='*70}")
        print("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ:")
        print(f"{'='*70}")
        print(f"{'Источник':<25} {'Сырые':>8} {'Валидные':>10} {'Время':>8} {'Кэш':>6}")
        print("-" * 70)
        
        total_raw = 0
        for stat in self.source_stats:
            cache_mark = "✓" if stat["cached"] else "✗"
            print(f"{stat['name']:<25} {stat['raw']:>8} {stat['valid']:>10} "
                  f"{stat['time']:>7.2f}s {cache_mark:>6}")
            total_raw += stat["raw"]
            
        print("-" * 70)
        print(f"{'ИТОГО':<25} {total_raw:>8} {total_domains:>10}")
        print(f"\n⏱️  Общее время: {self.total_time:.2f} сек")

def ensure_gitignore():
    """Создаёт .gitignore если его нет."""
    gitignore_path = ".gitignore"
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            if ".download_cache.json" in f.read():
                return
        with open(gitignore_path, "a", encoding="utf-8") as f:
            f.write("\n# DNS blocklist cache\n.download_cache.json\n")
    else:
        with open(gitignore_path, "w", encoding="utf-8") as f:
            f.write("# DNS blocklist cache\n.download_cache.json\n")

# ─── Главная функция ───────────────────────────────────────────────────────
def main():
    ensure_gitignore()
    
    start_total = perf_counter()
    cache = load_cache()
    stats = StatsCollector()
    
    now = datetime.now(timezone.utc)
    print(f"🚀 Запуск сборщика: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"💾 Кэш: {'найден' if cache else 'пуст'}")
    print("=" * 70)

    all_domains = set()
    
    for source in SOURCES:
        print(f"\n📥 {source['name']}")
        start_time = perf_counter()
        
        text, used_cache = fetch(source["url"], cache)
        download_time = perf_counter() - start_time
        
        if not text:
            stats.add_source_result(source["name"], 0, 0, download_time, used_cache)
            continue
            
        raw_domains = extract_domains(text)
        valid_domains = {d for d in raw_domains if is_valid_domain(d)}
        
        stats.add_source_result(
            source["name"], 
            len(raw_domains), 
            len(valid_domains),
            download_time,
            used_cache
        )
        
        cache_status = "(кэш)" if used_cache else f"{len(text)//1024}KB"
        print(f"   ✅ {len(valid_domains):,} доменов {cache_status} [{download_time:.2f}s]")
        
        all_domains.update(valid_domains)

    save_cache(cache)
    
    stats.total_time = perf_counter() - start_total
    stats.print_summary(len(all_domains))

    # Генерация выходного файла
    print(f"\n{'='*70}")
    print("💾 ГЕНЕРАЦИЯ ФАЙЛА:")
    
    lines = [
        "# ============================================================",
        "# Dynamic DNS Blocklist — auto-generated",
        f"# Updated: {now.strftime('%Y-%m-%d %H:%M UTC')}",
        f"# Total domains: {len(all_domains):,}",
        "# Sources: StevenBlack, AdAway, HaGeZi Ultimate",
        "# ============================================================",
        "",
    ]
    
    sorted_domains = sorted(all_domains)
    lines.extend(f"0.0.0.0 {domain}" for domain in sorted_domains)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    
    file_size = os.path.getsize(OUTPUT_FILE)
    print(f"   📁 {OUTPUT_FILE}")
    print(f"   📏 {file_size:,} байт ({file_size//1024} KB)")
    print(f"   📝 {len(lines):,} строк")
    
    print(f"\n{'='*70}")
    print(f"✅ Готово! {len(all_domains):,} уникальных доменов")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
