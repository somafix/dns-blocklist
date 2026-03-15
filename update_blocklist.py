#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder
Собирает новые трекеры, телеметрию и малварь из живых источников
и генерирует hosts-файл для personalDNSfilter.

Улучшения:
- HTTP-кэширование (ETag/Last-Modified) — не грузим, если не изменилось
- Метрики времени выполнения каждого источника
- Детальная статистика по дубликатам между источниками
- Итоговая сводка производительности
- Автосоздание .gitignore
"""

import re
import urllib.request
import urllib.error
import json
import os
from datetime import datetime, timezone
from time import perf_counter
from collections import defaultdict
from typing import Set, Dict, List, Tuple

# ─── Конфигурация ──────────────────────────────────────────────────────────
CACHE_FILE = ".download_cache.json"
OUTPUT_FILE = "dynamic-blocklist.txt"
TIMEOUT = 30

# ─── Источники угроз ───────────────────────────────────────────────────────
SOURCES = [
    {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "name": "URLhaus (abuse.ch)",
        "category": "malware",
    },
    {
        "url": "https://openphish.com/feed.txt",
        "name": "OpenPhish",
        "is_url_list": True,
        "category": "phishing",
    },
    {
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "name": "ThreatFox (abuse.ch)",
        "category": "malware",
    },
    {
        "url": "https://hole.cert.pl/domains/domains_hosts.txt",
        "name": "CERT.PL",
        "category": "malware",
    },
    {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt",
        "name": "HaGeZi Pro++",
        "category": "ads_tracking",
    },
]

# ─── Вайтлист ──────────────────────────────────────────────────────────────
WHITELIST = {
    "localhost", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback",
}

# ─── Регулярные выражения ──────────────────────────────────────────────────
DOMAIN_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w\-\.]+)", re.MULTILINE)
URL_DOMAIN_RE = re.compile(r"https?://([^/\s:]+)")

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

def fetch(url: str, cache: Dict) -> Tuple[str, bool, Dict]:
    """
    Загружает текст с поддержкой кэширования.
    Возвращает: (текст, использован_кэш, обновленный_кэш_заголовок)
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "dns-blocklist-builder/2.0"},
    )
    
    # Добавляем кэш-заголовки
    cache_entry = cache.get(url, {})
    if "etag" in cache_entry:
        req.add_header("If-None-Match", cache_entry["etag"])
    if "last_modified" in cache_entry:
        req.add_header("If-Modified-Since", cache_entry["last_modified"])
    
    new_cache_entry = {}
    text = ""
    used_cache = False
    
    try:
        start_time = perf_counter()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            # Собираем новые кэш-заголовки
            new_cache_entry["etag"] = resp.headers.get("ETag")
            new_cache_entry["last_modified"] = resp.headers.get("Last-Modified")
            
            text = resp.read().decode("utf-8", errors="ignore")
            download_time = perf_counter() - start_time
            
    except urllib.error.HTTPError as e:
        if e.code == 304:  # Not Modified
            print(f"   💾 Использован кэш (304 Not Modified)")
            used_cache = True
            text = cache_entry.get("content", "")
            new_cache_entry = cache_entry  # Сохраняем старые заголовки
        else:
            print(f"   ⚠️  HTTP ошибка {e.code}: {e.reason}")
            return "", False, {}
    except Exception as e:
        print(f"   ⚠️  Ошибка загрузки: {e}")
        return "", False, {}
    
    # Сохраняем контент в кэш только если получили новые данные
    if not used_cache and text:
        new_cache_entry["content"] = text
        new_cache_entry["cached_at"] = datetime.now(timezone.utc).isoformat()
    
    cache[url] = new_cache_entry
    return text, used_cache, new_cache_entry

# ─── Обработка доменов ─────────────────────────────────────────────────────
def extract_domains(text: str, is_url_list: bool = False) -> Set[str]:
    """Извлекает домены из hosts-файла или списка URL."""
    domains = set()
    if is_url_list:
        for match in URL_DOMAIN_RE.finditer(text):
            domain = match.group(1).lower().strip()
            if domain and "." in domain:
                domains.add(domain)
    else:
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

# ─── Статистика и аналитика ────────────────────────────────────────────────
class StatsCollector:
    def __init__(self):
        self.source_stats = []
        self.duplicates_analysis = defaultdict(set)  # domain -> set of sources
        self.total_time = 0.0
        
    def add_source_result(self, name: str, raw_count: int, valid_count: int, 
                         time_sec: float, used_cache: bool, category: str):
        self.source_stats.append({
            "name": name,
            "raw": raw_count,
            "valid": valid_count,
            "time": time_sec,
            "cached": used_cache,
            "category": category,
        })
        
    def add_domain_source(self, domain: str, source: str):
        self.duplicates_analysis[domain].add(source)
        
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
        print(f"\n⏱️  Общее время выполнения: {self.total_time:.2f} сек")
        
        # Анализ пересечений
        print(f"\n{'='*70}")
        print("🔗 АНАЛИЗ ПЕРЕСЕЧЕНИЙ МЕЖДУ ИСТОЧНИКАМИ:")
        print(f"{'='*70}")
        
        overlaps = defaultdict(int)
        category_stats = defaultdict(lambda: {"unique": set(), "total": 0})
        
        for domain, sources in self.duplicates_analysis.items():
            if len(sources) > 1:
                key = " + ".join(sorted(sources))
                overlaps[key] += 1
            
            # Статистика по категориям
            for src in sources:
                cat = next((s["category"] for s in SOURCES if s["name"] == src), "unknown")
                category_stats[cat]["total"] += 1
                if len(sources) == 1:  # Уникальный для категории
                    category_stats[cat]["unique"].add(domain)
        
        if overlaps:
            for combo, count in sorted(overlaps.items(), key=lambda x: -x[1])[:5]:
                print(f"   {combo}: {count} доменов")
        else:
            print("   Пересечений между источниками не обнаружено")
            
        # Статистика по категориям
        print(f"\n{'='*70}")
        print("🛡️  РАСПРЕДЕЛЕНИЕ ПО КАТЕГОРИЯМ:")
        print(f"{'='*70}")
        category_names = {
            "malware": "🦠 Малварь/C2",
            "phishing": "🎣 Фишинг", 
            "ads_tracking": "📺 Реклама/Трекинг"
        }
        for cat, data in sorted(category_stats.items()):
            name = category_names.get(cat, cat)
            unique = len(data["unique"])
            total = data["total"]
            shared = total - unique
            print(f"   {name:<20} {total:>6} всего ({unique} уникальных, {shared} пересекаются)")

def ensure_gitignore():
    """Создаёт .gitignore если его нет. Безопасно, не перезаписывает существующий."""
    gitignore_path = ".gitignore"
    if os.path.exists(gitignore_path):
        # Проверим, есть ли уже наша строка в файле
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()
        if ".download_cache.json" in content:
            return  # Уже есть, ничего не делаем
        
        # Дописываем в конец
        with open(gitignore_path, "a", encoding="utf-8") as f:
            f.write("\n# Кэш DNS блоклиста\n.download_cache.json\n")
        print("📝 Добавлен .download_cache.json в существующий .gitignore")
    else:
        # Создаём новый файл
        with open(gitignore_path, "w", encoding="utf-8") as f:
            f.write("# Кэш DNS блоклиста\n.download_cache.json\n")
        print("📝 Создан новый .gitignore с кэшем блоклиста")

# ─── Главная функция ───────────────────────────────────────────────────────
def main():
    # Создаём .gitignore если нужно (не сломает ничего)
    ensure_gitignore()
    
    start_total = perf_counter()
    cache = load_cache()
    stats = StatsCollector()
    
    now = datetime.now(timezone.utc)
    print(f"🚀 Запуск сборщика блок-листа: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"💾 Кэш: {'найден' if cache else 'пуст'} ({CACHE_FILE})")
    print("=" * 70)

    all_domains = set()
    
    for source in SOURCES:
        print(f"\n📥 {source['name']} [{source.get('category', 'unknown')}]")
        start_time = perf_counter()
        
        # Загрузка с кэшированием
        text, used_cache, _ = fetch(source["url"], cache)
        download_time = perf_counter() - start_time
        
        if not text:
            stats.add_source_result(
                source["name"], 0, 0, download_time, False, 
                source.get("category", "unknown")
            )
            continue
            
        # Обработка
        is_url_list = source.get("is_url_list", False)
        raw_domains = extract_domains(text, is_url_list)
        valid_domains = {d for d in raw_domains if is_valid_domain(d)}
        
        # Статистика по дубликатам
        for domain in valid_domains:
            stats.add_domain_source(domain, source["name"])
            
        # Сохраняем статистику
        stats.add_source_result(
            source["name"], 
            len(raw_domains), 
            len(valid_domains),
            download_time,
            used_cache,
            source.get("category", "unknown")
        )
        
        cache_status = "(из кэша)" if used_cache else f"({len(text)//1024} KB)"
        print(f"   ✅ Доменов: {len(valid_domains):,} {cache_status} [{download_time:.2f}s]")
        
        all_domains.update(valid_domains)

    # Сохраняем кэш
    save_cache(cache)
    
    stats.total_time = perf_counter() - start_total
    stats.print_summary(len(all_domains))

    # Генерация выходного файла
    print(f"\n{'='*70}")
    print("💾 ГЕНЕРАЦИЯ ФАЙЛА:")
    print(f"{'='*70}")
    
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# ============================================================",
        "# Dynamic DNS Blocklist — auto-generated",
        f"# Updated: {timestamp}",
        f"# Total domains: {len(all_domains):,}",
        "# Sources: URLhaus, OpenPhish, ThreatFox, CERT.PL, HaGeZi Pro++",
        "# Cache: ETag/Last-Modified supported",
        "# ============================================================",
        "",
    ]
    
    # Добавляем домены с сортировкой
    sorted_domains = sorted(all_domains)
    lines.extend(f"0.0.0.0 {domain}" for domain in sorted_domains)
    
    output = "\n".join(lines) + "\n"
    
    # Запись файла
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(output)
    
    file_size = os.path.getsize(OUTPUT_FILE)
    print(f"   📁 Файл: {OUTPUT_FILE}")
    print(f"   📏 Размер: {file_size:,} байт ({file_size//1024} KB)")
    print(f"   📝 Строк: {len(lines):,}")
    
    # Итог
    print(f"\n{'='*70}")
    print(f"✅ Готово! Уникальных доменов в блок-листе: {len(all_domains):,}")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()
