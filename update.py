#!/usr/bin/env python3
"""
DNS Blocklist Manager v4.0.0 - Полностью автономная система блокировки трекеров
Рефакторинг: async/aiohttp, ETag кэширование, улучшенная репутация, чистая архитектура
"""

import asyncio
import aiohttp
import hashlib
import re
import json
import gzip
import math
import os
import sys
import signal
import shutil
import tempfile
import time
from datetime import datetime
from typing import Set, Dict, Optional, Tuple, List
from pathlib import Path
from collections import defaultdict

__author__ = "somafix"
__version__ = "4.0.0"

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
CONFIG = {
    "urls": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    ],
    "timeout": 30,
    "max_file_size_mb": 50,
    "max_domains_to_analyze": 100_000,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "cleanup_days": 30,
    # Reputation
    "reputation_threshold": 5.0,       # выше → снять блокировку
    "reputation_block_at": -3.0,       # ниже → добавить в blocklist
    "reputation_decay": 0.05,          # ежедневное затухание (к нулю)
    "frequency_weight": 0.3,           # вес частоты появления
    "min_reputation": -10.0,
    "max_reputation": 10.0,
    # Cache
    "dns_cache_ttl": 3600,
    "enable_dns_cache": True,
    # Logs
    "enable_log_rotation": True,
    "max_log_size_mb": 10,
    "backup_count": 3,
}

FILES = {
    "output":     Path("hosts.txt"),
    "backup":     Path("hosts.backup"),
    "ai_db":      Path("ai_trackers.json"),
    "ai_blocklist": Path("ai_custom_blocklist.txt"),
    "whitelist":  Path("ai_whitelist.txt"),
    "etag_cache": Path("etag_cache.json"),
    "log":        Path("dns_blocker.log"),
}

SUSPICIOUS_KEYWORDS = [
    'track', 'analytics', 'metrics', 'stat', 'pixel', 'tag',
    'click', 'adserver', 'doubleclick', 'googlead', 'google-analytics',
    'facebook', 'criteo', 'taboola', 'outbrain', 'exelator', 'adsrv',
    'ssp', 'dsp', 'rtb', 'bid', 'impression', 'beacon', 'counter',
    'adzerk', 'appnexus', 'adnxs', 'rubicon', 'openx', 'pubmatic',
    'indexww', 'contextweb', 'monetize', 'mediation', 'adsystem',
    'clicktrack', 'trk', 'tracker', 'telemetry',
]

LEGIT_EXCEPTIONS = {
    'cloudflare', 'amazonaws', 'googleapis', 'github', 'cdn',
    'cloudfront', 'akamaiedge', 'fastly', 'stackpath',
}

SUSPICIOUS_PATTERNS = [
    re.compile(r'^ad[\d\-\.]', re.I),
    re.compile(r'^ads[\d\-\.]', re.I),
    re.compile(r'\.ad[\d\-\.]', re.I),
    re.compile(r'-ad[\-\.]', re.I),
    re.compile(r'trk[\-\.]', re.I),
    re.compile(r'track[\-\.]', re.I),
    re.compile(r'click[\-\.]', re.I),
    re.compile(r'redirect[\-\.]', re.I),
    re.compile(r'banner[\-\.]', re.I),
    re.compile(r'^[a-z0-9]{20,}\.', re.I),
    re.compile(r'[0-9a-f]{16,}', re.I),
    re.compile(r'pixel\.[a-z]+', re.I),
]


# ─────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────
class Logger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_log(self):
        if not CONFIG["enable_log_rotation"] or not self.log_file.exists():
            return
        if self.log_file.stat().st_size > CONFIG["max_log_size_mb"] * 1024 * 1024:
            for i in range(CONFIG["backup_count"] - 1, 0, -1):
                old = self.log_file.with_suffix(f'.{i}.gz')
                new = self.log_file.with_suffix(f'.{i-1}.gz') if i > 1 else self.log_file
                old.unlink(missing_ok=True)
                if new.exists() and i > 1:
                    new.rename(old)
            with open(self.log_file, 'rb') as f_in:
                with gzip.open(self.log_file.with_suffix('.1.gz'), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            self.log_file.unlink()

    def _write(self, level: str, message: str):
        line = f"[{datetime.now().isoformat()}] [{level}] {message}\n"
        try:
            self._rotate_log()
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass
        print(f"[{level}] {message}")

    def info(self, msg):    self._write("INFO", msg)
    def error(self, msg):   self._write("ERROR", msg)
    def warning(self, msg): self._write("WARNING", msg)


# ─────────────────────────────────────────────
#  DNS IN-MEMORY CACHE
# ─────────────────────────────────────────────
class DNSCache:
    def __init__(self):
        self._cache: Dict[str, Tuple[bool, float]] = {}
        self.hits = 0
        self.misses = 0

    def get(self, domain: str) -> Optional[bool]:
        if not CONFIG["enable_dns_cache"]:
            return None
        entry = self._cache.get(domain)
        if entry:
            result, expires = entry
            if time.monotonic() < expires:
                self.hits += 1
                return result
            del self._cache[domain]
        self.misses += 1
        return None

    def set(self, domain: str, value: bool):
        if CONFIG["enable_dns_cache"]:
            self._cache[domain] = (value, time.monotonic() + CONFIG["dns_cache_ttl"])

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0


# ─────────────────────────────────────────────
#  ETAG HTTP CACHE
# ─────────────────────────────────────────────
class ETagCache:
    """Хранит ETag/Last-Modified для каждого URL — не скачивает если не изменилось."""

    def __init__(self, cache_file: Path):
        self.cache_file = cache_file
        self._data: Dict[str, dict] = self._load()

    def _load(self) -> dict:
        if self.cache_file.exists():
            try:
                return json.loads(self.cache_file.read_text())
            except Exception:
                pass
        return {}

    def save(self):
        try:
            self.cache_file.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def get_headers(self, url: str) -> dict:
        entry = self._data.get(url, {})
        headers = {}
        if entry.get("etag"):
            headers["If-None-Match"] = entry["etag"]
        if entry.get("last_modified"):
            headers["If-Modified-Since"] = entry["last_modified"]
        return headers

    def update(self, url: str, response_headers: dict):
        self._data[url] = {
            "etag": response_headers.get("ETag", ""),
            "last_modified": response_headers.get("Last-Modified", ""),
        }

    def get_cached_content(self, url: str) -> Optional[str]:
        entry = self._data.get(url, {})
        cached_path = entry.get("cached_path")
        if cached_path and Path(cached_path).exists():
            return Path(cached_path).read_text(encoding='utf-8', errors='ignore')
        return None

    def set_cached_content(self, url: str, content: str):
        filename = hashlib.md5(url.encode()).hexdigest() + ".cache"
        path = FILES["etag_cache"].parent / filename
        try:
            path.write_text(content, encoding='utf-8')
            self._data.setdefault(url, {})["cached_path"] = str(path)
        except Exception:
            pass


# ─────────────────────────────────────────────
#  DOMAIN VALIDATION
# ─────────────────────────────────────────────
_SEGMENT_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$')

def validate_domain(domain: str) -> bool:
    """Валидирует домен. Допускает однобуквенные сегменты (фикс v3)."""
    if not domain or len(domain) > 253:
        return False
    segments = domain.lower().split('.')
    if len(segments) < 2:
        return False
    for seg in segments:
        if not seg or len(seg) > 63:
            return False
        # Однобуквенный сегмент допустим: 'a', 'b', 'x' и т.д.
        if len(seg) == 1:
            if not seg.isalnum():
                return False
        else:
            if not _SEGMENT_RE.match(seg):
                return False
    return True


# ─────────────────────────────────────────────
#  ASYNC DOWNLOADER
# ─────────────────────────────────────────────
async def fetch_blocklist(
    session: aiohttp.ClientSession,
    url: str,
    etag_cache: ETagCache,
    logger: Logger,
) -> Set[str]:
    """Скачивает список с поддержкой ETag (304 Not Modified → берём кэш)."""
    conditional_headers = etag_cache.get_headers(url)
    headers = {
        "User-Agent": CONFIG["user_agent"],
        **conditional_headers,
    }

    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])) as resp:
            if resp.status == 304:
                logger.info(f"304 Not Modified: {url}")
                cached = etag_cache.get_cached_content(url)
                if cached:
                    return _parse_hosts(cached)
                # нет локального кэша — придётся скачать заново без заголовков
                async with session.get(url, headers={"User-Agent": CONFIG["user_agent"]},
                                       timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])) as r2:
                    r2.raise_for_status()
                    text = await r2.text(encoding='utf-8', errors='ignore')
                    etag_cache.update(url, dict(r2.headers))
                    etag_cache.set_cached_content(url, text)
                    return _parse_hosts(text)

            resp.raise_for_status()

            # Проверка размера
            cl = resp.headers.get("Content-Length")
            if cl and int(cl) > CONFIG["max_file_size_mb"] * 1024 * 1024:
                raise ValueError(f"File too large: {url}")

            text = await resp.text(encoding='utf-8', errors='ignore')
            etag_cache.update(url, dict(resp.headers))
            etag_cache.set_cached_content(url, text)
            return _parse_hosts(text)

    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        # Fallback на кэш
        cached = etag_cache.get_cached_content(url)
        if cached:
            logger.warning(f"Using cached version for {url}")
            return _parse_hosts(cached)
        return set()


def _parse_hosts(text: str) -> Set[str]:
    domains: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        domain = parts[1].lower()
        if validate_domain(domain):
            domains.add(domain)
    return domains


async def merge_blocklists_async(
    urls: List[str],
    etag_cache: ETagCache,
    logger: Logger,
) -> Set[str]:
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_blocklist(session, url, etag_cache, logger) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    all_domains: Set[str] = set()
    for url, result in zip(urls, results):
        if isinstance(result, Exception):
            logger.error(f"Exception for {url}: {result}")
        else:
            logger.info(f"Loaded {len(result):,} domains from {url}")
            all_domains.update(result)
    return all_domains


# ─────────────────────────────────────────────
#  TRACKER AI
# ─────────────────────────────────────────────
class TrackerAI:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.dns_cache = DNSCache()

        # Репутация и метаданные
        self.reputation: Dict[str, float] = {}
        self.last_seen: Dict[str, str] = {}
        self.first_added: Dict[str, str] = {}
        self.frequency: Dict[str, int] = {}      # сколько раз домен встречался
        self.custom_domains: Set[str] = set()
        self.whitelist: Set[str] = set()

        self.stats = {"analyzed": 0, "added": 0, "removed": 0, "whitelisted": 0}

        self._load_all()

    # ── Загрузка ──────────────────────────────
    def _load_all(self):
        self._load_db()
        self._load_custom_blocklist()
        self._load_whitelist()
        self._apply_reputation_decay()
        self._cleanup_false_positives()

    def _load_db(self):
        f = FILES["ai_db"]
        if not f.exists():
            return
        try:
            data = json.loads(f.read_text())
            self.reputation  = data.get("reputation", {})
            self.last_seen   = data.get("last_seen", {})
            self.first_added = data.get("first_added", {})
            self.frequency   = data.get("frequency", {})
            self.logger.info(f"Loaded DB: {len(self.reputation)} domains")
        except Exception as e:
            self.logger.error(f"Failed to load DB: {e}")

    def _load_custom_blocklist(self):
        f = FILES["ai_blocklist"]
        if not f.exists():
            return
        try:
            for line in f.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                domain = line[8:] if line.startswith('0.0.0.0 ') else line
                self.custom_domains.add(domain.lower())
            self.logger.info(f"Loaded {len(self.custom_domains)} custom blocked domains")
        except Exception as e:
            self.logger.error(f"Failed to load custom blocklist: {e}")

    def _load_whitelist(self):
        f = FILES["whitelist"]
        if not f.exists():
            return
        try:
            for line in f.read_text().splitlines():
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    self.whitelist.add(line)
            self.logger.info(f"Loaded {len(self.whitelist)} whitelisted domains")
        except Exception as e:
            self.logger.error(f"Failed to load whitelist: {e}")

    # ── Репутация: затухание ──────────────────
    def _apply_reputation_decay(self):
        """Ежедневное затухание: репутация плавно движется к 0."""
        decay = CONFIG["reputation_decay"]
        for domain in list(self.reputation):
            rep = self.reputation[domain]
            if abs(rep) < 0.01:
                del self.reputation[domain]
                continue
            self.reputation[domain] = rep * (1 - decay)

    # ── Очистка ложных срабатываний ──────────
    def _cleanup_false_positives(self):
        to_remove = []
        now = datetime.now()
        for domain in list(self.custom_domains):
            if domain in self.whitelist:
                to_remove.append(domain)
                self.stats["whitelisted"] += 1
                continue
            rep = self.reputation.get(domain, 0.0)
            if rep >= CONFIG["reputation_threshold"]:
                to_remove.append(domain)
                self.stats["removed"] += 1
                continue
            last_str = self.last_seen.get(domain)
            if last_str:
                try:
                    delta = (now - datetime.fromisoformat(last_str)).days
                    if delta > CONFIG["cleanup_days"] and rep > -2:
                        to_remove.append(domain)
                        self.stats["removed"] += 1
                except Exception:
                    pass
        for d in to_remove:
            self.custom_domains.discard(d)
        if to_remove:
            self.logger.info(f"Cleaned up {len(to_remove)} false positives")

    # ── Энтропия ─────────────────────────────
    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        l = len(s)
        return -sum((v / l) * math.log2(v / l) for v in freq.values())

    # ── Анализ домена (публичный метод) ───────
    def score_domain(self, domain: str) -> Tuple[bool, int]:
        """Возвращает (is_suspicious, score). Публичный интерфейс."""
        cached = self.dns_cache.get(domain)
        if cached is not None:
            return cached, 0

        d = domain.lower()
        score = 0

        # Белый список CDN/легитимных сервисов
        for exc in LEGIT_EXCEPTIONS:
            if exc in d:
                self.dns_cache.set(domain, False)
                return False, 0

        parts = d.split('.')

        # Структурные признаки
        if len(parts) > 5:
            score += 2
        for part in parts[:-2]:
            if len(part) > 20:
                score += 1
            if re.search(r'\d{5,}', part):
                score += 2
            if '_' in part:
                score += 1
            if len(part) >= 15 and self._entropy(part) > 3.5:
                score += 2

        # Ключевые слова
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in d:
                score += 2
                break  # один раз достаточно — не суммируем все совпадения

        # Паттерны
        for pat in SUSPICIOUS_PATTERNS:
            if pat.search(d):
                score += 1

        # Короткое основное имя (не TLD)
        if len(parts) >= 2:
            main = parts[-2]
            short_legit = {'com', 'net', 'org', 'ru', 'cn', 'io', 'co'}
            if len(main) <= 3 and main not in short_legit:
                score += 2

        result = score >= 4
        self.dns_cache.set(domain, result)
        return result, score

    # ── Запомнить домен ───────────────────────
    def observe(self, domain: str) -> bool:
        """
        Обновляет репутацию домена с учётом частоты.
        Возвращает True если домен добавлен в blocklist.
        """
        now_iso = datetime.now().isoformat()
        d = domain.lower()

        self.last_seen[d] = now_iso
        self.stats["analyzed"] += 1
        self.frequency[d] = self.frequency.get(d, 0) + 1

        if d in self.whitelist:
            self.reputation[d] = min(
                self.reputation.get(d, 0.0) + 1.0,
                CONFIG["max_reputation"]
            )
            self.custom_domains.discard(d)
            return False

        is_suspicious, score = self.score_domain(d)
        freq_bonus = min(self.frequency[d] * CONFIG["frequency_weight"], 3.0)

        if is_suspicious:
            delta = -(1.0 + freq_bonus)
            self.reputation[d] = max(
                self.reputation.get(d, 0.0) + delta,
                CONFIG["min_reputation"]
            )
            if self.reputation[d] <= CONFIG["reputation_block_at"] and d not in self.whitelist:
                if d not in self.custom_domains:
                    self.custom_domains.add(d)
                    self.first_added.setdefault(d, now_iso)
                    self.stats["added"] += 1
                    return True
        else:
            self.reputation[d] = min(
                self.reputation.get(d, 0.0) + 0.5,
                CONFIG["max_reputation"]
            )

        return False

    # ── Пакетный анализ ───────────────────────
    def analyze_batch(self, domains: List[str]) -> int:
        """observe() — чистый CPU без I/O, executor не нужен."""
        added = 0
        for domain in domains:
            if self.observe(domain):
                added += 1
        return added

    # ── Сохранение ────────────────────────────
    def save_all(self):
        try:
            FILES["ai_db"].write_text(json.dumps({
                "reputation":  self.reputation,
                "last_seen":   self.last_seen,
                "first_added": self.first_added,
                "frequency":   self.frequency,
                "version":     __version__,
            }, indent=2))
            self._save_custom_blocklist()
            self.logger.info("All data saved successfully")
        except Exception as e:
            self.logger.error(f"Failed to save data: {e}")

    def _save_custom_blocklist(self):
        try:
            lines = [
                "# AI Self-Learning Blocklist",
                f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"# Total: {len(self.custom_domains)}",
                "",
            ]
            lines += [f"0.0.0.0 {d}" for d in sorted(self.custom_domains)]
            FILES["ai_blocklist"].write_text('\n'.join(lines) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to save custom blocklist: {e}")

    def get_custom_domains(self) -> Set[str]:
        return self.custom_domains.copy()


# ─────────────────────────────────────────────
#  WRITE HOSTS FILE
# ─────────────────────────────────────────────
def write_hosts_file(domains: Set[str], output_path: Path, backup_path: Path) -> bool:
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8', suffix='.tmp') as tmp:
            tmp_path = tmp.name
            tmp.write("# DNS Blocklist Manager v4.0.0\n")
            tmp.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            tmp.write(f"# Total domains: {len(domains):,}\n")
            tmp.write("# ==========================================\n\n")
            for domain in sorted(domains):
                tmp.write(f"0.0.0.0 {domain}\n")
        if output_path.exists():
            shutil.copy2(output_path, backup_path)
        shutil.move(tmp_path, output_path)
        return True
    except Exception as e:
        print(f"ERROR: Failed to write hosts file: {e}")
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return False


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def signal_handler(signum, frame):
    print("\nInterrupted.")
    sys.exit(0)


async def async_main() -> int:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"DNS Blocklist Manager v{__version__}  |  Author: {__author__}")
    print("=" * 55)

    logger     = Logger(FILES["log"])
    etag_cache = ETagCache(FILES["etag_cache"])
    ai         = TrackerAI(logger)

    logger.info(f"Starting DNS Blocklist Manager v{__version__}")

    # ── 1. Скачивание ─────────────────────────
    print("\n[1/4] Downloading blocklists (async + ETag)...")
    main_domains = await merge_blocklists_async(CONFIG["urls"], etag_cache, logger)
    etag_cache.save()

    if not main_domains:
        logger.error("Failed to download any blocklist")
        return 1

    print(f"      Total domains fetched: {len(main_domains):,}")

    # ── 2. Фильтрация подозрительных ──────────
    print("\n[2/4] Scoring domains...")
    suspicious: List[str] = []
    sample = list(main_domains)[:CONFIG["max_domains_to_analyze"]]
    for domain in sample:
        is_susp, _ = ai.score_domain(domain)
        if is_susp:
            suspicious.append(domain)

    print(f"      Suspicious found: {len(suspicious):,}")
    print(f"      DNS cache hit rate: {ai.dns_cache.hit_rate:.1f}%")

    # ── 3. Обучение AI ────────────────────────
    print("\n[3/4] Training AI (reputation + frequency)...")
    ai.analyze_batch(suspicious)
    ai.save_all()

    s = ai.stats
    print(f"      Analyzed:    {s['analyzed']:,}")
    print(f"      Added:       {s['added']:,}")
    print(f"      Removed:     {s['removed']:,}")
    print(f"      Whitelisted: {s['whitelisted']:,}")
    print(f"      Custom:      {len(ai.get_custom_domains()):,}")

    # ── 4. Запись ─────────────────────────────
    ai_domains  = ai.get_custom_domains()
    all_domains = main_domains | ai_domains

    print(f"\n[4/4] Writing hosts file...")
    print(f"      From lists: {len(main_domains):,}")
    print(f"      AI learned: {len(ai_domains):,}")
    print(f"      Total:      {len(all_domains):,}")

    if write_hosts_file(all_domains, FILES["output"], FILES["backup"]):
        size_mb = FILES["output"].stat().st_size / 1024 / 1024
        print(f"\n✓ SUCCESS → {FILES['output']}  ({size_mb:.2f} MB, {len(all_domains):,} domains)")
        logger.info(f"Hosts file written: {len(all_domains)} domains, {size_mb:.2f} MB")
        return 0
    else:
        print("\n✗ ERROR: Failed to write hosts file")
        return 1


def main() -> int:
    return asyncio.run(async_main())


if __name__ == "__main__":
    sys.exit(main())
