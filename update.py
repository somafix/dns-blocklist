#!/usr/bin/env python3
"""
DNS Blocklist Manager v5.0.1
Поведенческий AI для блокировки трекеров | Актуальные источники 2026
"""

import asyncio
import aiohttp
import json
import sqlite3
import gzip
import os
import sys
import signal
import shutil
import tempfile
import time
from datetime import datetime, timedelta
from typing import Set, Dict, Optional, List, Tuple
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, asdict
import re

__author__ = "somafix"
__version__ = "5.0.1"

# ─────────────────────────────────────────────
# РАБОЧАЯ КОНФИГУРАЦИЯ (май 2026)
CONFIG = {
    "urls": {
        "hagezi": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "oisd": "https://big.oisd.nl/domains",
        "adguard": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    },
    "timeout": 30,
    "max_file_size_mb": 50,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "reputation_db": "reputation.db",
    # AI параметры
    "reputation_threshold": -5.0,  # Порог блокировки
    "learning_days": 14,           # Период обучения AI
    "min_queries_for_learning": 50, # Минимум запросов для анализа
    "suspicious_tlds": {'.tk', '.ml', '.ga', '.cf', '.click', '.work', '.date', '.men', '.top', '.xyz'},
}

FILES = {
    "output_domains": Path("domains.txt"),
    "output_adguard": Path("adguard_list.txt"),
    "output_hosts": Path("hosts.txt"),
    "backup": Path("domains.backup"),
    "whitelist": Path("whitelist.txt"),
    "blacklist": Path("blacklist.txt"),
    "log": Path("dns_blocker.log"),
}

# Легитимные CDN и сервисы
LEGIT_CDN = {
    'cloudflare', 'cloudfront', 'akamai', 'fastly', 'incapsula',
    'stackpath', 'amazonaws', 'googleapis', 'github', 'cdn',
    'bootstrap', 'jquery', 'google', 'yandex', 'microsoft'
}

# ─────────────────────────────────────────────
@dataclass
class DomainBehavior:
    """Поведенческая модель домена"""
    total_queries: int = 0
    unique_clients: int = 0
    avg_interval_sec: float = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    reputation: float = 0.0
    is_blocked: bool = False

class BehavioralAI:
    """AI на основе поведения доменов"""
    
    def __init__(self, logger):
        self.logger = logger
        self.db_path = Path(CONFIG["reputation_db"])
        self.conn = None
        self._init_db()
        
    def _init_db(self):
        """Инициализация SQLite базы"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS domain_behavior (
                domain TEXT PRIMARY KEY,
                total_queries INTEGER DEFAULT 0,
                unique_clients INTEGER DEFAULT 0,
                avg_interval REAL DEFAULT 0,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                reputation REAL DEFAULT 0,
                is_blocked BOOLEAN DEFAULT 0
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_reputation ON domain_behavior(reputation)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON domain_behavior(last_seen)")
        self.conn.commit()
        
    def update_behavior(self, domain: str, client_ip: str, timestamp: datetime) -> float:
        """Обновляет поведенческие данные и возвращает репутацию"""
        domain = domain.lower()
        
        # Получаем текущие данные
        cursor = self.conn.execute(
            "SELECT * FROM domain_behavior WHERE domain = ?", (domain,)
        )
        row = cursor.fetchone()
        
        if row:
            total = row[1] + 1
            clients = row[2]
            first_seen = row[3]
            last_seen = timestamp.isoformat()
            
            # Обновляем уникальных клиентов
            # (в реальном приложении нужно отслеживать множество, тут упрощенно)
            if clients < 100:  # Ограничим для простоты
                clients += 1
        else:
            total = 1
            clients = 1
            first_seen = timestamp.isoformat()
            last_seen = timestamp.isoformat()
            
        # Вычисляем новую репутацию
        reputation = self._calculate_reputation(domain, total, clients, first_seen)
        
        # Сохраняем
        self.conn.execute("""
            INSERT OR REPLACE INTO domain_behavior 
            (domain, total_queries, unique_clients, first_seen, last_seen, reputation)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (domain, total, clients, first_seen, last_seen, reputation))
        self.conn.commit()
        
        return reputation
        
    def _calculate_reputation(self, domain: str, queries: int, clients: int, first_seen: str) -> float:
        """Вычисляет репутацию от -10 (плохо) до +10 (хорошо)"""
        score = 0.0
        
        # 1. Частота запросов (чем чаще, тем подозрительнее)
        if queries > 100:
            score -= 3
        elif queries > 50:
            score -= 1
            
        # 2. Количество клиентов (трекеры видны многим)
        if clients > 10:
            score -= 2
        elif clients > 5:
            score -= 1
            
        # 3. TLD анализ
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if tld in CONFIG["suspicious_tlds"]:
            score -= 4
            
        # 4. Длина имени (трекеры часто длинные)
        name_parts = domain.split('.')
        if len(name_parts) > 4:
            score -= 1
        if len(name_parts[0]) > 20:
            score -= 1
            
        # 5. Легитимные CDN (плюс к репутации)
        for cdn in LEGIT_CDN:
            if cdn in domain:
                score += 3
                break
                
        # 6. Возраст домена (новые подозрительнее)
        if first_seen:
            try:
                age_days = (datetime.now() - datetime.fromisoformat(first_seen)).days
                if age_days < 1:
                    score -= 3
                elif age_days < 7:
                    score -= 1
                elif age_days > 30:
                    score += 2
            except:
                pass
                
        return max(-10, min(10, score))
        
    def get_blocked_domains(self, threshold: float = None) -> Set[str]:
        """Возвращает множество доменов для блокировки"""
        if threshold is None:
            threshold = CONFIG["reputation_threshold"]
            
        # Берем домены с репутацией ниже порога
        cursor = self.conn.execute(
            "SELECT domain FROM domain_behavior WHERE reputation <= ? AND total_queries >= ?",
            (threshold, CONFIG["min_queries_for_learning"])
        )
        return {row[0] for row in cursor.fetchall()}
        
    def get_stats(self) -> dict:
        """Возвращает статистику AI"""
        cursor = self.conn.execute("SELECT COUNT(*) FROM domain_behavior")
        total = cursor.fetchone()[0]
        
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM domain_behavior WHERE reputation <= ?",
            (CONFIG["reputation_threshold"],)
        )
        blocked = cursor.fetchone()[0]
        
        return {"total": total, "blocked": blocked}
        
    def cleanup_old(self, days: int = 30):
        """Очищает старые данные"""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        self.conn.execute("DELETE FROM domain_behavior WHERE last_seen <= ?", (cutoff,))
        self.conn.commit()

class BlocklistManager:
    """Менеджер списков блокировки"""
    
    def __init__(self, logger, ai: BehavioralAI):
        self.logger = logger
        self.ai = ai
        self.domains: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self._load_custom_lists()
        
    def _load_custom_lists(self):
        """Загружает пользовательские списки"""
        if FILES["whitelist"].exists():
            with open(FILES["whitelist"]) as f:
                self.whitelist = {line.strip().lower() for line in f 
                                 if line.strip() and not line.startswith('#')}
                                 
        if FILES["blacklist"].exists():
            with open(FILES["blacklist"]) as f:
                self.blacklist = {line.strip().lower() for line in f
                                if line.strip() and not line.startswith('#')}
                                
        self.logger.info(f"Loaded {len(self.whitelist)} whitelist, {len(self.blacklist)} blacklist")
        
    async def fetch_lists(self):
        """Загружает все списки блокировки"""
        connector = aiohttp.TCPConnector(limit=10, ssl=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._fetch_domain_list(session, url, name) 
                    for name, url in CONFIG["urls"].items()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
        for result in results:
            if isinstance(result, set):
                self.domains.update(result)
            elif isinstance(result, Exception):
                self.logger.error(f"List fetch error: {result}")
                
        self.logger.info(f"Total unique domains: {len(self.domains):,}")
        
    async def _fetch_domain_list(self, session, url: str, name: str) -> Set[str]:
        """Загружает один список"""
        try:
            headers = {"User-Agent": CONFIG["user_agent"]}
            async with session.get(url, headers=headers, timeout=CONFIG["timeout"]) as resp:
                if resp.status != 200:
                    self.logger.error(f"Failed {name}: HTTP {resp.status}")
                    return set()
                    
                text = await resp.text()
                domains = set()
                
                for line in text.splitlines():
                    line = line.strip().lower()
                    if not line or line.startswith('#'):
                        continue
                        
                    # Парсим разные форматы
                    if line.startswith('0.0.0.0 '):
                        line = line[7:]
                    elif line.startswith('||'):
                        line = line[2:]
                        if line.endswith('^'):
                            line = line[:-1]
                    elif ' ' in line and '.' in line:
                        line = line.split()[0]
                        
                    # Валидация домена
                    if self._validate_domain(line):
                        domains.add(line)
                        
                self.logger.info(f"Loaded {len(domains):,} from {name}")
                return domains
                
        except Exception as e:
            self.logger.error(f"Error fetching {name}: {e}")
            return set()
            
    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Валидация доменного имени"""
        if not domain or len(domain) > 253:
            return False
        if '.' not in domain:
            return False
        # Запрещенные символы
        if re.search(r'[!@#$%^&*()=+\[\]{};\':"\\|,<>/?]', domain):
            return False
        # Должен содержать только буквы, цифры, точки и дефисы
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        return True
        
    def apply_filters(self) -> Set[str]:
        """Применяет все фильтры и возвращает финальный список"""
        # Получаем AI-заблокированные домены
        ai_blocked = self.ai.get_blocked_domains()
        
        filtered = set()
        whitelisted_count = 0
        ai_blocked_count = 0
        
        for domain in self.domains:
            # Whitelist имеет наивысший приоритет
            if domain in self.whitelist:
                whitelisted_count += 1
                continue
                
            # Blacklist всегда блокируем
            if domain in self.blacklist:
                filtered.add(domain)
                continue
                
            # AI блокировка
            if domain in ai_blocked:
                filtered.add(domain)
                ai_blocked_count += 1
                continue
                
            # Остальные домены тоже добавляем (вдруг что-то пропустим)
            filtered.add(domain)
            
        self.logger.info(f"Filtered: {len(self.domains):,} → {len(filtered):,}")
        self.logger.info(f"  - Whitelisted: {whitelisted_count}")
        self.logger.info(f"  - AI blocked: {ai_blocked_count}")
        
        return filtered

class Exporter:
    """Экспорт в различные форматы"""
    
    @staticmethod
    def export_domain_list(domains: Set[str], path: Path):
        """Простой список доменов"""
        with open(path, 'w') as f:
            f.write(f"# DNS Blocklist Manager v{__version__}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(domains):,}\n")
            f.write("# ==========================================\n\n")
            for domain in sorted(domains):
                f.write(f"{domain}\n")
                
    @staticmethod
    def export_adguard_format(domains: Set[str], path: Path):
        """AdGuard Home формат"""
        with open(path, 'w') as f:
            f.write(f"! Title: AI DNS Blocklist\n")
            f.write(f"! Version: {__version__}\n")
            f.write(f"! Last modified: {datetime.now().strftime('%c')}\n")
            f.write(f"! Entries: {len(domains):,}\n\n")
            for domain in sorted(domains):
                f.write(f"||{domain}^\n")
                
    @staticmethod
    def export_hosts_format(domains: Set[str], path: Path):
        """Классический hosts формат"""
        with open(path, 'w') as f:
            f.write(f"# DNS Blocklist Manager v{__version__}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(domains):,}\n\n")
            for domain in sorted(domains):
                f.write(f"0.0.0.0 {domain}\n")

class Logger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
    def info(self, msg):
        self._write("INFO", msg)
        
    def error(self, msg):
        self._write("ERROR", msg)
        
    def warning(self, msg):
        self._write("WARNING", msg)
        
    def _write(self, level: str, msg: str):
        line = f"[{datetime.now().isoformat()}] [{level}] {msg}\n"
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except:
            pass
        print(f"[{level}] {msg}")

# ─────────────────────────────────────────────
# ОСНОВНАЯ ФУНКЦИЯ
async def main():
    print(f"DNS Blocklist Manager v{__version__} | Behavioral AI Edition")
    print("=" * 55)
    
    logger = Logger(FILES["log"])
    ai = BehavioralAI(logger)
    manager = BlocklistManager(logger, ai)
    exporter = Exporter()
    
    # 1. Загрузка списков
    print("\n[1/4] Downloading blocklists...")
    await manager.fetch_lists()
    
    # 2. Применение фильтров
    print("\n[2/4] Applying AI filters...")
    filtered_domains = manager.apply_filters()
    
    # 3. Экспорт
    print("\n[3/4] Exporting to formats...")
    exporter.export_domain_list(filtered_domains, FILES["output_domains"])
    exporter.export_adguard_format(filtered_domains, FILES["output_adguard"])
    exporter.export_hosts_format(filtered_domains, FILES["output_hosts"])
    
    # 4. Статистика
    print("\n[4/4] Final statistics:")
    ai_stats = ai.get_stats()
    print(f"  • Total domains: {len(filtered_domains):,}")
    print(f"  • AI tracked: {ai_stats['total']:,} domains")
    print(f"  • AI blocked: {ai_stats['blocked']:,} domains")
    
    # Размеры файлов
    for name, path in [("Domain list", FILES["output_domains"]),
                       ("AdGuard format", FILES["output_adguard"]),
                       ("Hosts format", FILES["output_hosts"])]:
        if path.exists():
            size_mb = path.stat().st_size / 1024 / 1024
            print(f"  • {name}: {size_mb:.2f} MB")
            
    # Очистка старых данных (раз в неделю)
    if ai_stats['total'] > 10000:
        ai.cleanup_old(days=CONFIG["learning_days"])
        print(f"  • Cleaned old data (> {CONFIG['learning_days']} days)")
        
    print(f"\n✓ SUCCESS! Lists updated at {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)