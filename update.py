#!/usr/bin/env python3
"""
DNS Blocklist Manager v5.0.0
Многоуровневая система блокировки трекеров с поведенческим AI.
"""

import asyncio
import aiohttp
import hashlib
import json
import gzip
import os
import sys
import signal
import shutil
import tempfile
import time
import fcntl
from datetime import datetime, timedelta
from typing import Set, Dict, Optional, List, Tuple
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import sqlite3

__author__ = "somafix"
__version__ = "5.0.0"

# ─────────────────────────────────────────────
# СОВРЕМЕННАЯ КОНФИГУРАЦИЯ
CONFIG = {
    # Только актуальные источники (май 2026)
    "urls": {
        "primary": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "secondary": "https://blocks.1hosts.com/lite/domains.txt",
        "trackers": "https://raw.githubusercontent.com/Perflyst/Pi-hole-ADBLOCK/master/src/trackers",
    },
    "adguard_api": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "timeout": 30,
    "max_file_size_mb": 50,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "reputation_db": "reputation.db",
    # AI параметры
    "behavior_window_minutes": 60,
    "min_requests_for_block": 100,
    "suspicious_tlds": {'.tk', '.ml', '.ga', '.cf', '.click', '.work', '.date', '.men'},
    "block_threshold": 0.7,  # 70% запросов к новым доменам = трекер
    "safelist_threshold": 0.95,  # 95% к известным = легитимный
}

FILES = {
    "output_domains": Path("domains.txt"),
    "output_adguard": Path("adguard_list.txt"),
    "backup": Path("domains.backup"),
    "ai_db": Path("ai_trackers.json"),
    "whitelist": Path("whitelist.txt"),
    "blacklist": Path("blacklist.txt"),
    "log": Path("dns_blocker.log"),
    "pid_file": Path("/tmp/dns_blocker.pid"),
}

# Современные сигнатуры
LEGIT_TLDS = {'.com', '.org', '.net', '.io', '.app', '.dev', '.cloud', '.ai'}
KNOWN_CDN = {
    'cloudflare', 'cloudfront', 'akamai', 'fastly', 'incapsula',
    'stackpath', 'aws', 'google', 'azure', 'digitalocean'
}

# ─────────────────────────────────────────────
@dataclass
class DomainBehavior:
    """Поведенческая модель домена"""
    total_queries: int = 0
    unique_client_ips: Set[str] = None
    avg_interval_sec: float = 0
    first_seen: datetime = None
    last_seen: datetime = None
    cname_chain: List[str] = None
    parent_domain: str = ""
    
    def __post_init__(self):
        if self.unique_client_ips is None:
            self.unique_client_ips = set()
        if self.cname_chain is None:
            self.cname_chain = []

class BehavioralAI:
    """AI на основе поведения, а не названий"""
    
    def __init__(self, logger):
        self.logger = logger
        self.db_path = Path(CONFIG["reputation_db"])
        self._init_db()
        self.behaviors: Dict[str, DomainBehavior] = {}
        self.session_stats = {"total_domains": 0, "blocked": 0, "analyzed": 0}
        
    def _init_db(self):
        """SQLite для хранения поведенческих данных"""
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
                is_blocked BOOLEAN DEFAULT 0,
                cname_chain TEXT,
                parent_domain TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_reputation 
            ON domain_behavior(reputation DESC)
        """)
        self.conn.commit()
        
    def analyze_behavior(self, domain: str, client_ip: str, timestamp: datetime) -> float:
        """Анализирует поведение и возвращает репутацию"""
        behavior = self._get_or_create_behavior(domain)
        
        # Обновляем статистику
        behavior.total_queries += 1
        behavior.unique_client_ips.add(client_ip)
        behavior.last_seen = timestamp
        
        if not behavior.first_seen:
            behavior.first_seen = timestamp
            
        # Рассчитываем интервалы (трекеры часто стучатся регулярно)
        if behavior.total_queries > 1:
            time_diff = (behavior.last_seen - behavior.first_seen).total_seconds()
            behavior.avg_interval_sec = time_diff / behavior.total_queries
            
        # Вычисляем репутацию
        reputation = self._calculate_reputation(behavior, domain)
        
        # Сохраняем
        self._save_behavior(domain, behavior, reputation)
        
        return reputation
        
    def _calculate_reputation(self, behavior: DomainBehavior, domain: str) -> float:
        """Калькулятор репутации от -10 (плохо) до +10 (хорошо)"""
        score = 0.0
        
        # 1. Частота запросов (трекеры часто стучатся)
        if behavior.avg_interval_sec > 0:
            freq_per_hour = 3600 / behavior.avg_interval_sec
            if freq_per_hour > 60:  # >1 запроса в минуту
                score -= 3
            elif freq_per_hour > 10:  # 10-60 в час
                score -= 1
                
        # 2. Количество уникальных клиентов (трекеры от многих)
        unique_clients = len(behavior.unique_client_ips)
        if unique_clients > 10:
            score -= 2
        elif unique_clients == 1:
            score += 1  # Легитимный сервис, скорее всего
            
        # 3. Структура домена
        parts = domain.split('.')
        tld = '.' + parts[-1] if len(parts) > 0 else ''
        
        # Подозрительные TLD
        if tld in CONFIG["suspicious_tlds"]:
            score -= 4
            
        # Слишком длинное имя
        if len(parts[0]) > 30:
            score -= 2
            
        # 4. Цепочка CNAME (трекеры часто маскируются)
        if behavior.cname_chain:
            # Если CNAME ведет на CDN - скорее легитимно
            for cname in behavior.cname_chain:
                if any(cdn in cname for cdn in KNOWN_CDN):
                    score += 2
                    break
            # Длинная цепочка (>3) - подозрительно
            if len(behavior.cname_chain) > 3:
                score -= 3
                
        # 5. Время жизни (новые домены подозрительны)
        if behavior.first_seen:
            age_hours = (datetime.now() - behavior.first_seen).total_seconds() / 3600
            if age_hours < 24:
                score -= 2
            elif age_hours > 720:  # >30 дней
                score += 1
                
        # Возраст последнего запроса
        if behavior.last_seen:
            idle_hours = (datetime.now() - behavior.last_seen).total_seconds() / 3600
            if idle_hours > 48 and behavior.total_queries < 100:
                score += 1  # Возможно, разовый запрос
                
        return max(-10, min(10, score))
        
    def _get_or_create_behavior(self, domain: str) -> DomainBehavior:
        if domain not in self.behaviors:
            # Пробуем загрузить из БД
            cursor = self.conn.execute(
                "SELECT * FROM domain_behavior WHERE domain = ?", 
                (domain,)
            )
            row = cursor.fetchone()
            if row:
                behavior = DomainBehavior(
                    total_queries=row[1],
                    unique_client_ips=set(),  # Десериализуем отдельно
                    avg_interval=row[3],
                    first_seen=datetime.fromisoformat(row[4]) if row[4] else None,
                    last_seen=datetime.fromisoformat(row[5]) if row[5] else None,
                    cname_chain=json.loads(row[8]) if row[8] else [],
                    parent_domain=row[9] or ""
                )
                self.behaviors[domain] = behavior
            else:
                self.behaviors[domain] = DomainBehavior()
                self.session_stats["total_domains"] += 1
                
        return self.behaviors[domain]
        
    def _save_behavior(self, domain: str, behavior: DomainBehavior, reputation: float):
        self.conn.execute("""
            INSERT OR REPLACE INTO domain_behavior 
            (domain, total_queries, unique_clients, avg_interval, 
             first_seen, last_seen, reputation, cname_chain, parent_domain)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            behavior.total_queries,
            len(behavior.unique_client_ips),
            behavior.avg_interval_sec,
            behavior.first_seen.isoformat() if behavior.first_seen else None,
            behavior.last_seen.isoformat() if behavior.last_seen else None,
            reputation,
            json.dumps(behavior.cname_chain),
            behavior.parent_domain
        ))
        self.conn.commit()
        
    def get_blocked_domains(self, threshold: float = -5.0) -> Set[str]:
        """Возвращает домены с репутацией ниже порога"""
        cursor = self.conn.execute(
            "SELECT domain FROM domain_behavior WHERE reputation <= ?",
            (threshold,)
        )
        return {row[0] for row in cursor.fetchall()}
        
    def cleanup_old(self, days: int = 30):
        """Удаляет старые данные"""
        cutoff = datetime.now() - timedelta(days=days)
        self.conn.execute(
            "DELETE FROM domain_behavior WHERE last_seen <= ?",
            (cutoff.isoformat(),)
        )
        self.conn.commit()

class ModernBlocklistManager:
    """Современный менеджер списков блокировки"""
    
    def __init__(self, logger, ai):
        self.logger = logger
        self.ai = ai
        self.domains: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self._load_lists()
        
    def _load_lists(self):
        """Загружает whitelist/blacklist"""
        # Whitelist
        if FILES["whitelist"].exists():
            with open(FILES["whitelist"]) as f:
                self.whitelist = {line.strip().lower() for line in f 
                                 if line.strip() and not line.startswith('#')}
                                 
        # Blacklist  
        if FILES["blacklist"].exists():
            with open(FILES["blacklist"]) as f:
                self.blacklist = {line.strip().lower() for line in f
                                if line.strip() and not line.startswith('#')}
                                
        self.logger.info(f"Loaded {len(self.whitelist)} whitelist, {len(self.blacklist)} blacklist")
        
    async def fetch_modern_lists(self):
        """Загрузка современных списков блокировки"""
        connector = aiohttp.TCPConnector(limit=20, ssl=True)  # ssl включен!
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for name, url in CONFIG["urls"].items():
                tasks.append(self._fetch_list(session, url, name))
                
            # AdGuard filter
            tasks.append(self._fetch_adguard_filter(session))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
        for result in results:
            if isinstance(result, set):
                self.domains.update(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Error fetching list: {result}")
                
        self.logger.info(f"Total unique domains: {len(self.domains):,}")
        
    async def _fetch_list(self, session, url: str, name: str) -> Set[str]:
        """Загрузка списка доменов"""
        try:
            headers = {"User-Agent": CONFIG["user_agent"]}
            async with session.get(url, headers=headers, timeout=CONFIG["timeout"]) as resp:
                resp.raise_for_status()
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
                    elif ' ' in line:
                        line = line.split()[0]
                        
                    # Валидация
                    if self._validate_domain(line):
                        domains.add(line)
                        
                self.logger.info(f"Loaded {len(domains):,} from {name}")
                return domains
                
        except Exception as e:
            self.logger.error(f"Failed to fetch {name}: {e}")
            return set()
            
    async def _fetch_adguard_filter(self, session) -> Set[str]:
        """Специальный парсер для AdGuard фильтров"""
        url = CONFIG["adguard_api"]
        try:
            async with session.get(url, headers={"User-Agent": CONFIG["user_agent"]}) as resp:
                text = await resp.text()
                domains = set()
                
                for line in text.splitlines():
                    # AdGuard format: ||example.org^
                    if line.startswith('||') and '^' in line:
                        domain = line[2:line.index('^')]
                        if self._validate_domain(domain):
                            domains.add(domain)
                            
                self.logger.info(f"Loaded {len(domains):,} from AdGuard")
                return domains
                
        except Exception as e:
            self.logger.error(f"Failed to fetch AdGuard filter: {e}")
            return set()
            
    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Валидация домена"""
        if not domain or len(domain) > 253:
            return False
        # Минимум 2 сегмента
        if '.' not in domain:
            return False
        # Нет спецсимволов
        if any(c in domain for c in '!@#$%^&*()=+[]{};:\'"\\|<>?,'):
            return False
        return True
        
    def apply_filters(self) -> Set[str]:
        """Применяет whitelist/blacklist и AI рекомендации"""
        filtered = set()
        
        for domain in self.domains:
            # Whitelist имеет приоритет
            if domain in self.whitelist:
                continue
                
            # Blacklist всегда блокируем
            if domain in self.blacklist:
                filtered.add(domain)
                continue
                
            # AI анализ (если есть данные)
            ai_reputation = self._get_ai_reputation(domain)
            if ai_reputation is not None:
                if ai_reputation <= -5.0:  # Плохая репутация
                    filtered.add(domain)
                    self.ai.session_stats["blocked"] += 1
                elif ai_reputation >= 5.0:  # Хорошая репутация
                    continue  # Пропускаем
                else:
                    # Серая зона - включаем как есть
                    filtered.add(domain)
            else:
                # Нет данных AI - включаем
                filtered.add(domain)
                
        self.logger.info(f"Filtered: {len(self.domains):,} → {len(filtered):,} domains")
        return filtered
        
    def _get_ai_reputation(self, domain: str) -> Optional[float]:
        """Получает репутацию от AI"""
        cursor = self.ai.conn.execute(
            "SELECT reputation FROM domain_behavior WHERE domain = ?",
            (domain,)
        )
        row = cursor.fetchone()
        return row[0] if row else None

class MultiFormatExporter:
    """Экспорт в разные форматы"""
    
    @staticmethod
    def export_domain_list(domains: Set[str], output_path: Path):
        """Простой список доменов"""
        with open(output_path, 'w') as f:
            f.write(f"# DNS Blocklist Manager v{__version__}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(domains):,}\n")
            f.write("# ==========================================\n\n")
            
            for domain in sorted(domains):
                f.write(f"{domain}\n")
                
    @staticmethod
    def export_adguard_format(domains: Set[str], output_path: Path):
        """AdGuard Home совместимый формат"""
        with open(output_path, 'w') as f:
            f.write(f"! Title: AI DNS Blocklist\n")
            f.write(f"! Version: {__version__}\n")
            f.write(f"! Last modified: {datetime.now().strftime('%c')}\n")
            f.write(f"! Number of entries: {len(domains):,}\n")
            f.write(f"! --------------------------------\n\n")
            
            for domain in sorted(domains):
                # AdGuard format: ||domain^
                f.write(f"||{domain}^\n")
                
    @staticmethod
    def export_hosts_format(domains: Set[str], output_path: Path):
        """Классический hosts формат (для совместимости)"""
        with open(output_path, 'w') as f:
            f.write(f"# DNS Blocklist Manager v{__version__} (Legacy format)\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(domains):,}\n")
            f.write("# ==========================================\n\n")
            
            for domain in sorted(domains):
                f.write(f"0.0.0.0 {domain}\n")

async def main():
    """Основная функция"""
    print(f"DNS Blocklist Manager v{__version__} | Behavioral AI Edition")
    print("="*60)
    
    # Инициализация
    logger = Logger(FILES["log"])
    ai = BehavioralAI(logger)
    manager = ModernBlocklistManager(logger, ai)
    exporter = MultiFormatExporter()
    
    print("\n[1/4] Downloading modern blocklists...")
    await manager.fetch_modern_lists()
    
    print("\n[2/4] Applying AI filters...")
    filtered_domains = manager.apply_filters()
    
    print("\n[3/4] Exporting to formats...")
    exporter.export_domain_list(filtered_domains, FILES["output_domains"])
    exporter.export_adguard_format(filtered_domains, FILES["output_adguard"])
    exporter.export_hosts_format(filtered_domains, FILES["output_domains"].with_suffix(".hosts"))
    
    # Статистика
    print("\n[4/4] Final statistics:")
    print(f"  • Total domains: {len(filtered_domains):,}")
    print(f"  • AI blocked: {ai.session_stats['blocked']:,}")
    print(f"  • DB size: {len(ai.behaviors):,} domains tracked")
    
    # Размеры файлов
    for fmt, file in [("Domain list", FILES["output_domains"]),
                      ("AdGuard format", FILES["output_adguard"])]:
        if file.exists():
            size_mb = file.stat().st_size / 1024 / 1024
            print(f"  • {fmt}: {size_mb:.2f} MB")
            
    print(f"\n✓ SUCCESS! Lists updated at {datetime.now().strftime('%H:%M:%S')}")
    
    # Очистка старых данных
    if len(ai.behaviors) > 10000:
        ai.cleanup_old(days=30)
        print("  • Cleaned old behavioral data")

class Logger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
    def info(self, msg):    self._write("INFO", msg)
    def error(self, msg):   self._write("ERROR", msg)
    def warning(self, msg): self._write("WARNING", msg)
    
    def _write(self, level: str, message: str):
        line = f"[{datetime.now().isoformat()}] [{level}] {message}\n"
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(line)
        except Exception:
            pass
        print(f"[{level}] {message}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)