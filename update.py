#!/usr/bin/env python3
"""
DNS Blocklist Manager - Production Ready v8.1.0
Полностью рабочий, безопасный и оптимизированный блоклист менеджер
"""

import asyncio
import aiohttp
import os
import sys
import shutil
import re
import logging
import logging.handlers
import atexit
import json
import signal
import hashlib
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Set, Optional, Dict, List, Iterable
from collections import defaultdict
import time

__version__ = "8.1.0-production"


# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

@dataclass
class Source:
    """Источник блоклиста"""
    name: str
    url: str
    enabled: bool = True
    max_size_mb: int = 100

@dataclass
class Config:
    """Конфигурация приложения"""
    timeout: int = 30
    max_retries: int = 3
    parallel_downloads: int = 3
    enable_cache: bool = True
    cache_ttl_hours: int = 24
    
    sources: List[Source] = field(default_factory=lambda: [
        Source(
            name="HaGeZi PRO",
            url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
            max_size_mb=50
        ),
        Source(
            name="oisd full",
            url="https://big.oisd.nl/domains",
            max_size_mb=30
        )
    ])

# Загрузка конфигурации из переменных окружения
def load_config() -> Config:
    """Загрузка конфигурации с валидацией"""
    config = Config()
    with suppress(Exception):
        if os.getenv("BLOCKLIST_TIMEOUT"):
            config.timeout = int(os.getenv("BLOCKLIST_TIMEOUT"))
        if os.getenv("BLOCKLIST_PARALLEL"):
            config.parallel_downloads = int(os.getenv("BLOCKLIST_PARALLEL"))
        if os.getenv("BLOCKLIST_CACHE") == "0":
            config.enable_cache = False
    return config

CONFIG = load_config()


# ============================================================================
# ПУТИ К ФАЙЛАМ
# ============================================================================

class Paths:
    """Централизованное управление путями"""
    OUTPUT = Path("blocklist.txt")
    BACKUP_DIR = Path("backup")
    WHITELIST = Path("whitelist.txt")
    BLACKLIST = Path("blacklist.txt")
    WILDCARD_WHITELIST = Path("wildcard_whitelist.txt")
    LOG_DIR = Path("logs")
    LOG_FILE = Path("logs/dns_blocker.log")
    CACHE_DIR = Path(".cache")
    CACHE_FILE = Path(".cache/domains.json")
    STATS_FILE = Path("stats.json")
    PID_FILE = Path("/tmp/dns_blocker.pid")

# Создание директорий
for dir_path in [Paths.BACKUP_DIR, Paths.LOG_DIR, Paths.CACHE_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


# ============================================================================
# ЛОГГЕР
# ============================================================================

class Logger:
    """Логгер с цветным выводом"""
    
    COLORS = {
        "INFO": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m", 
        "RESET": "\033[0m",
    }
    
    def __init__(self, log_file: Path, verbose: bool = False):
        self.logger = logging.getLogger("DNSBlocker")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()
        
        # Файловый логгер
        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(handler)
        
        # Консольный логгер
        console = logging.StreamHandler()
        console.setFormatter(self._ColorFormatter())
        self.logger.addHandler(console)
    
    class _ColorFormatter(logging.Formatter):
        def format(self, record):
            color = Logger.COLORS.get(record.levelname, Logger.COLORS["RESET"])
            record.levelname = f"{color}{record.levelname}{Logger.COLORS['RESET']}"
            return super().format(record)
    
    def info(self, msg: str): self.logger.info(f"ℹ️ {msg}")
    def warning(self, msg: str): self.logger.warning(f"⚠️ {msg}")
    def error(self, msg: str): self.logger.error(f"❌ {msg}")
    def success(self, msg: str): self.logger.info(f"✅ {msg}")
    def progress(self, msg: str): self.logger.info(f"📊 {msg}")
    def debug(self, msg: str): self.logger.debug(f"🐛 {msg}")


# ============================================================================
# ВАЛИДАТОР ДОМЕНОВ
# ============================================================================

class DomainValidator:
    """Валидация и очистка доменов"""
    
    @staticmethod
    def clean(line: str) -> Optional[str]:
        """Очистка строки и извлечение домена"""
        if not line or not isinstance(line, str):
            return None
        
        # Удаление комментариев
        if "#" in line:
            line = line[:line.index("#")]
        
        # Очистка
        line = line.strip().lower()
        if not line:
            return None
        
        # Удаление префиксов
        prefixes = ['https://', 'http://', '||', '0.0.0.0 ', '127.0.0.1 ']
        for prefix in prefixes:
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        
        # Удаление суффиксов
        line = line.rstrip('/^')
        
        # Проверка на IP адреса
        if re.match(r'^\d+(\.\d+){3}$', line) or re.match(r'^[0-9a-f:]+$', line):
            return None
        
        # Базовая валидация
        if len(line) > 253:
            return None
        if line.startswith('.') or line.endswith('.'):
            return None
        if '..' in line:
            return None
        if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', line):
            return None
        
        return line
    
    @staticmethod
    def match_wildcard(domain: str, patterns: Set[str]) -> bool:
        """Проверка wildcard паттернов"""
        for pattern in patterns:
            if pattern.endswith('*'):
                if domain.startswith(pattern[:-1]):
                    return True
            elif pattern.startswith('*'):
                if domain.endswith(pattern[1:]):
                    return True
            elif domain == pattern:
                return True
        return False


# ============================================================================
# КЭШ
# ============================================================================

class Cache:
    """Кэш с TTL"""
    
    def __init__(self, cache_file: Path, ttl_hours: int = 24):
        self.cache_file = cache_file
        self.ttl = timedelta(hours=ttl_hours)
        self.data: Dict[str, List[str]] = {}
        self._load()
    
    def _load(self):
        """Загрузка кэша"""
        if not self.cache_file.exists():
            return
        
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    return
                
                timestamp = data.get('timestamp')
                if timestamp:
                    ts = datetime.fromisoformat(timestamp)
                    if datetime.now() - ts < self.ttl:
                        self.data = data.get('domains', {})
        except Exception:
            pass
    
    def save(self):
        """Сохранение кэша"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'domains': self.data
            }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def get(self, key: str) -> Optional[Set[str]]:
        """Получение из кэша"""
        if key in self.data:
            return set(self.data[key])
        return None
    
    def set(self, key: str, domains: Set[str]):
        """Сохранение в кэш"""
        self.data[key] = list(domains)[:5_000_000]  # Лимит 5M доменов


# ============================================================================
# ЗАГРУЗЧИК
# ============================================================================

class Fetcher:
    """Асинхронный загрузчик"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=CONFIG.timeout)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": f"DNS-Blocklist-Manager/{__version__}"}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch(self, source: Source) -> Optional[Set[str]]:
        """Загрузка одного источника"""
        for attempt in range(CONFIG.max_retries):
            try:
                async with self.session.get(source.url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        domains = self._parse(text)
                        self.logger.info(f"  📥 {source.name}: {len(domains):,} domains")
                        return domains
                    elif resp.status == 404:
                        self.logger.error(f"  {source.name}: Not found (404)")
                        return None
                    else:
                        self.logger.warning(f"  {source.name}: HTTP {resp.status}")
            except asyncio.TimeoutError:
                self.logger.warning(f"  {source.name}: Timeout (attempt {attempt+1})")
            except Exception as e:
                self.logger.warning(f"  {source.name}: {str(e)[:50]}")
            
            if attempt < CONFIG.max_retries - 1:
                await asyncio.sleep(CONFIG.max_retries * 2)
        
        return None
    
    def _parse(self, content: str) -> Set[str]:
        """Парсинг доменов"""
        domains = set()
        for line in content.splitlines():
            domain = DomainValidator.clean(line)
            if domain:
                domains.add(domain)
        return domains
    
    async def fetch_all(self, sources: List[Source]) -> Set[str]:
        """Параллельная загрузка всех источников"""
        semaphore = asyncio.Semaphore(CONFIG.parallel_downloads)
        
        async def fetch_one(source: Source):
            async with semaphore:
                return await self.fetch(source)
        
        tasks = [fetch_one(s) for s in sources if s.enabled]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_domains = set()
        for result in results:
            if isinstance(result, set):
                all_domains.update(result)
        
        return all_domains


# ============================================================================
# МЕНЕДЖЕР БЛОКЛИСТА
# ============================================================================

class BlocklistManager:
    """Управление блоклистом"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.stats = defaultdict(int)
        
        # Загрузка пользовательских списков
        self.whitelist = self._load_list(Paths.WHITELIST)
        self.blacklist = self._load_list(Paths.BLACKLIST)
        self.wildcard_whitelist = self._load_list(Paths.WILDCARD_WHITELIST)
        
        self.logger.info(f"📋 Whitelist: {len(self.whitelist)}")
        self.logger.info(f"📋 Blacklist: {len(self.blacklist)}")
        self.logger.info(f"📋 Wildcard: {len(self.wildcard_whitelist)}")
    
    def _load_list(self, path: Path) -> Set[str]:
        """Загрузка списка из файла"""
        domains = set()
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        domains.add(domain)
        return domains
    
    async def build(self, use_cache: bool = True) -> List[str]:
        """Сборка блоклиста"""
        self.logger.progress("Building blocklist...")
        
        # Попытка загрузки из кэша
        all_domains = None
        if use_cache:
            cache = Cache(Paths.CACHE_FILE, CONFIG.cache_ttl_hours)
            all_domains = cache.get("combined")
            if all_domains:
                self.logger.info(f"📀 Cache: {len(all_domains):,} domains")
        
        # Загрузка из сети
        if not all_domains:
            async with Fetcher(self.logger) as fetcher:
                all_domains = await fetcher.fetch_all(CONFIG.sources)
            
            if not all_domains:
                self.logger.error("No domains downloaded")
                return []
            
            # Сохранение в кэш
            if use_cache:
                cache = Cache(Paths.CACHE_FILE, CONFIG.cache_ttl_hours)
                cache.set("combined", all_domains)
                cache.save()
        
        self.stats['total'] = len(all_domains)
        self.logger.info(f"📊 Total unique: {len(all_domains):,}")
        
        # Фильтрация
        self.logger.progress("Filtering domains...")
        filtered = []
        
        for domain in all_domains:
            # Проверка wildcard
            if DomainValidator.match_wildcard(domain, self.wildcard_whitelist):
                self.stats['wildcard_filtered'] += 1
                continue
            
            # Проверка whitelist
            if domain in self.whitelist:
                self.stats['whitelisted'] += 1
                continue
            
            # Проверка blacklist
            if domain in self.blacklist:
                self.stats['blacklisted'] += 1
            
            filtered.append(domain)
        
        self.stats['output'] = len(filtered)
        self._print_stats()
        
        return filtered
    
    def _print_stats(self):
        """Вывод статистики"""
        total = self.stats['total']
        output = self.stats['output']
        
        self.logger.info("📈 Statistics:")
        self.logger.info(f"   ├─ Input: {total:,}")
        self.logger.info(f"   ├─ Output: {output:,}")
        self.logger.info(f"   ├─ Filtered: {total - output:,}")
        
        if total > 0:
            reduction = (1 - output/total) * 100
            self.logger.info(f"   └─ Reduction: {reduction:.1f}%")
    
    def save_stats(self):
        """Сохранение статистики"""
        try:
            stats = {
                'timestamp': datetime.now().isoformat(),
                'version': __version__,
                'stats': dict(self.stats),
                'config': {
                    'timeout': CONFIG.timeout,
                    'parallel': CONFIG.parallel_downloads,
                    'sources': len(CONFIG.sources)
                }
            }
            with open(Paths.STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Stats save failed: {e}")


# ============================================================================
# ЭКСПОРТЕРЫ
# ============================================================================

class HostsExporter:
    """Экспорт в формат hosts"""
    
    @staticmethod
    def export(domains: List[str], output_path: Path) -> None:
        """Экспорт в hosts файл"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# DNS Blocklist v{__version__}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"# Total: {len(domains):,} domains\n\n")
            
            for domain in domains:
                f.write(f"0.0.0.0 {domain}\n")

class DomainsExporter:
    """Экспорт в plain domains формат"""
    
    @staticmethod
    def export(domains: List[str], output_path: Path) -> None:
        """Экспорт в список доменов"""
        with open(output_path, 'w', encoding='utf-8') as f:
            for domain in domains:
                f.write(f"{domain}\n")


# ============================================================================
# PID МЕНЕДЖЕР
# ============================================================================

class PIDManager:
    """Управление PID файлом"""
    
    def __init__(self, pid_file: Path):
        self.pid_file = pid_file
        self.pid = os.getpid()
    
    def acquire(self) -> bool:
        """Захват блокировки"""
        if self.pid_file.exists():
            try:
                old_pid = int(self.pid_file.read_text().strip())
                os.kill(old_pid, 0)
                print(f"❌ Process already running (PID: {old_pid})")
                return False
            except (OSError, ValueError):
                self.pid_file.unlink()
        
        self.pid_file.write_text(str(self.pid))
        return True
    
    def release(self):
        """Освобождение блокировки"""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
        except Exception:
            pass


# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

async def main() -> int:
    """Главная функция"""
    
    # PID проверка
    pid_manager = PIDManager(Paths.PID_FILE)
    if not pid_manager.acquire():
        return 1
    atexit.register(pid_manager.release)
    
    # Логгер
    logger = Logger(Paths.LOG_FILE, verbose=os.getenv("DEBUG", "0") == "1")
    
    # Приветствие
    print(f"\n{'='*50}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'='*50}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len([s for s in CONFIG.sources if s.enabled])}")
    print(f"{'='*50}\n")
    
    try:
        # Инициализация
        manager = BlocklistManager(logger)
        
        # Бэкап
        logger.progress("Creating backup...")
        if Paths.OUTPUT.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Paths.BACKUP_DIR / f"blocklist_{timestamp}.txt"
            shutil.copy2(Paths.OUTPUT, backup_path)
            logger.info(f"Backup: {backup_path.name}")
        
        # Сборка блоклиста
        domains = await manager.build(use_cache=CONFIG.enable_cache)
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Экспорт
        logger.progress("Exporting...")
        
        # Hosts формат
        HostsExporter.export(domains, Paths.OUTPUT)
        size_mb = Paths.OUTPUT.stat().st_size / 1024 / 1024
        logger.info(f"  • hosts: {size_mb:.2f} MB")
        
        # Domains формат
        domains_path = Paths.OUTPUT.parent / "domains.txt"
        DomainsExporter.export(domains, domains_path)
        size_mb = domains_path.stat().st_size / 1024 / 1024
        logger.info(f"  • domains: {size_mb:.2f} MB")
        
        # Статистика
        manager.save_stats()
        
        # Финальный вывод
        print(f"\n{'='*50}")
        print(f"✅ BUILD COMPLETED")
        print(f"{'='*50}")
        print(f"📊 Blocked domains: {len(domains):,}")
        print(f"💾 Memory: ~{len(domains) * 40 / 1024 / 1024:.1f} MB")
        print(f"📁 Output: {Paths.OUTPUT}")
        print(f"{'='*50}\n")
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if os.getenv("DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

def cli():
    """CLI точка входа"""
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    cli()