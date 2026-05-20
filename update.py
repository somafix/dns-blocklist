#!/usr/bin/env python3
"""
DNS Blocklist Manager - Working Version v8.2.0
Исправлено обновление hosts.txt
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
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Set, Optional, Dict, List
from collections import defaultdict
import time

__version__ = "8.2.0-production"


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
    enable_cache: bool = False  # ОТКЛЮЧАЕМ КЭШ для принудительного обновления
    cache_ttl_hours: int = 0    # Нулевой TTL
    
    sources: List[Source] = field(default_factory=lambda: [
        Source(
            name="HaGeZi PRO",
            url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
            max_size_mb=50
        ),
    ])

def load_config() -> Config:
    """Загрузка конфигурации"""
    config = Config()
    with suppress(Exception):
        if os.getenv("BLOCKLIST_TIMEOUT"):
            config.timeout = int(os.getenv("BLOCKLIST_TIMEOUT"))
        if os.getenv("BLOCKLIST_PARALLEL"):
            config.parallel_downloads = int(os.getenv("BLOCKLIST_PARALLEL"))
        # Принудительное отключение кэша через переменную окружения
        if os.getenv("NO_CACHE", "1") == "1":
            config.enable_cache = False
    return config

CONFIG = load_config()


# ============================================================================
# ПУТИ К ФАЙЛАМ
# ============================================================================

class Paths:
    """Централизованное управление путями"""
    OUTPUT_HOSTS = Path("hosts.txt")  # ИСПРАВЛЕНО: правильное имя файла
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
# КЭШ (упрощённый)
# ============================================================================

class Cache:
    """Простой кэш с возможностью очистки"""
    
    def __init__(self, cache_file: Path, ttl_hours: int = 0):
        self.cache_file = cache_file
        self.ttl_hours = ttl_hours
    
    def clear(self):
        """Очистка кэша"""
        if self.cache_file.exists():
            self.cache_file.unlink()
    
    def get(self, key: str) -> Optional[Set[str]]:
        """Получение из кэша (только если TTL > 0)"""
        if self.ttl_hours <= 0:
            return None
        
        if not self.cache_file.exists():
            return None
        
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                timestamp = data.get('timestamp')
                if timestamp:
                    ts = datetime.fromisoformat(timestamp)
                    if datetime.now() - ts < timedelta(hours=self.ttl_hours):
                        return set(data.get('domains', []))
        except Exception:
            pass
        
        return None
    
    def set(self, key: str, domains: Set[str]):
        """Сохранение в кэш (только если TTL > 0)"""
        if self.ttl_hours <= 0:
            return
        
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'domains': list(domains)[:5_000_000]
            }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass


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
                self.logger.debug(f"Downloading {source.name}...")
                async with self.session.get(source.url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        domains = self._parse(text)
                        self.logger.info(f"  📥 {source.name}: {len(domains):,} domains")
                        return domains
                    else:
                        self.logger.warning(f"  {source.name}: HTTP {resp.status}")
            except asyncio.TimeoutError:
                self.logger.warning(f"  {source.name}: Timeout (attempt {attempt+1})")
            except Exception as e:
                self.logger.warning(f"  {source.name}: {str(e)[:50]}")
            
            if attempt < CONFIG.max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        
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
                self.logger.debug(f"Merged: {len(all_domains):,} total")
        
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
    
    async def build(self, force_refresh: bool = False) -> List[str]:
        """Сборка блоклиста"""
        self.logger.progress("Building blocklist...")
        
        # Очистка кэша если нужно принудительное обновление
        cache = Cache(Paths.CACHE_FILE, CONFIG.cache_ttl_hours)
        if force_refresh or not CONFIG.enable_cache:
            self.logger.info("🔄 Force refresh mode - ignoring cache")
            cache.clear()
        
        # Попытка загрузки из кэша
        all_domains = None
        if CONFIG.enable_cache and not force_refresh:
            all_domains = cache.get("combined")
            if all_domains:
                self.logger.info(f"📀 Cache hit: {len(all_domains):,} domains")
        
        # Загрузка из сети
        if all_domains is None:
            self.logger.progress("Downloading from sources...")
            async with Fetcher(self.logger) as fetcher:
                all_domains = await fetcher.fetch_all(CONFIG.sources)
            
            if not all_domains:
                self.logger.error("No domains downloaded")
                return []
            
            # Сохранение в кэш
            if CONFIG.enable_cache:
                cache.set("combined", all_domains)
                self.logger.info("💾 Saved to cache")
        
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
            
            # Прогресс (каждые 100k)
            if len(filtered) % 100000 == 0:
                self.logger.debug(f"Filtered: {len(filtered):,}/{len(all_domains):,}")
        
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
    def export(domains: List[str], output_path: Path) -> bool:
        """Экспорт в hosts файл"""
        try:
            # Принудительная перезапись
            with open(output_path, 'w', encoding='utf-8', buffering=8192) as f:
                # Заголовок
                f.write(f"# DNS Blocklist v{__version__}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"# Total: {len(domains):,} domains\n")
                f.write(f"# Format: 0.0.0.0 domain.com\n\n")
                
                # Запись доменов
                for i, domain in enumerate(domains):
                    f.write(f"0.0.0.0 {domain}\n")
                    
                    # Flush каждые 100k доменов
                    if i > 0 and i % 100000 == 0:
                        f.flush()
            
            # Проверка что файл создан
            if output_path.exists() and output_path.stat().st_size > 0:
                return True
            return False
            
        except Exception as e:
            print(f"Error writing hosts file: {e}")
            return False


# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

async def main() -> int:
    """Главная функция"""
    
    # Логгер
    logger = Logger(Paths.LOG_FILE, verbose=os.getenv("DEBUG", "0") == "1")
    
    # Приветствие
    print(f"\n{'='*60}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'='*60}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len([s for s in CONFIG.sources if s.enabled])}")
    print(f"💾 Cache: {'OFF' if not CONFIG.enable_cache else f'ON ({CONFIG.cache_ttl_hours}h)'}")
    print(f"📁 Output: {Paths.OUTPUT_HOSTS}")
    print(f"{'='*60}\n")
    
    try:
        # Инициализация
        manager = BlocklistManager(logger)
        
        # Бэкап старого файла
        if Paths.OUTPUT_HOSTS.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Paths.BACKUP_DIR / f"hosts_{timestamp}.txt"
            shutil.copy2(Paths.OUTPUT_HOSTS, backup_path)
            logger.info(f"💾 Backup created: {backup_path.name}")
        
        # Сборка блоклиста (force refresh = cache disabled)
        force_refresh = not CONFIG.enable_cache
        domains = await manager.build(force_refresh=force_refresh)
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Экспорт в hosts.txt
        logger.progress("Writing hosts.txt...")
        success = HostsExporter.export(domains, Paths.OUTPUT_HOSTS)
        
        if success:
            size_mb = Paths.OUTPUT_HOSTS.stat().st_size / 1024 / 1024
            logger.success(f"hosts.txt created: {size_mb:.2f} MB ({len(domains):,} domains)")
        else:
            logger.error("Failed to write hosts.txt")
            return 1
        
        # Статистика
        manager.save_stats()
        
        # Финальный вывод
        print(f"\n{'='*60}")
        print(f"✅ BUILD COMPLETED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"📊 Total blocked: {len(domains):,} domains")
        print(f"📁 Output file: {Paths.OUTPUT_HOSTS.absolute()}")
        print(f"📏 File size: {size_mb:.2f} MB")
        print(f"{'='*60}\n")
        
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