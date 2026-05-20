#!/usr/bin/env python3
"""
DNS Blocklist Manager - Production Ready v11.0.0
Профессиональный инструмент для создания DNS блоклистов
"""

import asyncio
import json
import logging
import logging.handlers
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple

try:
    import aiohttp
except ImportError:
    print("❌ Ошибка: Установите aiohttp: pip install aiohttp")
    sys.exit(1)

__version__ = "11.0.0"


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================

class Config:
    """Централизованная конфигурация приложения"""
    TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    PARALLEL_DOWNLOADS: int = 2
    USER_AGENT: str = f"DNS-Blocklist-Manager/{__version__}"
    
    # Источники данных
    SOURCES: List[Dict[str, str]] = [
        {
            "name": "HaGeZi PRO",
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        }
    ]
    
    # Пути к файлам
    HOSTS_OUTPUT: Path = Path("hosts.txt")
    BACKUP_DIR: Path = Path("backup")
    WHITELIST_FILE: Path = Path("whitelist.txt")
    BLACKLIST_FILE: Path = Path("blacklist.txt")
    WILDCARD_WHITELIST_FILE: Path = Path("wildcard_whitelist.txt")
    LOG_FILE: Path = Path("logs/dns_blocker.log")
    STATS_FILE: Path = Path("stats.json")
    
    @classmethod
    def init_directories(cls) -> None:
        """Создание необходимых директорий"""
        cls.BACKUP_DIR.mkdir(exist_ok=True)
        cls.LOG_FILE.parent.mkdir(exist_ok=True)


# ============================================================================
# ЛОГГЕР
# ============================================================================

class Logger:
    """Профессиональный логгер с ротацией файлов"""
    
    def __init__(self, log_file: Path, verbose: bool = False):
        self.logger = logging.getLogger("DNSBlocker")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()
        
        # Файловый обработчик с ротацией
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(file_handler)
        
        # Консольный обработчик
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(console_handler)
    
    def _log(self, level: str, msg: str, emoji: str = "") -> None:
        """Базовый метод логирования"""
        getattr(self.logger, level)(f"{emoji} {msg}" if emoji else msg)
    
    def info(self, msg: str) -> None: self._log("info", msg, "ℹ️")
    def warning(self, msg: str) -> None: self._log("warning", msg, "⚠️")
    def error(self, msg: str) -> None: self._log("error", msg, "❌")
    def success(self, msg: str) -> None: self._log("info", msg, "✅")
    def progress(self, msg: str) -> None: self._log("info", msg, "📊")
    def debug(self, msg: str) -> None: self._log("debug", msg, "🐛")


# ============================================================================
# ВАЛИДАТОР ДОМЕНОВ
# ============================================================================

class DomainValidator:
    """Валидация и нормализация доменных имён"""
    
    # Регулярные выражения скомпилированы для производительности
    _IP_PATTERN = re.compile(r'^\d+(\.\d+){3}$')
    _DOMAIN_PATTERN = re.compile(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$')
    _PREFIXES = ('https://', 'http://', '||', '0.0.0.0 ', '127.0.0.1 ')
    
    @classmethod
    def clean(cls, line: str) -> Optional[str]:
        """Очистка и валидация строки домена"""
        if not line or not isinstance(line, str):
            return None
        
        # Удаление комментариев
        if '#' in line:
            line = line[:line.index('#')]
        
        # Нормализация
        line = line.strip().lower()
        if not line:
            return None
        
        # Удаление префиксов
        for prefix in cls._PREFIXES:
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        
        # Удаление суффиксов
        line = line.rstrip('/^')
        
        # Проверка на IP-адрес
        if cls._IP_PATTERN.match(line):
            return None
        
        # Валидация домена
        if len(line) < 3 or len(line) > 253:
            return None
        if line[0] == '.' or line[-1] == '.' or '..' in line:
            return None
        if not cls._DOMAIN_PATTERN.match(line):
            return None
        
        return line
    
    @staticmethod
    def match_wildcard(domain: str, patterns: Set[str]) -> bool:
        """Проверка соответствия wildcard паттернам"""
        for pattern in patterns:
            if pattern.endswith('*') and domain.startswith(pattern[:-1]):
                return True
            if pattern.startswith('*') and domain.endswith(pattern[1:]):
                return True
            if domain == pattern:
                return True
        return False


# ============================================================================
# ЗАГРУЗЧИК ДАННЫХ
# ============================================================================

class DataFetcher:
    """Асинхронный загрузчик данных с обработкой ошибок"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": Config.USER_AGENT}
        )
        return self
    
    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()
    
    async def fetch_source(self, name: str, url: str) -> Set[str]:
        """Загрузка одного источника данных"""
        if not self._session:
            raise RuntimeError("Session not initialized")
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                async with self._session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        domains = self._parse_content(content)
                        self.logger.info(f"  📥 {name}: {len(domains):,} domains")
                        return domains
                    else:
                        self.logger.warning(f"  {name}: HTTP {response.status}")
            except asyncio.TimeoutError:
                self.logger.warning(f"  {name}: Timeout ({attempt + 1}/{Config.MAX_RETRIES})")
            except aiohttp.ClientError as e:
                self.logger.warning(f"  {name}: Network error - {str(e)[:50]}")
            except Exception as e:
                self.logger.warning(f"  {name}: Unexpected error - {str(e)[:50]}")
            
            if attempt < Config.MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)
        
        return set()
    
    @staticmethod
    def _parse_content(content: str) -> Set[str]:
        """Парсинг доменов из контента"""
        domains = set()
        for line in content.splitlines():
            domain = DomainValidator.clean(line)
            if domain:
                domains.add(domain)
        return domains
    
    async def fetch_all(self) -> Set[str]:
        """Параллельная загрузка всех источников"""
        semaphore = asyncio.Semaphore(Config.PARALLEL_DOWNLOADS)
        
        async def fetch_one(source: Dict[str, str]) -> Set[str]:
            async with semaphore:
                return await self.fetch_source(source["name"], source["url"])
        
        results = await asyncio.gather(*[fetch_one(src) for src in Config.SOURCES])
        
        # Объединение результатов
        all_domains = set()
        for domains in results:
            all_domains.update(domains)
        
        return all_domains


# ============================================================================
# МЕНЕДЖЕР БЛОКЛИСТА
# ============================================================================

class BlocklistBuilder:
    """Построитель блоклиста с фильтрацией"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.stats: Dict[str, int] = {}
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._wildcard_whitelist: Set[str] = set()
        
        self._load_lists()
    
    def _load_lists(self) -> None:
        """Загрузка пользовательских списков"""
        self._whitelist = self._load_domain_file(Config.WHITELIST_FILE)
        self._blacklist = self._load_domain_file(Config.BLACKLIST_FILE)
        self._wildcard_whitelist = self._load_domain_file(Config.WILDCARD_WHITELIST_FILE)
        
        self.logger.info(f"📋 Whitelist: {len(self._whitelist):,} domains")
        self.logger.info(f"📋 Blacklist: {len(self._blacklist):,} domains")
    
    @staticmethod
    def _load_domain_file(file_path: Path) -> Set[str]:
        """Загрузка доменов из файла"""
        domains = set()
        if not file_path.exists():
            return domains
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        domains.add(domain)
        except Exception as e:
            print(f"⚠️ Failed to load {file_path}: {e}")
        
        return domains
    
    async def build(self) -> List[str]:
        """Построение финального блоклиста"""
        self.logger.progress("Building blocklist...")
        
        # Загрузка данных
        self.logger.progress("Downloading sources...")
        async with DataFetcher(self.logger) as fetcher:
            all_domains = await fetcher.fetch_all()
        
        if not all_domains:
            self.logger.error("No domains downloaded")
            return []
        
        self.stats['total'] = len(all_domains)
        self.logger.info(f"📊 Total unique: {len(all_domains):,}")
        
        # Фильтрация
        self.logger.progress("Filtering domains...")
        filtered = []
        counts = {'whitelisted': 0, 'wildcard_filtered': 0, 'blacklisted': 0}
        
        for domain in all_domains:
            if DomainValidator.match_wildcard(domain, self._wildcard_whitelist):
                counts['wildcard_filtered'] += 1
                continue
            
            if domain in self._whitelist:
                counts['whitelisted'] += 1
                continue
            
            if domain in self._blacklist:
                counts['blacklisted'] += 1
            
            filtered.append(domain)
        
        # Сохранение статистики
        self.stats.update(counts)
        self.stats['output'] = len(filtered)
        self._print_stats()
        
        return filtered
    
    def _print_stats(self) -> None:
        """Вывод статистики"""
        total = self.stats.get('total', 0)
        output = self.stats.get('output', 0)
        
        self.logger.info("📈 Statistics:")
        self.logger.info(f"   ├─ Input: {total:,} domains")
        self.logger.info(f"   ├─ Output: {output:,} domains")
        self.logger.info(f"   ├─ Whitelisted: {self.stats.get('whitelisted', 0):,}")
        self.logger.info(f"   └─ Wildcard filtered: {self.stats.get('wildcard_filtered', 0):,}")
        
        if total > 0:
            reduction = (1 - output / total) * 100
            self.logger.info(f"   └─ Reduction: {reduction:.1f}%")
    
    def save_stats(self) -> None:
        """Сохранение статистики в JSON"""
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'version': __version__,
                'stats': self.stats
            }
            with open(Config.STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save stats: {e}")


# ============================================================================
# ЭКСПОРТЕР
# ============================================================================

class HostsFileWriter:
    """Запись блоклиста в формате hosts"""
    
    @staticmethod
    def write(domains: List[str], output_path: Path) -> bool:
        """Запись доменов в hosts файл"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Заголовок
                f.write(f"# DNS Blocklist v{__version__}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"# Total: {len(domains):,} domains\n\n")
                
                # Данные
                for domain in domains:
                    f.write(f"0.0.0.0 {domain}\n")
                
                f.flush()
                os.fsync(f.fileno())
            
            return output_path.exists() and output_path.stat().st_size > 0
        except Exception as e:
            print(f"❌ Error writing hosts file: {e}")
            return False


# ============================================================================
# УТИЛИТЫ
# ============================================================================

class BackupManager:
    """Управление резервными копиями"""
    
    @staticmethod
    def create_backup(file_path: Path, backup_dir: Path) -> Optional[Path]:
        """Создание резервной копии файла"""
        if not file_path.exists():
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{file_path.stem}_{timestamp}{file_path.suffix}"
        shutil.copy2(file_path, backup_path)
        return backup_path


# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

async def main() -> int:
    """Главная функция приложения"""
    # Инициализация
    Config.init_directories()
    logger = Logger(Config.LOG_FILE, verbose=os.getenv("DEBUG", "0") == "1")
    
    # Приветствие
    print(f"\n{'=' * 50}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'=' * 50}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len(Config.SOURCES)}")
    print(f"📁 Output: {Config.HOSTS_OUTPUT}")
    print(f"{'=' * 50}\n")
    
    try:
        # Резервное копирование
        backup = BackupManager.create_backup(Config.HOSTS_OUTPUT, Config.BACKUP_DIR)
        if backup:
            logger.info(f"💾 Backup created: {backup.name}")
        
        # Построение блоклиста
        builder = BlocklistBuilder(logger)
        domains = await builder.build()
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Запись файла
        logger.progress("Writing hosts.txt...")
        if not HostsFileWriter.write(domains, Config.HOSTS_OUTPUT):
            logger.error("Failed to write hosts.txt")
            return 1
        
        # Сохранение статистики
        builder.save_stats()
        
        # Финальный вывод
        file_size = Config.HOSTS_OUTPUT.stat().st_size / 1024 / 1024
        print(f"\n{'=' * 50}")
        print(f"✅ BUILD COMPLETED SUCCESSFULLY")
        print(f"{'=' * 50}")
        print(f"📊 Blocked domains: {len(domains):,}")
        print(f"💾 File size: {file_size:.2f} MB")
        print(f"📁 Output path: {Config.HOSTS_OUTPUT.absolute()}")
        print(f"{'=' * 50}\n")
        
        return 0
        
    except asyncio.CancelledError:
        logger.warning("Operation cancelled")
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

def cli_main() -> None:
    """CLI точка входа с обработкой сигналов"""
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli_main()