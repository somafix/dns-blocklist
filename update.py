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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple, Callable, Any

try:
    import aiohttp
    from aiohttp import ClientTimeout, ClientError
except ImportError:
    print("❌ Ошибка: Установите aiohttp: pip install aiohttp")
    sys.exit(1)

__version__ = "11.0.0"


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================

@dataclass
class Config:
    """Централизованная конфигурация приложения"""
    # Настройки сети
    timeout: int = 30
    max_retries: int = 3
    parallel_downloads: int = 2
    user_agent: str = f"DNS-Blocklist-Manager/{__version__}"
    
    # Источники данных
    sources: List[Dict[str, str]] = None
    
    # Пути к файлам
    hosts_output: Path = Path("hosts.txt")
    backup_dir: Path = Path("backup")
    whitelist_file: Path = Path("whitelist.txt")
    blacklist_file: Path = Path("blacklist.txt")
    wildcard_whitelist_file: Path = Path("wildcard_whitelist.txt")
    log_file: Path = Path("logs/dns_blocker.log")
    stats_file: Path = Path("stats.json")
    
    def __post_init__(self):
        if self.sources is None:
            self.sources = [
                {
                    "name": "HaGeZi PRO",
                    "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
                }
            ]
    
    def init_directories(self) -> None:
        """Создание необходимых директорий"""
        self.backup_dir.mkdir(exist_ok=True)
        self.log_file.parent.mkdir(exist_ok=True)


# ============================================================================
# ЛОГГЕР
# ============================================================================

class Logger:
    """Профессиональный логгер с ротацией файлов"""
    
    _EMOJIS = {
        'info': 'ℹ️',
        'warning': '⚠️',
        'error': '❌',
        'success': '✅',
        'progress': '📊',
        'debug': '🐛'
    }
    
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
        
        self._verbose = verbose
    
    def _log(self, level: str, msg: str, emoji_key: str = "") -> None:
        """Базовый метод логирования"""
        emoji = self._EMOJIS.get(emoji_key, "")
        formatted_msg = f"{emoji} {msg}" if emoji else msg
        getattr(self.logger, level)(formatted_msg)
    
    def info(self, msg: str) -> None:
        self._log("info", msg, "info")
    
    def warning(self, msg: str) -> None:
        self._log("warning", msg, "warning")
    
    def error(self, msg: str) -> None:
        self._log("error", msg, "error")
    
    def success(self, msg: str) -> None:
        self._log("info", msg, "success")
    
    def progress(self, msg: str) -> None:
        self._log("info", msg, "progress")
    
    def debug(self, msg: str) -> None:
        if self._verbose:
            self._log("debug", msg, "debug")


# ============================================================================
# ВАЛИДАТОР ДОМЕНОВ
# ============================================================================

class DomainValidator:
    """Валидация и нормализация доменных имён"""
    
    # Оптимизированные регулярные выражения
    _IP_PATTERN = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    _DOMAIN_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$')
    _PREFIXES = ('https://', 'http://', '||', '0.0.0.0 ', '127.0.0.1 ')
    _WILDCARD_PATTERN = re.compile(r'^(\*\.)|(\.\*)$')
    
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
        
        # Пропуск wildcard паттернов
        if '*' in line:
            return None
        
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
            if pattern.endswith('*'):
                prefix = pattern[:-1]
                if domain.startswith(prefix):
                    return True
            elif pattern.startswith('*'):
                suffix = pattern[1:]
                if domain.endswith(suffix):
                    return True
            elif domain == pattern:
                return True
        return False


# ============================================================================
# ЗАГРУЗЧИК ДАННЫХ
# ============================================================================

class DataFetcher:
    """Асинхронный загрузчик данных с обработкой ошибок"""
    
    def __init__(self, logger: Logger, config: Config):
        self.logger = logger
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        timeout = ClientTimeout(total=self.config.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": self.config.user_agent}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
    
    async def fetch_source(self, name: str, url: str) -> Set[str]:
        """Загрузка одного источника данных"""
        if not self._session:
            raise RuntimeError("Session not initialized")
        
        for attempt in range(self.config.max_retries):
            try:
                async with self._session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        domains = self._parse_content(content)
                        self.logger.info(f"  📥 {name}: {len(domains):,} domains")
                        return domains
                    
                    self.logger.warning(f"  {name}: HTTP {response.status}")
                    
            except asyncio.TimeoutError:
                self.logger.warning(f"  {name}: Timeout ({attempt + 1}/{self.config.max_retries})")
            except ClientError as e:
                self.logger.warning(f"  {name}: Network error - {str(e)[:50]}")
            except Exception as e:
                self.logger.warning(f"  {name}: Unexpected error - {str(e)[:50]}")
            
            if attempt < self.config.max_retries - 1:
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
        semaphore = asyncio.Semaphore(self.config.parallel_downloads)
        
        async def fetch_one(source: Dict[str, str]) -> Set[str]:
            async with semaphore:
                return await self.fetch_source(source["name"], source["url"])
        
        results = await asyncio.gather(*[fetch_one(src) for src in self.config.sources])
        
        # Объединение результатов
        all_domains = set()
        for domains in results:
            all_domains.update(domains)
        
        return all_domains


# ============================================================================
# МЕНЕДЖЕР БЛОКЛИСТА
# ============================================================================

@dataclass
class BuildStats:
    """Статистика сборки блоклиста"""
    total: int = 0
    whitelisted: int = 0
    wildcard_filtered: int = 0
    blacklisted: int = 0
    output: int = 0
    reduction_percent: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total': self.total,
            'whitelisted': self.whitelisted,
            'wildcard_filtered': self.wildcard_filtered,
            'blacklisted': self.blacklisted,
            'output': self.output,
            'reduction_percent': self.reduction_percent
        }


class BlocklistBuilder:
    """Построитель блоклиста с фильтрацией"""
    
    def __init__(self, logger: Logger, config: Config):
        self.logger = logger
        self.config = config
        self.stats = BuildStats()
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._wildcard_whitelist: Set[str] = set()
        
        self._load_lists()
    
    def _load_lists(self) -> None:
        """Загрузка пользовательских списков"""
        self._whitelist = self._load_domain_file(self.config.whitelist_file)
        self._blacklist = self._load_domain_file(self.config.blacklist_file)
        self._wildcard_whitelist = self._load_domain_file(self.config.wildcard_whitelist_file)
        
        self.logger.info(f"📋 Whitelist: {len(self._whitelist):,} domains")
        self.logger.info(f"📋 Blacklist: {len(self._blacklist):,} domains")
        self.logger.info(f"📋 Wildcard whitelist: {len(self._wildcard_whitelist):,} patterns")
    
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
        except (OSError, UnicodeDecodeError) as e:
            print(f"⚠️ Failed to load {file_path}: {e}")
        
        return domains
    
    async def build(self) -> List[str]:
        """Построение финального блоклиста"""
        self.logger.progress("Building blocklist...")
        
        # Загрузка данных
        self.logger.progress("Downloading sources...")
        async with DataFetcher(self.logger, self.config) as fetcher:
            all_domains = await fetcher.fetch_all()
        
        if not all_domains:
            self.logger.error("No domains downloaded")
            return []
        
        self.stats.total = len(all_domains)
        self.logger.info(f"📊 Total unique: {len(all_domains):,}")
        
        # Фильтрация
        self.logger.progress("Filtering domains...")
        filtered = []
        
        for domain in all_domains:
            # Проверка wildcard whitelist
            if DomainValidator.match_wildcard(domain, self._wildcard_whitelist):
                self.stats.wildcard_filtered += 1
                continue
            
            # Проверка whitelist
            if domain in self._whitelist:
                self.stats.whitelisted += 1
                continue
            
            # Проверка blacklist
            if domain in self._blacklist:
                self.stats.blacklisted += 1
            
            filtered.append(domain)
        
        self.stats.output = len(filtered)
        if self.stats.total > 0:
            self.stats.reduction_percent = (1 - self.stats.output / self.stats.total) * 100
        
        self._print_stats()
        return filtered
    
    def _print_stats(self) -> None:
        """Вывод статистики"""
        self.logger.info("📈 Statistics:")
        self.logger.info(f"   ├─ Input: {self.stats.total:,} domains")
        self.logger.info(f"   ├─ Output: {self.stats.output:,} domains")
        self.logger.info(f"   ├─ Whitelisted: {self.stats.whitelisted:,}")
        self.logger.info(f"   ├─ Wildcard filtered: {self.stats.wildcard_filtered:,}")
        self.logger.info(f"   ├─ Blacklisted (kept): {self.stats.blacklisted:,}")
        self.logger.info(f"   └─ Reduction: {self.stats.reduction_percent:.1f}%")
    
    def save_stats(self) -> None:
        """Сохранение статистики в JSON"""
        try:
            data = {
                'timestamp': datetime.now(timezone.UTC).isoformat(),
                'version': __version__,
                'stats': self.stats.to_dict()
            }
            self.config.stats_file.write_text(
                json.dumps(data, indent=2),
                encoding='utf-8'
            )
        except (OSError, json.JSONDecodeError) as e:
            self.logger.warning(f"Failed to save stats: {e}")


# ============================================================================
# ЭКСПОРТЕР
# ============================================================================

class HostsFileWriter:
    """Запись блоклиста в формате hosts"""
    
    @staticmethod
    def write(domains: List[str], output_path: Path) -> bool:
        """Запись доменов в hosts файл"""
        if not domains:
            return False
        
        try:
            output_path.write_text(
                f"# DNS Blocklist v{__version__}\n"
                f"# Generated: {datetime.now(timezone.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"# Total: {len(domains):,} domains\n"
                f"# Last update: {datetime.now(timezone.UTC).isoformat()}\n\n"
                + ''.join(f"0.0.0.0 {domain}\n" for domain in domains),
                encoding='utf-8'
            )
            return output_path.exists() and output_path.stat().st_size > 0
        except OSError as e:
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
        
        try:
            shutil.copy2(file_path, backup_path)
            return backup_path
        except (OSError, shutil.Error) as e:
            print(f"⚠️ Failed to create backup: {e}")
            return None


# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

async def main() -> int:
    """Главная функция приложения"""
    # Инициализация
    config = Config()
    config.init_directories()
    
    logger = Logger(config.log_file, verbose=os.getenv("DEBUG", "0") == "1")
    
    # Приветствие
    print(f"\n{'=' * 50}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'=' * 50}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len(config.sources)}")
    print(f"📁 Output: {config.hosts_output}")
    print(f"{'=' * 50}\n")
    
    try:
        # Резервное копирование
        backup = BackupManager.create_backup(config.hosts_output, config.backup_dir)
        if backup:
            logger.info(f"💾 Backup created: {backup.name}")
        
        # Построение блоклиста
        builder = BlocklistBuilder(logger, config)
        domains = await builder.build()
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Запись файла
        logger.progress("Writing hosts.txt...")
        if not HostsFileWriter.write(domains, config.hosts_output):
            logger.error("Failed to write hosts.txt")
            return 1
        
        # Сохранение статистики
        builder.save_stats()
        
        # Финальный вывод
        file_size = config.hosts_output.stat().st_size / (1024 * 1024)
        print(f"\n{'=' * 50}")
        print(f"✅ BUILD COMPLETED SUCCESSFULLY")
        print(f"{'=' * 50}")
        print(f"📊 Blocked domains: {len(domains):,}")
        print(f"💾 File size: {file_size:.2f} MB")
        print(f"📁 Output path: {config.hosts_output.absolute()}")
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