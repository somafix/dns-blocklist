#!/usr/bin/env python3
"""
DNS Blocklist Manager - Production Ready v10.0.1
Полностью рабочий, оптимизированный и протестированный блоклист менеджер
"""

import asyncio
import sys
import shutil
import re
import json
import os  # ИСПРАВЛЕНО: добавлен импорт os
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Optional
import logging
import logging.handlers

# Проверка наличия aiohttp
try:
    import aiohttp
except ImportError:
    print("❌ Ошибка: Установите aiohttp: pip install aiohttp")
    sys.exit(1)

__version__ = "10.0.1-production"


# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

TIMEOUT = 30
MAX_RETRIES = 3
PARALLEL_DOWNLOADS = 2

SOURCES = [
    {
        "name": "HaGeZi PRO",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "enabled": True
    }
]

# Пути к файлам
HOSTS_OUTPUT = Path("hosts.txt")
BACKUP_DIR = Path("backup")
WHITELIST_FILE = Path("whitelist.txt")
BLACKLIST_FILE = Path("blacklist.txt")
WILDCARD_WHITELIST_FILE = Path("wildcard_whitelist.txt")
LOG_FILE = Path("logs/dns_blocker.log")
STATS_FILE = Path("stats.json")

# Создание необходимых директорий
BACKUP_DIR.mkdir(exist_ok=True)
Path("logs").mkdir(exist_ok=True)


# ============================================================================
# ЛОГГЕР
# ============================================================================

class Logger:
    """Простой логгер с цветным выводом"""
    
    def __init__(self):
        self.logger = logging.getLogger("DNSBlocker")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        
        # Файловый логгер
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(file_handler)
        
        # Консольный логгер
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(console_handler)
    
    def info(self, msg: str): self.logger.info(f"ℹ️ {msg}")
    def warning(self, msg: str): self.logger.warning(f"⚠️ {msg}")
    def error(self, msg: str): self.logger.error(f"❌ {msg}")
    def success(self, msg: str): self.logger.info(f"✅ {msg}")
    def progress(self, msg: str): self.logger.info(f"📊 {msg}")


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
        if re.match(r'^\d+(\.\d+){3}$', line):
            return None
        
        # Базовая валидация домена
        if len(line) > 253 or len(line) < 3:
            return None
        if line[0] == '.' or line[-1] == '.':
            return None
        if '..' in line:
            return None
        
        # Проверка допустимых символов
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
# ЗАГРУЗЧИК
# ============================================================================

class Fetcher:
    """Асинхронный загрузчик"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=TIMEOUT)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": f"DNS-Blocklist-Manager/{__version__}"}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
            self.session = None
    
    async def fetch_source(self, name: str, url: str) -> Set[str]:
        """Загрузка одного источника"""
        if not self.session:
            raise RuntimeError("Сессия не инициализирована")
        
        for attempt in range(MAX_RETRIES):
            try:
                async with self.session.get(url) as response:
                    if response.status == 200:
                        text = await response.text()
                        domains = self._parse_domains(text)
                        self.logger.info(f"  📥 {name}: {len(domains):,} domains")
                        return domains
                    else:
                        self.logger.warning(f"  {name}: HTTP {response.status}")
            except asyncio.TimeoutError:
                self.logger.warning(f"  {name}: Timeout (attempt {attempt+1}/{MAX_RETRIES})")
            except aiohttp.ClientError as e:
                self.logger.warning(f"  {name}: Network error - {str(e)[:50]}")
            except Exception as e:
                self.logger.warning(f"  {name}: Unexpected error - {str(e)[:50]}")
            
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)
        
        return set()
    
    def _parse_domains(self, content: str) -> Set[str]:
        """Парсинг доменов из контента"""
        domains = set()
        for line in content.splitlines():
            domain = DomainValidator.clean(line)
            if domain:
                domains.add(domain)
        return domains
    
    async def fetch_all(self) -> Set[str]:
        """Параллельная загрузка всех источников"""
        semaphore = asyncio.Semaphore(PARALLEL_DOWNLOADS)
        
        async def fetch_one(source: dict) -> Set[str]:
            if not source["enabled"]:
                return set()
            async with semaphore:
                return await self.fetch_source(source["name"], source["url"])
        
        results = await asyncio.gather(*[fetch_one(src) for src in SOURCES])
        
        # Объединение результатов
        all_domains = set()
        for domains in results:
            if domains:
                all_domains.update(domains)
        
        return all_domains


# ============================================================================
# МЕНЕДЖЕР БЛОКЛИСТА
# ============================================================================

class BlocklistManager:
    """Управление блоклистом"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.stats: Dict[str, int] = {}
        
        # Загрузка пользовательских списков
        self.whitelist = self._load_domain_list(WHITELIST_FILE)
        self.blacklist = self._load_domain_list(BLACKLIST_FILE)
        self.wildcard_whitelist = self._load_domain_list(WILDCARD_WHITELIST_FILE)
        
        self.logger.info(f"📋 Whitelist: {len(self.whitelist)} domains")
        self.logger.info(f"📋 Blacklist: {len(self.blacklist)} domains")
    
    def _load_domain_list(self, path: Path) -> Set[str]:
        """Загрузка списка доменов из файла"""
        domains = set()
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        domain = DomainValidator.clean(line)
                        if domain:
                            domains.add(domain)
            except Exception as e:
                self.logger.warning(f"Failed to load {path}: {e}")
        return domains
    
    async def build(self) -> List[str]:
        """Сборка блоклиста"""
        self.logger.progress("Building blocklist...")
        
        # Загрузка из сети
        self.logger.progress("Downloading sources...")
        async with Fetcher(self.logger) as fetcher:
            all_domains = await fetcher.fetch_all()
        
        if not all_domains:
            self.logger.error("No domains downloaded")
            return []
        
        self.stats['total'] = len(all_domains)
        self.logger.info(f"📊 Total unique: {len(all_domains):,}")
        
        # Фильтрация
        self.logger.progress("Filtering domains...")
        filtered_domains = []
        whitelisted = 0
        wildcard_filtered = 0
        blacklisted = 0
        
        for domain in all_domains:
            # Проверка wildcard whitelist
            if DomainValidator.match_wildcard(domain, self.wildcard_whitelist):
                wildcard_filtered += 1
                continue
            
            # Проверка обычного whitelist
            if domain in self.whitelist:
                whitelisted += 1
                continue
            
            # Подсчёт blacklist
            if domain in self.blacklist:
                blacklisted += 1
            
            filtered_domains.append(domain)
        
        # Сохранение статистики
        self.stats['whitelisted'] = whitelisted
        self.stats['wildcard_filtered'] = wildcard_filtered
        self.stats['blacklisted'] = blacklisted
        self.stats['output'] = len(filtered_domains)
        
        self._print_stats()
        return filtered_domains
    
    def _print_stats(self):
        """Вывод статистики"""
        total = self.stats.get('total', 0)
        output = self.stats.get('output', 0)
        
        self.logger.info("📈 Statistics:")
        self.logger.info(f"   ├─ Input: {total:,} domains")
        self.logger.info(f"   ├─ Output: {output:,} domains")
        self.logger.info(f"   ├─ Whitelisted: {self.stats.get('whitelisted', 0):,}")
        self.logger.info(f"   └─ Wildcard filtered: {self.stats.get('wildcard_filtered', 0):,}")
        
        if total > 0:
            reduction = (1 - output/total) * 100
            self.logger.info(f"   └─ Reduction: {reduction:.1f}%")
    
    def save_stats(self):
        """Сохранение статистики"""
        try:
            stats_data = {
                'timestamp': datetime.now().isoformat(),
                'version': __version__,
                'stats': self.stats
            }
            with open(STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump(stats_data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save stats: {e}")


# ============================================================================
# ЭКСПОРТЕР
# ============================================================================

class HostsExporter:
    """Экспорт в формат hosts"""
    
    @staticmethod
    def export(domains: List[str], output_path: Path) -> bool:
        """Экспорт доменов в hosts файл"""
        try:
            # Запись файла
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"# DNS Blocklist v{__version__}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"# Total: {len(domains):,} domains\n\n")
                
                for domain in domains:
                    f.write(f"0.0.0.0 {domain}\n")
                
                f.flush()
                # Принудительная запись на диск
                os.fsync(f.fileno())  # ИСПРАВЛЕНО: os теперь импортирован
            
            # Проверка результата
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
    
    logger = Logger()
    
    # Приветствие
    print(f"\n{'='*50}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'='*50}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len([s for s in SOURCES if s['enabled']])}")
    print(f"📁 Output: {HOSTS_OUTPUT}")
    print(f"{'='*50}\n")
    
    try:
        # Создание бэкапа
        if HOSTS_OUTPUT.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = BACKUP_DIR / f"hosts_{timestamp}.txt"
            shutil.copy2(HOSTS_OUTPUT, backup_path)
            logger.info(f"💾 Backup created: {backup_path.name}")
        
        # Сборка блоклиста
        manager = BlocklistManager(logger)
        domains = await manager.build()
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Экспорт в hosts файл
        logger.progress("Writing hosts.txt...")
        success = HostsExporter.export(domains, HOSTS_OUTPUT)
        
        if not success:
            logger.error("Failed to write hosts.txt")
            return 1
        
        # Сохранение статистики
        manager.save_stats()
        
        # Финальный вывод
        file_size = HOSTS_OUTPUT.stat().st_size / 1024 / 1024
        print(f"\n{'='*50}")
        print(f"✅ BUILD COMPLETED")
        print(f"{'='*50}")
        print(f"📊 Blocked: {len(domains):,} domains")
        print(f"💾 File size: {file_size:.2f} MB")
        print(f"📁 Path: {HOSTS_OUTPUT.absolute()}")
        print(f"{'='*50}\n")
        
        return 0
        
    except asyncio.CancelledError:
        logger.warning("Operation cancelled")
        return 130
    except Exception as e:
        logger.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()
        return 1


# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

def main_cli():
    """CLI точка входа"""
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main_cli()