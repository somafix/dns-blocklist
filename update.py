#!/usr/bin/env python3
"""
DNS Blocklist Manager - Stable v9.0.0
Полностью рабочий, протестированный и оптимизированный блоклист менеджер
"""

import asyncio
import aiohttp
import os
import sys
import shutil
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Set, Optional, List, Dict
from collections import defaultdict
import logging
import logging.handlers

__version__ = "9.0.0-stable"


# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

class Config:
    """Конфигурация приложения"""
    TIMEOUT = 30
    MAX_RETRIES = 3
    PARALLEL_DOWNLOADS = 2
    ENABLE_CACHE = False  # Отключено для гарантии обновления
    
    SOURCES = [
        {
            "name": "HaGeZi PRO",
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
            "enabled": True
        }
    ]


# ============================================================================
# ПУТИ К ФАЙЛАМ
# ============================================================================

class Paths:
    """Управление путями"""
    OUTPUT_HOSTS = Path("hosts.txt")
    BACKUP_DIR = Path("backup")
    WHITELIST = Path("whitelist.txt")
    BLACKLIST = Path("blacklist.txt")
    WILDCARD_WHITELIST = Path("wildcard_whitelist.txt")
    LOGS_DIR = Path("logs")
    LOG_FILE = Path("logs/dns_blocker.log")
    CACHE_FILE = Path(".cache/domains.json")
    STATS_FILE = Path("stats.json")

# Создание директорий
Paths.BACKUP_DIR.mkdir(exist_ok=True)
Paths.LOGS_DIR.mkdir(exist_ok=True)
Path(".cache").mkdir(exist_ok=True)


# ============================================================================
# ЛОГГЕР
# ============================================================================

class Logger:
    """Логгер с цветным выводом"""
    
    def __init__(self):
        self.logger = logging.getLogger("DNSBlocker")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        
        # Файловый логгер
        file_handler = logging.handlers.RotatingFileHandler(
            Paths.LOG_FILE, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"
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
        for prefix in ['https://', 'http://', '||', '0.0.0.0 ', '127.0.0.1 ']:
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        
        # Удаление суффиксов
        line = line.rstrip('/^')
        
        # Проверка на IP адреса
        if re.match(r'^\d+(\.\d+){3}$', line) or re.match(r'^[0-9a-f:]+$', line):
            return None
        
        # Базовая валидация
        if len(line) > 253 or len(line) < 3:
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
# ЗАГРУЗЧИК
# ============================================================================

class Fetcher:
    """Асинхронный загрузчик"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
        self.session = None
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": f"DNS-Blocklist-Manager/{__version__}"}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch_source(self, name: str, url: str) -> Optional[Set[str]]:
        """Загрузка одного источника"""
        for attempt in range(Config.MAX_RETRIES):
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
                self.logger.warning(f"  {name}: Timeout (attempt {attempt+1})")
            except Exception as e:
                self.logger.warning(f"  {name}: {str(e)[:50]}")
            
            if attempt < Config.MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)
        
        return None
    
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
        semaphore = asyncio.Semaphore(Config.PARALLEL_DOWNLOADS)
        
        async def fetch_one(source):
            if not source["enabled"]:
                return set()
            async with semaphore:
                result = await self.fetch_source(source["name"], source["url"])
                return result if result else set()
        
        tasks = [fetch_one(source) for source in Config.SOURCES]
        results = await asyncio.gather(*tasks)
        
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
        self.stats = defaultdict(int)
        
        # Загрузка пользовательских списков
        self.whitelist = self._load_domain_list(Paths.WHITELIST)
        self.blacklist = self._load_domain_list(Paths.BLACKLIST)
        self.wildcard_whitelist = self._load_domain_list(Paths.WILDCARD_WHITELIST)
        
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
        
        for domain in all_domains:
            # Проверка wildcard
            if DomainValidator.match_wildcard(domain, self.wildcard_whitelist):
                self.stats['wildcard_filtered'] += 1
                continue
            
            # Проверка whitelist
            if domain in self.whitelist:
                self.stats['whitelisted'] += 1
                continue
            
            # Добавление в результат
            filtered_domains.append(domain)
            
            # Статистика blacklist
            if domain in self.blacklist:
                self.stats['blacklisted'] += 1
        
        self.stats['output'] = len(filtered_domains)
        self._print_stats()
        
        return filtered_domains
    
    def _print_stats(self):
        """Вывод статистики"""
        total = self.stats['total']
        output = self.stats['output']
        
        self.logger.info("📈 Statistics:")
        self.logger.info(f"   ├─ Input: {total:,} domains")
        self.logger.info(f"   ├─ Output: {output:,} domains")
        
        if total > 0:
            reduction = (1 - output/total) * 100
            self.logger.info(f"   └─ Reduction: {reduction:.1f}%")
    
    def save_stats(self):
        """Сохранение статистики"""
        try:
            stats_data = {
                'timestamp': datetime.now().isoformat(),
                'version': __version__,
                'stats': dict(self.stats)
            }
            with open(Paths.STATS_FILE, 'w', encoding='utf-8') as f:
                json.dump(stats_data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save stats: {e}")


# ============================================================================
# ЭКСПОРТЕР HOSTS ФАЙЛА
# ============================================================================

class HostsExporter:
    """Экспорт в формат hosts"""
    
    @staticmethod
    def export(domains: List[str], output_path: Path) -> bool:
        """Экспорт доменов в hosts файл"""
        try:
            # Запись файла
            with open(output_path, 'w', encoding='utf-8', buffering=8192) as f:
                # Заголовок
                f.write(f"# DNS Blocklist v{__version__}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"# Total: {len(domains):,} domains\n\n")
                
                # Запись доменов
                for domain in domains:
                    f.write(f"0.0.0.0 {domain}\n")
            
            # Проверка результата
            if output_path.exists() and output_path.stat().st_size > 0:
                return True
            
        except Exception as e:
            print(f"Error writing hosts file: {e}")
        
        return False


# ============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# ============================================================================

async def main() -> int:
    """Главная функция"""
    
    # Инициализация логгера
    logger = Logger()
    
    # Приветствие
    print(f"\n{'='*50}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'='*50}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len([s for s in Config.SOURCES if s['enabled']])}")
    print(f"📁 Output: {Paths.OUTPUT_HOSTS}")
    print(f"{'='*50}\n")
    
    try:
        # Создание бэкапа
        if Paths.OUTPUT_HOSTS.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Paths.BACKUP_DIR / f"hosts_{timestamp}.txt"
            shutil.copy2(Paths.OUTPUT_HOSTS, backup_path)
            logger.info(f"💾 Backup created: {backup_path.name}")
        
        # Сборка блоклиста
        manager = BlocklistManager(logger)
        domains = await manager.build()
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Экспорт в hosts файл
        logger.progress("Writing hosts.txt...")
        success = HostsExporter.export(domains, Paths.OUTPUT_HOSTS)
        
        if not success:
            logger.error("Failed to write hosts.txt")
            return 1
        
        # Сохранение статистики
        manager.save_stats()
        
        # Финальный вывод
        file_size = Paths.OUTPUT_HOSTS.stat().st_size / 1024 / 1024
        print(f"\n{'='*50}")
        print(f"✅ BUILD COMPLETED")
        print(f"{'='*50}")
        print(f"📊 Blocked: {len(domains):,} domains")
        print(f"💾 File: {file_size:.2f} MB")
        print(f"📁 Path: {Paths.OUTPUT_HOSTS.absolute()}")
        print(f"{'='*50}\n")
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
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
        print("\n⚠️ Interrupted")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main_cli()