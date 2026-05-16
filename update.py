#!/usr/bin/env python3
"""
DNS Blocklist Manager - Elite Edition
Профессиональный менеджер блоклистов с поддержкой множества источников,
расширенной фильтрацией, кэшированием и мониторингом.
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
import hashlib
import json
import signal
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Set, Optional, Dict, List, Callable, Awaitable, Final
from functools import wraps
from collections import defaultdict

__version__ = "7.0.0-elite"


# ============================================================================
# Конфигурация с типизацией и валидацией
# ============================================================================

@dataclass(frozen=True)
class SourceConfig:
    """Конфигурация источника блоклиста"""
    name: str
    url: str
    enabled: bool = True
    priority: int = 0  # Чем выше, тем важнее
    max_size_mb: int = 500
    expected_format: str = "hosts"  # hosts, domains, adblock


@dataclass(frozen=True)
class AppConfig:
    """Главная конфигурация приложения"""
    timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 5
    user_agent: str = f"DNS-Blocklist-Manager/{__version__}"
    max_domains: int = 10_000_000
    enable_cache: bool = True
    cache_ttl_hours: int = 24
    parallel_downloads: int = 3
    sources: List[SourceConfig] = field(default_factory=lambda: [
        SourceConfig(
            name="HaGeZi PRO",
            url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
            priority=100
        ),
    ])
    
    @classmethod
    def from_env(cls) -> 'AppConfig':
        """Загрузка конфигурации из переменных окружения"""
        config = cls()
        with suppress(Exception):
            if os.getenv("BLOCKLIST_TIMEOUT"):
                config = config._replace(timeout=int(os.getenv("BLOCKLIST_TIMEOUT")))
        return config


CONFIG = AppConfig.from_env()


# ============================================================================
# Пути к файлам с использованием Path API
# ============================================================================

@dataclass(frozen=True)
class FilePaths:
    """Централизованное управление путями"""
    output_hosts: Path = Path("hosts.txt")
    backup_dir: Path = Path("backup")
    whitelist: Path = Path("lists/whitelist.txt")
    blacklist: Path = Path("lists/blacklist.txt")
    wildcard_whitelist: Path = Path("lists/wildcard_whitelist.txt")
    log_dir: Path = Path("logs")
    log_file: Path = Path("logs/dns_blocker.log")
    cache_dir: Path = Path(".cache")
    cache_file: Path = Path(".cache/domains_cache.json")
    stats_file: Path = Path("stats.json")
    pid_file: Path = Path("/tmp/dns_blocker.pid")
    
    def __post_init__(self):
        """Создание необходимых директорий"""
        for dir_path in {self.backup_dir, self.log_dir, self.cache_dir}:
            dir_path.mkdir(parents=True, exist_ok=True)


FILES = FilePaths()


# ============================================================================
# Кастомные исключения
# ============================================================================

class BlocklistError(Exception):
    """Базовое исключение для блоклиста"""
    pass


class FetchError(BlocklistError):
    """Ошибка загрузки данных"""
    pass


class ValidationError(BlocklistError):
    """Ошибка валидации домена"""
    pass


# ============================================================================
# Логирование с ротацией и форматированием
# ============================================================================

class EliteLogger:
    """Профессиональный логгер с цветным выводом и структурированным логированием"""
    
    _COLORS = {
        "INFO": "\033[92m",    # Green
        "WARNING": "\033[93m", # Yellow
        "ERROR": "\033[91m",   # Red
        "DEBUG": "\033[96m",   # Cyan
        "RESET": "\033[0m",
    }
    
    def __init__(self, log_file: Path, verbose: bool = False):
        self.logger = logging.getLogger("DNSBlocklistManager")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()
        
        # Файловый хендлер с ротацией
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self.logger.addHandler(file_handler)
        
        # Консольный хендлер с цветами
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self._ColoredFormatter())
        self.logger.addHandler(console_handler)
    
    class _ColoredFormatter(logging.Formatter):
        def format(self, record):
            color = EliteLogger._COLORS.get(record.levelname, EliteLogger._COLORS["RESET"])
            record.levelname = f"{color}{record.levelname}{EliteLogger._COLORS['RESET']}"
            return super().format(record)
    
    def _log(self, level: str, msg: str, emoji: str = ""):
        getattr(self.logger, level.lower())(f"{emoji} {msg}" if emoji else msg)
    
    def info(self, msg: str): self._log("INFO", msg, "ℹ️")
    def warning(self, msg: str): self._log("WARNING", msg, "⚠️")
    def error(self, msg: str): self._log("ERROR", msg, "❌")
    def debug(self, msg: str): self._log("DEBUG", msg, "🐛")
    def success(self, msg: str): self._log("INFO", msg, "✅")
    def progress(self, msg: str): self._log("INFO", msg, "📊")


# ============================================================================
# Продвинутый валидатор доменов
# ============================================================================

class DomainValidator:
    """Валидация доменов с поддержкой wildcard и regex"""
    
    # TLD проверка (примерные, для реального использования нужен полный список)
    _VALID_TLDS: Set[str] = {
        'com', 'org', 'net', 'io', 'app', 'dev', 'xyz', 'info', 'biz',
        'ru', 'ua', 'by', 'kz', 'pl', 'de', 'fr', 'uk', 'us', 'ca', 'au',
        'jp', 'cn', 'in', 'br', 'mx', 'za', 'eg', 'sa', 'ae', 'tr'
    }
    
    # Паттерны для очистки
    _CLEAN_PATTERNS: List[re.Pattern] = [
        re.compile(r'^https?://'),
        re.compile(r'^[0-9.]+ '),
        re.compile(r'^\|\|'),
        re.compile(r'\^$'),
        re.compile(r'/+\s*$'),
        re.compile(r'^[0-9a-f:]+ '),
    ]
    
    @classmethod
    def clean(cls, line: str) -> Optional[str]:
        """
        Очистка и извлечение домена из строки
        Возвращает None если строка не является валидным доменом
        """
        if not line or not isinstance(line, str):
            return None
        
        # Удаление комментариев
        if "#" in line:
            line = line[:line.index("#")]
        
        # Очистка от лишних символов
        line = line.strip().lower()
        if not line:
            return None
        
        # Применение паттернов очистки
        for pattern in cls._CLEAN_PATTERNS:
            line = pattern.sub('', line)
        
        # Проверка на IP-адреса
        if re.match(r'^\d+(\.\d+){3}$', line) or re.match(r'^[0-9a-f:]+$', line):
            return None
        
        # Базовая валидация домена
        if not cls._is_valid_domain(line):
            return None
        
        return line
    
    @classmethod
    def _is_valid_domain(cls, domain: str) -> bool:
        """Строгая валидация домена"""
        if len(domain) > 253:
            return False
        
        if domain.startswith('.') or domain.endswith('.'):
            return False
        
        if '..' in domain:
            return False
        
        # Проверка допустимых символов
        if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', domain):
            return False
        
        # Проверка TLD
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            # Не блокируем если TLD не в списке (может быть новый домен)
            if tld not in cls._VALID_TLDS and len(tld) > 6:
                return False
        
        return True
    
    @classmethod
    def match_wildcard(cls, domain: str, patterns: Set[str]) -> bool:
        """Проверка соответствия домена wildcard паттернам"""
        for pattern in patterns:
            if pattern.endswith('*'):
                if domain.startswith(pattern[:-1]):
                    return True
            elif pattern.startswith('*'):
                if domain.endswith(pattern[1:]):
                    return True
            elif '*' in pattern:
                regex = pattern.replace('.', r'\.').replace('*', '.*')
                if re.match(f"^{regex}$", domain):
                    return True
            elif domain == pattern:
                return True
        return False


# ============================================================================
# Кэширование результатов
# ============================================================================

class DomainCache:
    """Кэширование доменов с TTL"""
    
    def __init__(self, cache_file: Path, ttl_hours: int = 24):
        self.cache_file = cache_file
        self.ttl = timedelta(hours=ttl_hours)
        self._cache: Dict[str, Dict] = {}
        self._load()
    
    def _load(self):
        """Загрузка кэша из файла"""
        if not self.cache_file.exists():
            return
        
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                timestamp = datetime.fromisoformat(data.get('timestamp', '2000-01-01'))
                
                if datetime.now() - timestamp < self.ttl:
                    self._cache = data.get('domains', {})
                    return
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
        
        self._cache = {}
    
    def save(self):
        """Сохранение кэша в файл"""
        data = {
            'timestamp': datetime.now().isoformat(),
            'domains': self._cache
        }
        with open(self.cache_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def get(self, source: str) -> Optional[Set[str]]:
        """Получение доменов из кэша"""
        if source in self._cache:
            return set(self._cache[source])
        return None
    
    def set(self, source: str, domains: Set[str]):
        """Сохранение доменов в кэш"""
        self._cache[source] = list(domains)


# ============================================================================
# Асинхронный загрузчик с семафорами и retry политикой
# ============================================================================

class AsyncFetcher:
    """Асинхронный загрузчик с поддержкой лимитов и retry"""
    
    def __init__(self, logger: EliteLogger, max_concurrent: int = 3):
        self.logger = logger
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": CONFIG.user_agent}
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch(self, url: str, name: str) -> Optional[str]:
        """Загрузка одного источника с retry"""
        async with self.semaphore:
            for attempt in range(CONFIG.max_retries):
                try:
                    async with self.session.get(url, timeout=CONFIG.timeout) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            self.logger.debug(f"{name}: {len(text):,} байт")
                            return text
                        elif resp.status == 404:
                            self.logger.error(f"{name}: Источник не найден (404)")
                            return None
                        else:
                            self.logger.warning(f"{name}: HTTP {resp.status}")
                
                except asyncio.TimeoutError:
                    self.logger.warning(f"{name}: Таймаут (попытка {attempt + 1}/{CONFIG.max_retries})")
                except aiohttp.ClientError as e:
                    self.logger.warning(f"{name}: Сетевая ошибка - {e}")
                except Exception as e:
                    self.logger.warning(f"{name}: {type(e).__name__} - {e}")
                
                if attempt < CONFIG.max_retries - 1:
                    await asyncio.sleep(CONFIG.retry_delay * (attempt + 1))
            
            self.logger.error(f"{name}: Не удалось загрузить после {CONFIG.max_retries} попыток")
            return None
    
    async def fetch_all(self, sources: List[SourceConfig]) -> Dict[str, Set[str]]:
        """Параллельная загрузка всех источников"""
        tasks = []
        for source in sources:
            if source.enabled:
                tasks.append(self._fetch_with_parse(source))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domains_by_source = {}
        for result in results:
            if isinstance(result, tuple):
                name, domains = result
                if domains:
                    domains_by_source[name] = domains
        
        return domains_by_source
    
    async def _fetch_with_parse(self, source: SourceConfig) -> tuple[str, Set[str]]:
        """Загрузка и парсинг одного источника"""
        content = await self.fetch(source.url, source.name)
        if not content:
            return source.name, set()
        
        domains = set()
        for line in content.splitlines():
            domain = DomainValidator.clean(line)
            if domain:
                domains.add(domain)
        
        self.logger.info(f"  📥 {source.name}: {len(domains):,} доменов")
        return source.name, domains


# ============================================================================
# Основной менеджер блоклиста
# ============================================================================

class BlocklistManager:
    """Управление блоклистами с фильтрацией и статистикой"""
    
    def __init__(self, logger: EliteLogger):
        self.logger = logger
        self.domains: Set[str] = set()
        self.stats = defaultdict(int)
        
        # Загрузка пользовательских списков
        self.whitelist = self._load_domain_list(FILES.whitelist, "whitelist")
        self.blacklist = self._load_domain_list(FILES.blacklist, "blacklist")
        self.wildcard_whitelist = self._load_domain_list(FILES.wildcard_whitelist, "wildcard whitelist")
    
    def _load_domain_list(self, path: Path, name: str) -> Set[str]:
        """Загрузка списка доменов из файла"""
        domains = set()
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        domains.add(domain)
            self.logger.info(f"📋 {name}: {len(domains)} доменов")
        return domains
    
    async def build(self, sources: List[SourceConfig], use_cache: bool = True) -> Set[str]:
        """Сборка блоклиста из всех источников"""
        self.logger.progress("Начало сборки блоклиста")
        
        cached_domains = None
        if use_cache:
            cache = DomainCache(FILES.cache_file, CONFIG.cache_ttl_hours)
            cached_domains = cache.get("combined")
        
        if cached_domains:
            self.logger.info(f"📀 Использован кэш: {len(cached_domains):,} доменов")
            self.domains = cached_domains
        else:
            async with AsyncFetcher(self.logger, CONFIG.parallel_downloads) as fetcher:
                domains_by_source = await fetcher.fetch_all(sources)
                
                # Объединение с учетом приоритетов
                for source in sorted(sources, key=lambda s: s.priority, reverse=True):
                    if source.name in domains_by_source:
                        self.domains.update(domains_by_source[source.name])
                        self.stats[f"from_{source.name}"] = len(domains_by_source[source.name])
            
            # Сохранение в кэш
            if use_cache:
                cache = DomainCache(FILES.cache_file, CONFIG.cache_ttl_hours)
                cache.set("combined", self.domains)
                cache.save()
                self.logger.debug("Кэш сохранен")
        
        self.stats["total_raw"] = len(self.domains)
        self.logger.info(f"📊 Собрано уникальных доменов: {len(self.domains):,}")
        
        return self._apply_filters()
    
    def _apply_filters(self) -> Set[str]:
        """Применение белого и черного списков"""
        result = set()
        
        for domain in self.domains:
            # Проверка wildcard whitelist
            if DomainValidator.match_wildcard(domain, self.wildcard_whitelist):
                self.stats["wildcard_whitelisted"] += 1
                continue
            
            # Обычный whitelist
            if domain in self.whitelist:
                self.stats["whitelisted"] += 1
                continue
            
            # Blacklist
            if domain in self.blacklist:
                result.add(domain)
                self.stats["blacklisted"] += 1
                continue
            
            result.add(domain)
            self.stats["normal"] += 1
        
        self.logger.success(f"Фильтрация завершена: {len(result):,} доменов")
        self._log_stats()
        
        return result
    
    def _log_stats(self):
        """Вывод статистики"""
        self.logger.info("📈 Статистика обработки:")
        self.logger.info(f"   ├─ Входных доменов: {self.stats['total_raw']:,}")
        self.logger.info(f"   ├─ Выходных доменов: {self.stats['normal'] + self.stats['blacklisted']:,}")
        self.logger.info(f"   ├─ Whitelist: {self.stats['whitelisted']}")
        self.logger.info(f"   ├─ Wildcard whitelist: {self.stats['wildcard_whitelisted']}")
        self.logger.info(f"   └─ Blacklist (force): {self.stats['blacklisted']}")
    
    def save_stats(self):
        """Сохранение статистики в JSON"""
        stats_data = {
            "timestamp": datetime.now().isoformat(),
            "version": __version__,
            "stats": dict(self.stats),
            "config": {
                "timeout": CONFIG.timeout,
                "sources": len(CONFIG.sources)
            }
        }
        with open(FILES.stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats_data, f, indent=2)


# ============================================================================
# Экспорт в различные форматы
# ============================================================================

class Exporter:
    """Экспорт блоклиста в различные форматы"""
    
    @staticmethod
    def backup():
        """Создание бэкапа существующего файла"""
        if FILES.output_hosts.exists():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = FILES.backup_dir / f"hosts_{timestamp}.txt"
            shutil.copy2(FILES.output_hosts, backup_path)
            return backup_path
        return None
    
    @staticmethod
    def export_hosts(domains: Set[str], path: Path, source_name: str = "HaGeZi PRO"):
        """Экспорт в формат hosts"""
        with open(path, 'w', encoding='utf-8') as f:
            # Заголовок
            f.write(
                f"# ================================================================\n"
                f"# DNS Blocklist Manager v{__version__}\n"
                f"# Source: {source_name}\n"
                f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"# Total domains: {len(domains):,}\n"
                f"# ================================================================\n"
                f"#\n"
                f"# Created by: DNS Blocklist Manager\n"
                f"# Repository: https://github.com/yourname/dns-blocklist-manager\n"
                f"# License: MIT\n"
                f"#\n"
                f"# Usage: Add these entries to your /etc/hosts file\n"
                f"# ================================================================\n\n"
            )
            
            # Основные домены
            for domain in sorted(domains):
                f.write(f"0.0.0.0 {domain}\n")
    
    @staticmethod
    def export_domains(domains: Set[str], path: Path):
        """Экспорт в формат plain domains (одна строка - один домен)"""
        with open(path, 'w', encoding='utf-8') as f:
            for domain in sorted(domains):
                f.write(f"{domain}\n")
    
    @staticmethod
    def export_adblock(domains: Set[str], path: Path):
        """Экспорт в формат AdBlock Plus"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"[Adblock Plus 2.0]\n")
            f.write(f"! Title: Custom Blocklist v{__version__}\n")
            f.write(f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! Number of rules: {len(domains):,}\n")
            f.write(f"! ==========================================\n\n")
            for domain in sorted(domains):
                f.write(f"||{domain}^\n")


# ============================================================================
# PID менеджер для предотвращения дублирования
# ============================================================================

class PIDManager:
    """Управление PID файлом для предотвращения множественных запусков"""
    
    def __init__(self, pid_file: Path):
        self.pid_file = pid_file
        self.pid = os.getpid()
    
    def acquire(self) -> bool:
        """Захват блокировки"""
        if self.pid_file.exists():
            try:
                old_pid = int(self.pid_file.read_text().strip())
                # Проверка, жив ли процесс
                os.kill(old_pid, 0)
                print(f"❌ Процесс уже запущен (PID: {old_pid})")
                return False
            except (OSError, ValueError):
                # Процесс мертв, можно удалить файл
                self.pid_file.unlink()
        
        self.pid_file.write_text(str(self.pid))
        return True
    
    def release(self):
        """Освобождение блокировки"""
        try:
            if self.pid_file.exists() and int(self.pid_file.read_text().strip()) == self.pid:
                self.pid_file.unlink()
        except (OSError, ValueError):
            pass


# ============================================================================
# Обработчики сигналов
# ============================================================================

class SignalHandler:
    """Грациозная обработка сигналов"""
    
    def __init__(self):
        self.shutdown_event = asyncio.Event()
        
    def setup(self):
        """Установка обработчиков"""
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: self.shutdown_event.set())
    
    async def wait_for_shutdown(self):
        """Ожидание сигнала завершения"""
        await self.shutdown_event.wait()


# ============================================================================
# Основная функция с прогресс-баром
# ============================================================================

async def main() -> int:
    """Главная асинхронная функция"""
    
    # Проверка PID
    pid_manager = PIDManager(FILES.pid_file)
    if not pid_manager.acquire():
        return 1
    atexit.register(pid_manager.release)
    
    # Логгер
    logger = EliteLogger(FILES.log_file, verbose=os.getenv("DEBUG", "0") == "1")
    
    # Приветствие
    print(f"\n{'='*60}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"{'='*60}")
    print(f"📅 Время запуска: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Источников: {len([s for s in CONFIG.sources if s.enabled])}")
    print(f"{'='*60}\n")
    
    logger.info(f"Запуск DNS Blocklist Manager v{__version__}")
    
    try:
        # Обработка сигналов
        signal_handler = SignalHandler()
        signal_handler.setup()
        
        manager = BlocklistManager(logger)
        exporter = Exporter()
        
        # Шаг 1: Бэкап
        logger.progress("Шаг 1/4: Создание бэкапа")
        backup_path = exporter.backup()
        if backup_path:
            logger.info(f"Бэкап создан: {backup_path}")
        
        # Шаг 2: Загрузка
        logger.progress("Шаг 2/4: Загрузка блоклистов")
        filtered_domains = await manager.build(CONFIG.sources, use_cache=CONFIG.enable_cache)
        
        # Проверка лимита
        if len(filtered_domains) > CONFIG.max_domains:
            logger.warning(f"Превышен лимит доменов ({len(filtered_domains):,} > {CONFIG.max_domains:,})")
        
        # Шаг 3: Экспорт
        logger.progress("Шаг 3/4: Экспорт в файлы")
        exporter.export_hosts(filtered_domains, FILES.output_hosts)
        logger.success(f"hosts.txt: {len(filtered_domains):,} доменов")
        
        # Дополнительный экспорт для совместимости
        domains_file = FILES.output_hosts.parent / "domains.txt"
        exporter.export_domains(filtered_domains, domains_file)
        logger.info(f"domains.txt: {len(filtered_domains):,} доменов")
        
        # Шаг 4: Статистика
        logger.progress("Шаг 4/4: Сохранение статистики")
        manager.save_stats()
        
        # Финальный вывод
        print(f"\n{'='*60}")
        print(f"✅ СБОРКА УСПЕШНО ЗАВЕРШЕНА")
        print(f"{'='*60}")
        print(f"📊 ИТОГО ЗАБЛОКИРОВАНО: {len(filtered_domains):,} доменов")
        print(f"\n📁 Выходные файлы:")
        
        if FILES.output_hosts.exists():
            size = FILES.output_hosts.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size / 1024 / 1024:.2f} MB"
            else:
                size_str = f"{size / 1024:.2f} KB"
            print(f"   • hosts.txt: {size_str}")
        
        if domains_file.exists():
            size = domains_file.stat().st_size
            print(f"   • domains.txt: {size / 1024:.2f} KB")
        
        print(f"{'='*60}")
        
        logger.info(f"Сборка завершена: {len(filtered_domains):,} доменов")
        return 0
        
    except asyncio.CancelledError:
        logger.warning("Операция отменена")
        return 130
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        if os.getenv("DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


def cli_entry():
    """Точка входа для CLI"""
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Прервано пользователем")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Фатальная ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli_entry()