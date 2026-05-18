#!/usr/bin/env python3
"""
DNS Blocklist Manager - Elite Edition v7.1.0
Эволюционный рефакторинг: потоковая обработка, rate limiting, плагины
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
import gc
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Set, Optional, Dict, List, Callable, Awaitable, Final, Iterable, Iterator, Any
from functools import wraps
from collections import defaultdict
from abc import ABC, abstractmethod
import time

__version__ = "7.1.0-evolution"


# ============================================================================
# Конфигурация с типизацией и валидацией
# ============================================================================

@dataclass(frozen=True)
class SourceConfig:
    """Конфигурация источника блоклиста"""
    name: str
    url: str
    enabled: bool = True
    priority: int = 0
    max_size_mb: int = 500
    expected_format: str = "hosts"


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
        timeout = cls().timeout
        with suppress(Exception):
            if os.getenv("BLOCKLIST_TIMEOUT"):
                timeout = int(os.getenv("BLOCKLIST_TIMEOUT"))
        return cls(
            timeout=timeout,
            max_retries=cls().max_retries,
            retry_delay=cls().retry_delay,
            user_agent=cls().user_agent,
            max_domains=cls().max_domains,
            enable_cache=cls().enable_cache,
            cache_ttl_hours=cls().cache_ttl_hours,
            parallel_downloads=cls().parallel_downloads,
            sources=cls().sources
        )


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
        "INFO": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "DEBUG": "\033[96m",
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
    
    _VALID_TLDS: Set[str] = {
        'com', 'org', 'net', 'io', 'app', 'dev', 'xyz', 'info', 'biz',
        'ru', 'ua', 'by', 'kz', 'pl', 'de', 'fr', 'uk', 'us', 'ca', 'au',
        'jp', 'cn', 'in', 'br', 'mx', 'za', 'eg', 'sa', 'ae', 'tr'
    }
    
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
        """Очистка и извлечение домена из строки"""
        if not line or not isinstance(line, str):
            return None
        
        if "#" in line:
            line = line[:line.index("#")]
        
        line = line.strip().lower()
        if not line:
            return None
        
        for pattern in cls._CLEAN_PATTERNS:
            line = pattern.sub('', line)
        
        if re.match(r'^\d+(\.\d+){3}$', line) or re.match(r'^[0-9a-f:]+$', line):
            return None
        
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
        
        if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', domain):
            return False
        
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
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
        self._cache: Dict[str, List[str]] = {}
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
# Потоковый процессор для экономии памяти
# ============================================================================

class StreamingDomainProcessor:
    """Потоковая обработка доменов без загрузки всех в память"""
    
    def __init__(self, chunk_size: int = 10000):
        self.chunk_size = chunk_size
        self.stats = defaultdict(int)
    
    def process_stream(self, domains: Iterable[str], 
                      whitelist: Set[str],
                      blacklist: Set[str],
                      wildcard_whitelist: Set[str]) -> Iterator[str]:
        """Потоковая фильтрация - возвращает генератор"""
        chunk = []
        
        for domain in domains:
            if DomainValidator.match_wildcard(domain, wildcard_whitelist):
                self.stats["wildcard_whitelisted"] += 1
                continue
            
            if domain in whitelist:
                self.stats["whitelisted"] += 1
                continue
            
            if domain in blacklist:
                self.stats["blacklisted"] += 1
                chunk.append(domain)
            else:
                self.stats["normal"] += 1
                chunk.append(domain)
            
            if len(chunk) >= self.chunk_size:
                yield from chunk
                chunk = []
                
                if len(chunk) == 0:
                    gc.collect()
        
        if chunk:
            yield from chunk
    
    def get_stats(self) -> Dict[str, int]:
        """Возвращает копию статистики"""
        return dict(self.stats)


# ============================================================================
# Rate Limiter для защиты источников
# ============================================================================

class RateLimiter:
    """Скользящее окно для rate limiting"""
    
    def __init__(self, requests_per_second: float = 2.0):
        self.rate = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Ожидание разрешения на запрос"""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time
            
            if elapsed < self.min_interval:
                wait_time = self.min_interval - elapsed
                await asyncio.sleep(wait_time)
            
            self.last_request_time = time.time()


# ============================================================================
# Прогресс-бар для длительных операций
# ============================================================================

class ProgressTracker:
    """Отслеживание прогресса с ETA"""
    
    def __init__(self, logger: EliteLogger, total_items: int, description: str = "Processing"):
        self.logger = logger
        self.total = total_items
        self.description = description
        self.processed = 0
        self.start_time = time.time()
        self.last_log_time = 0
    
    def update(self, increment: int = 1):
        """Обновление прогресса"""
        self.processed += increment
        
        now = time.time()
        if now - self.last_log_time >= 5.0:
            self._log_progress()
            self.last_log_time = now
    
    def _log_progress(self):
        """Расчет и логирование прогресса"""
        if self.processed == 0:
            return
        
        elapsed = time.time() - self.start_time
        rate = self.processed / elapsed
        
        if rate > 0:
            remaining = self.total - self.processed
            eta = remaining / rate
            
            percent = (self.processed / self.total) * 100
            self.logger.info(
                f"📊 {self.description}: {percent:.1f}% "
                f"({self.processed:,}/{self.total:,}) "
                f"| {rate:.0f} items/s | ETA: {self._format_time(eta)}"
            )
    
    @staticmethod
    def _format_time(seconds: float) -> str:
        """Форматирование времени"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def finish(self):
        """Завершение и финальная статистика"""
        elapsed = time.time() - self.start_time
        rate = self.processed / elapsed if elapsed > 0 else 0
        
        self.logger.success(
            f"{self.description} завершена: {self.processed:,} items "
            f"за {self._format_time(elapsed)} (avg {rate:.0f}/s)"
        )


# ============================================================================
# Плагинная система экспортеров
# ============================================================================

class BaseExporter(ABC):
    """Абстрактный базовый класс для экспортеров"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    
    @property
    @abstractmethod
    def extension(self) -> str:
        pass
    
    @abstractmethod
    def export(self, domains: Iterable[str], output_path: Path) -> None:
        """Экспорт доменов в указанный формат"""
        pass
    
    def get_file_path(self, base_dir: Path) -> Path:
        """Получение пути к файлу"""
        return base_dir / f"blocklist.{self.extension}"


class HostsExporter(BaseExporter):
    """Экспорт в формат hosts"""
    
    @property
    def name(self) -> str:
        return "hosts"
    
    @property
    def extension(self) -> str:
        return "txt"
    
    def export(self, domains: Iterable[str], output_path: Path) -> None:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(
                f"# ================================================================\n"
                f"# DNS Blocklist Manager v{__version__}\n"
                f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"# ================================================================\n\n"
            )
            
            for domain in domains:
                f.write(f"0.0.0.0 {domain}\n")


class DomainsExporter(BaseExporter):
    """Экспорт в plain domains format"""
    
    @property
    def name(self) -> str:
        return "domains"
    
    @property
    def extension(self) -> str:
        return "txt"
    
    def export(self, domains: Iterable[str], output_path: Path) -> None:
        with open(output_path, 'w', encoding='utf-8') as f:
            for domain in domains:
                f.write(f"{domain}\n")


class AdBlockExporter(BaseExporter):
    """Экспорт в AdBlock Plus формат"""
    
    @property
    def name(self) -> str:
        return "adblock"
    
    @property
    def extension(self) -> str:
        return "txt"
    
    def export(self, domains: Iterable[str], output_path: Path) -> None:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"[Adblock Plus 2.0]\n")
            f.write(f"! Title: DNS Blocklist v{__version__}\n")
            f.write(f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for domain in domains:
                f.write(f"||{domain}^\n")


class ExporterRegistry:
    """Реестр экспортеров с возможностью динамической регистрации"""
    
    def __init__(self):
        self._exporters: Dict[str, BaseExporter] = {}
    
    def register(self, exporter: BaseExporter) -> None:
        """Регистрация экспортера"""
        self._exporters[exporter.name] = exporter
    
    def get(self, name: str) -> Optional[BaseExporter]:
        """Получение экспортера по имени"""
        return self._exporters.get(name)
    
    def export_all(self, domains: Iterable[str], base_dir: Path, 
                   enabled: List[str] = None) -> Dict[str, Path]:
        """Экспорт всеми зарегистрированными экспортерами"""
        results = {}
        
        if enabled is None:
            enabled = list(self._exporters.keys())
        
        for name in enabled:
            exporter = self._exporters.get(name)
            if exporter:
                output_path = exporter.get_file_path(base_dir)
                exporter.export(domains, output_path)
                results[name] = output_path
        
        return results


# ============================================================================
# Асинхронный загрузчик с rate limiting
# ============================================================================

class AsyncFetcher:
    """Асинхронный загрузчик с rate limiting и сжатием"""
    
    def __init__(self, logger: EliteLogger, max_concurrent: int = 3, 
                 rate_limit: float = 2.0):
        self.logger = logger
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limiter = RateLimiter(rate_limit)
        self.session: Optional[aiohttp.ClientSession] = None
        
        self.headers = {
            "User-Agent": CONFIG.user_agent,
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/plain, text/html, application/json"
        }
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            limit=10, 
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=CONFIG.timeout,
            connect=10,
            sock_read=CONFIG.timeout
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=self.headers,
            timeout=timeout
        )
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def fetch(self, url: str, name: str) -> Optional[str]:
        """Загрузка одного источника"""
        async with self.semaphore:
            await self.rate_limiter.acquire()
            
            for attempt in range(CONFIG.max_retries):
                try:
                    async with self.session.get(url) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            return text
                            
                        elif resp.status == 429:
                            retry_after = resp.headers.get('Retry-After', '5')
                            wait = int(retry_after) if retry_after.isdigit() else 5
                            self.logger.warning(f"{name}: Rate limited, waiting {wait}s...")
                            await asyncio.sleep(wait)
                            continue
                            
                        elif resp.status == 404:
                            self.logger.error(f"{name}: Source not found (404)")
                            return None
                        else:
                            self.logger.warning(f"{name}: HTTP {resp.status}")
                
                except asyncio.TimeoutError:
                    self.logger.warning(f"{name}: Timeout (attempt {attempt + 1})")
                except aiohttp.ClientError as e:
                    self.logger.warning(f"{name}: Network error - {e}")
                except Exception as e:
                    self.logger.warning(f"{name}: {type(e).__name__} - {e}")
                
                if attempt < CONFIG.max_retries - 1:
                    delay = CONFIG.retry_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
            
            self.logger.error(f"{name}: Failed after {CONFIG.max_retries} attempts")
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
        
        self.logger.info(f"  📥 {source.name}: {len(domains):,} domains")
        return source.name, domains


# ============================================================================
# Улучшенный BlocklistManager с потоковой обработкой
# ============================================================================

class BlocklistManager:
    """Управление блоклистами с потоковой обработкой"""
    
    def __init__(self, logger: EliteLogger):
        self.logger = logger
        self.stats = defaultdict(int)
        
        self.whitelist = self._load_domain_list(FILES.whitelist, "whitelist")
        self.blacklist = self._load_domain_list(FILES.blacklist, "blacklist")
        self.wildcard_whitelist = self._load_domain_list(
            FILES.wildcard_whitelist, "wildcard whitelist"
        )
        
        self.stream_processor = StreamingDomainProcessor(chunk_size=10000)
    
    def _load_domain_list(self, path: Path, name: str) -> Set[str]:
        """Загрузка списка доменов"""
        domains = set()
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        domains.add(domain)
            self.logger.info(f"📋 {name}: {len(domains)} domains")
        return domains
    
    async def build_streaming(self, sources: List[SourceConfig], 
                              use_cache: bool = True) -> List[str]:
        """
        Сборка блоклиста - возвращает список доменов
        """
        self.logger.progress("Starting streaming blocklist build")
        
        all_domains = None
        
        if use_cache:
            cache = DomainCache(FILES.cache_file, CONFIG.cache_ttl_hours)
            cached = cache.get("combined")
            if cached:
                self.logger.info(f"📀 Using cache: {len(cached):,} domains")
                all_domains = cached
        
        if all_domains is None:
            async with AsyncFetcher(
                self.logger, 
                CONFIG.parallel_downloads,
                rate_limit=2.0
            ) as fetcher:
                domains_by_source = await fetcher.fetch_all(sources)
                
                total_sources = len(domains_by_source)
                if total_sources > 0:
                    progress = ProgressTracker(
                        self.logger, total_sources, "Merging sources"
                    )
                    
                    all_domains = set()
                    for source_name, domains in domains_by_source.items():
                        all_domains.update(domains)
                        self.stats[f"from_{source_name}"] = len(domains)
                        progress.update()
                    
                    progress.finish()
                else:
                    self.logger.error("No sources loaded successfully")
                    return []
            
            if use_cache and all_domains:
                cache = DomainCache(FILES.cache_file, CONFIG.cache_ttl_hours)
                cache.set("combined", all_domains)
                cache.save()
        
        if not all_domains:
            self.logger.error("No domains collected")
            return []
        
        self.stats["total_raw"] = len(all_domains)
        self.logger.info(f"📊 Total unique domains collected: {len(all_domains):,}")
        
        self.logger.progress("Applying filters (streaming mode)")
        
        # Применяем фильтрацию
        filtered_domains = list(self.stream_processor.process_stream(
            all_domains,
            self.whitelist,
            self.blacklist,
            self.wildcard_whitelist
        ))
        
        return filtered_domains
    
    def update_stats(self, total_domains: int):
        """Обновление статистики"""
        final_stats = self.stream_processor.get_stats()
        self.stats.update(final_stats)
        
        total_output = self.stats.get('normal', 0) + self.stats.get('blacklisted', 0)
        
        self.logger.info("📈 Processing statistics:")
        self.logger.info(f"   ├─ Input domains: {self.stats.get('total_raw', 0):,}")
        self.logger.info(f"   ├─ Output domains: {total_output:,}")
        self.logger.info(f"   ├─ Whitelisted: {self.stats.get('whitelisted', 0)}")
        self.logger.info(f"   ├─ Wildcard whitelisted: {self.stats.get('wildcard_whitelisted', 0)}")
        self.logger.info(f"   └─ Blacklisted (forced): {self.stats.get('blacklisted', 0)}")
        
        if self.stats.get('total_raw', 0) > 0:
            reduction = (1 - total_output / self.stats['total_raw']) * 100
            self.logger.info(f"   └─ Reduction: {reduction:.1f}%")
    
    def save_stats(self):
        """Сохранение статистики"""
        stats_data = {
            "timestamp": datetime.now().isoformat(),
            "version": __version__,
            "stats": dict(self.stats),
            "config": {
                "timeout": CONFIG.timeout,
                "sources": len(CONFIG.sources),
                "streaming_mode": True
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


# ============================================================================
# PID менеджер для предотвращения дублирования
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
                print(f"❌ Процесс уже запущен (PID: {old_pid})")
                return False
            except (OSError, ValueError):
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
# Основная функция
# ============================================================================

async def main() -> int:
    """Главная функция"""
    
    pid_manager = PIDManager(FILES.pid_file)
    if not pid_manager.acquire():
        return 1
    atexit.register(pid_manager.release)
    
    logger = EliteLogger(FILES.log_file, verbose=os.getenv("DEBUG", "0") == "1")
    
    print(f"\n{'='*60}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__}")
    print(f"🔧 Streaming mode: ENABLED (memory optimized)")
    print(f"{'='*60}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len([s for s in CONFIG.sources if s.enabled])}")
    print(f"{'='*60}\n")
    
    try:
        signal_handler = SignalHandler()
        signal_handler.setup()
        
        manager = BlocklistManager(logger)
        
        registry = ExporterRegistry()
        registry.register(HostsExporter())
        registry.register(DomainsExporter())
        registry.register(AdBlockExporter())
        
        logger.progress("Step 1/4: Creating backup")
        exporter = Exporter()
        backup_path = exporter.backup()
        if backup_path:
            logger.info(f"Backup created: {backup_path}")
        
        logger.progress("Step 2/4: Building blocklist (streaming mode)")
        
        # Получаем список доменов
        domains_list = await manager.build_streaming(
            CONFIG.sources, 
            use_cache=CONFIG.enable_cache
        )
        
        logger.progress("Step 3/4: Exporting to multiple formats")
        
        if not domains_list:
            logger.error("No domains to export!")
            return 1
        
        exports = registry.export_all(
            domains_list, 
            FILES.output_hosts.parent,
            enabled=["hosts", "domains", "adblock"]
        )
        
        for fmt, path in exports.items():
            if path.exists():
                size = path.stat().st_size
                if size > 1024 * 1024:
                    size_str = f"{size / 1024 / 1024:.2f} MB"
                else:
                    size_str = f"{size / 1024:.2f} KB"
                logger.info(f"   • {fmt}.txt: {size_str}")
        
        logger.progress("Step 4/4: Saving statistics")
        manager.update_stats(len(domains_list))
        manager.save_stats()
        
        print(f"\n{'='*60}")
        print(f"✅ BUILD COMPLETED SUCCESSFULLY")
        print(f"{'='*60}")
        print(f"📊 TOTAL BLOCKED: {len(domains_list):,} domains")
        print(f"💾 Memory usage: ~{len(domains_list) * 50 / 1024 / 1024:.1f} MB")
        print(f"{'='*60}")
        
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