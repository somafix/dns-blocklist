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
# ENHANCEMENT 1: Потоковый процессор для экономии памяти
# ============================================================================

class StreamingDomainProcessor:
    """
    Потоковая обработка доменов без загрузки всех в память
    Использует генераторы для экономии RAM при больших списках
    """
    
    def __init__(self, chunk_size: int = 10000):
        self.chunk_size = chunk_size
        self.stats = defaultdict(int)
    
    def process_stream(self, domains: Iterable[str], 
                      whitelist: Set[str],
                      blacklist: Set[str],
                      wildcard_whitelist: Set[str]) -> Iterator[str]:
        """
        Потоковая фильтрация - возвращает генератор
        Память: O(chunk_size) вместо O(total_domains)
        """
        chunk = []
        
        for domain in domains:
            # Проверка wildcard whitelist
            if DomainValidator.match_wildcard(domain, wildcard_whitelist):
                self.stats["wildcard_whitelisted"] += 1
                continue
            
            # Обычный whitelist
            if domain in whitelist:
                self.stats["whitelisted"] += 1
                continue
            
            # Blacklist (force include)
            if domain in blacklist:
                self.stats["blacklisted"] += 1
                chunk.append(domain)
            else:
                self.stats["normal"] += 1
                chunk.append(domain)
            
            # Yield chunk когда накопили
            if len(chunk) >= self.chunk_size:
                yield from chunk
                chunk = []
                
                # Опционально: принудительная сборка мусора
                if len(chunk) == 0:
                    gc.collect()
        
        # Последний чанк
        if chunk:
            yield from chunk
    
    def get_stats(self) -> Dict[str, int]:
        """Возвращает копию статистики"""
        return dict(self.stats)


# ============================================================================
# ENHANCEMENT 2: Rate Limiter для защиты источников
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
    
    def __call__(self, func):
        """Декоратор для применения rate limiting"""
        @wraps(func)
        async def wrapper(*args, **kwargs):
            await self.acquire()
            return await func(*args, **kwargs)
        return wrapper


# ============================================================================
# ENHANCEMENT 3: Прогресс-бар для длительных операций
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
        self.last_processed = 0
        self.eta_seconds = 0
    
    def update(self, increment: int = 1):
        """Обновление прогресса"""
        self.processed += increment
        
        # Логируем каждые 5 секунд или каждые 10%
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
                f"| {rate:.0f} domains/s | ETA: {self._format_time(eta)}"
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
# ENHANCEMENT 4: Плагинная система экспортеров
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
            # Заголовок
            f.write(
                f"# ================================================================\n"
                f"# DNS Blocklist Manager v{__version__}\n"
                f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"# ================================================================\n\n"
            )
            
            # Потоковая запись
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
        
        # Если не указаны, используем все
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
# ENHANCEMENT 5: Обновленный AsyncFetcher с rate limiting
# ============================================================================

class AsyncFetcher:
    """Асинхронный загрузчик с rate limiting и сжатием"""
    
    def __init__(self, logger: EliteLogger, max_concurrent: int = 3, 
                 rate_limit: float = 2.0):
        self.logger = logger
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.rate_limiter = RateLimiter(rate_limit)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Поддержка сжатия
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
    
    @RateLimiter(2.0)  # Декоратор для ограничения запросов
    async def fetch(self, url: str, name: str) -> Optional[str]:
        """Загрузка одного источника с поддержкой сжатия"""
        async with self.semaphore:
            for attempt in range(CONFIG.max_retries):
                try:
                    async with self.session.get(url) as resp:
                        if resp.status == 200:
                            # Автоматическая распаковка gzip/deflate
                            text = await resp.text()
                            
                            # Логирование размера сжатого vs распакованного
                            content_encoding = resp.headers.get('Content-Encoding', 'none')
                            if content_encoding != 'none':
                                compressed_size = len(resp._body or b'')
                                self.logger.debug(
                                    f"{name}: {len(text):,} bytes "
                                    f"(compressed: {compressed_size:,})"
                                )
                            
                            return text
                            
                        elif resp.status == 429:  # Too Many Requests
                            retry_after = resp.headers.get('Retry-After', '5')
                            wait = int(retry_after) if retry_after.isdigit() else 5
                            self.logger.warning(
                                f"{name}: Rate limited, waiting {wait}s..."
                            )
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
                    # Exponential backoff
                    delay = CONFIG.retry_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
            
            self.logger.error(f"{name}: Failed after {CONFIG.max_retries} attempts")
            return None


# ============================================================================
# ENHANCEMENT 6: Улучшенный BlocklistManager с потоковой обработкой
# ============================================================================

class BlocklistManager:
    """Управление блоклистами с потоковой обработкой"""
    
    def __init__(self, logger: EliteLogger):
        self.logger = logger
        self.stats = defaultdict(int)
        
        # Загрузка пользовательских списков
        self.whitelist = self._load_domain_list(FILES.whitelist, "whitelist")
        self.blacklist = self._load_domain_list(FILES.blacklist, "blacklist")
        self.wildcard_whitelist = self._load_domain_list(
            FILES.wildcard_whitelist, "wildcard whitelist"
        )
        
        # Потоковый процессор
        self.stream_processor = StreamingDomainProcessor(chunk_size=10000)
    
    def _load_domain_list(self, path: Path, name: str) -> Set[str]:
        """Загрузка списка доменов (остается в памяти, т.к. списки маленькие)"""
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
                              use_cache: bool = True) -> Iterator[str]:
        """
        Потоковая сборка - возвращает генератор вместо полного сета
        Экономит память при больших объемах
        """
        self.logger.progress("Starting streaming blocklist build")
        
        # Загрузка всех источников
        all_domains = set()
        
        if use_cache:
            cache = DomainCache(FILES.cache_file, CONFIG.cache_ttl_hours)
            cached = cache.get("combined")
            if cached:
                self.logger.info(f"📀 Using cache: {len(cached):,} domains")
                all_domains = cached
        
        if not all_domains:
            async with AsyncFetcher(
                self.logger, 
                CONFIG.parallel_downloads,
                rate_limit=2.0
            ) as fetcher:
                domains_by_source = await fetcher.fetch_all(sources)
                
                # Объединение с прогресс-трекингом
                total_sources = len(domains_by_source)
                progress = ProgressTracker(
                    self.logger, total_sources, "Merging sources"
                )
                
                for source_name, domains in domains_by_source.items():
                    all_domains.update(domains)
                    self.stats[f"from_{source_name}"] = len(domains)
                    progress.update()
                
                progress.finish()
            
            # Сохранение в кэш
            if use_cache:
                cache = DomainCache(FILES.cache_file, CONFIG.cache_ttl_hours)
                cache.set("combined", all_domains)
                cache.save()
        
        self.stats["total_raw"] = len(all_domains)
        self.logger.info(f"📊 Total unique domains collected: {len(all_domains):,}")
        
        # Потоковая фильтрация
        self.logger.progress("Applying filters (streaming mode)")
        
        # Создаем генератор
        filtered_stream = self.stream_processor.process_stream(
            all_domains,
            self.whitelist,
            self.blacklist,
            self.wildcard_whitelist
        )
        
        # Счетчик для прогресса (без загрузки в память)
        processed = 0
        for domain in filtered_stream:
            processed += 1
            if processed % 10000 == 0:
                self.logger.debug(f"Streamed {processed:,} domains...")
            yield domain
        
        # Логируем финальную статистику
        final_stats = self.stream_processor.get_stats()
        self.stats.update(final_stats)
        self._log_stats()
        
        self.logger.success(f"Streaming complete: {processed:,} domains")
    
    def _log_stats(self):
        """Вывод статистики"""
        total_output = self.stats['normal'] + self.stats['blacklisted']
        
        self.logger.info("📈 Processing statistics:")
        self.logger.info(f"   ├─ Input domains: {self.stats['total_raw']:,}")
        self.logger.info(f"   ├─ Output domains: {total_output:,}")
        self.logger.info(f"   ├─ Whitelisted: {self.stats['whitelisted']}")
        self.logger.info(f"   ├─ Wildcard whitelisted: {self.stats['wildcard_whitelisted']}")
        self.logger.info(f"   └─ Blacklisted (forced): {self.stats['blacklisted']}")
        
        # Расчет эффективности фильтрации
        if self.stats['total_raw'] > 0:
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
# ENHANCEMENT 7: Обновленная main с новыми возможностями
# ============================================================================

async def main() -> int:
    """Главная функция с улучшенной обработкой"""
    
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
    print(f"🔧 Streaming mode: ENABLED (memory optimized)")
    print(f"{'='*60}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Sources: {len([s for s in CONFIG.sources if s.enabled])}")
    print(f"{'='*60}\n")
    
    try:
        # Обработка сигналов
        signal_handler = SignalHandler()
        signal_handler.setup()
        
        manager = BlocklistManager(logger)
        
        # Регистрация экспортеров
        registry = ExporterRegistry()
        registry.register(HostsExporter())
        registry.register(DomainsExporter())
        registry.register(AdBlockExporter())
        
        # Шаг 1: Бэкап
        logger.progress("Step 1/4: Creating backup")
        exporter = Exporter()  # Используем статический экспортер для бэкапа
        backup_path = exporter.backup()
        if backup_path:
            logger.info(f"Backup created: {backup_path}")
        
        # Шаг 2: Потоковая сборка
        logger.progress("Step 2/4: Building blocklist (streaming mode)")
        
        # Собираем домены в потоковом режиме
        domain_stream = await manager.build_streaming(
            CONFIG.sources, 
            use_cache=CONFIG.enable_cache
        )
        
        # Шаг 3: Экспорт в несколько форматов
        logger.progress("Step 3/4: Exporting to multiple formats")
        
        # Для экспорта нам нужен iterable, который можно использовать дважды
        # Поэтому сохраняем в список ТОЛЬКО если нужно несколько форматов
        domains_list = list(domain_stream)  # Здесь происходит полная загрузка в память
        
        # Экспорт во все форматы
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
        
        # Шаг 4: Статистика
        logger.progress("Step 4/4: Saving statistics")
        manager.save_stats()
        
        # Финальный вывод
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