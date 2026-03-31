#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - ENTERPRISE SECURITY HARDENED (v15.1.0)

Production-grade blocklist builder with:
- Enhanced deduplication using Bloom filters
- Improved signal handling and graceful shutdown
- Better resource management
- Comprehensive error recovery
"""

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import tempfile
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache, wraps
from pathlib import Path
from typing import (
    Any, AsyncIterator, Dict, Final, List, Optional, 
    Set, Tuple, Union, cast, ClassVar, Callable, Awaitable, 
    Iterator, Deque, AsyncGenerator, TypeVar, Generic
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientResponse, ClientTimeout, ClientError
from aiohttp.client_exceptions import ClientConnectorError, ServerTimeoutError

# Для Bloom filter - опциональная зависимость
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    # Fallback на обычный set

# ============================================================================
# УЛУЧШЕННАЯ КОНФИГУРАЦИЯ
# ============================================================================

@dataclass(frozen=True)
class AppConfig:
    """Immutable configuration from environment variables"""
    
    # Timeouts
    HTTP_TIMEOUT: Final[int] = int(os.getenv("DNSBL_HTTP_TIMEOUT", "15"))
    DNS_TIMEOUT: Final[int] = int(os.getenv("DNSBL_DNS_TIMEOUT", "5"))
    GRACEFUL_SHUTDOWN_TIMEOUT: Final[int] = int(os.getenv("DNSBL_SHUTDOWN_TIMEOUT", "10"))
    DNS_REBINDING_DELAY: Final[float] = float(os.getenv("DNSBL_REBINDING_DELAY", "0.5"))
    DNS_REBINDING_CHECKS: Final[int] = int(os.getenv("DNSBL_REBINDING_CHECKS", "2"))
    
    # Concurrency
    MAX_CONCURRENT_DOWNLOADS: Final[int] = int(os.getenv("DNSBL_MAX_CONCURRENT", "5"))
    CONNECTION_LIMIT_PER_HOST: Final[int] = int(os.getenv("DNSBL_CONN_LIMIT", "2"))
    
    # Retry strategy
    MAX_RETRIES: Final[int] = int(os.getenv("DNSBL_MAX_RETRIES", "3"))
    RETRY_BACKOFF_BASE: Final[float] = float(os.getenv("DNSBL_RETRY_BACKOFF", "1.0"))
    RETRY_MAX_BACKOFF: Final[float] = float(os.getenv("DNSBL_MAX_BACKOFF", "30.0"))
    
    # Performance limits
    MAX_DOMAINS_TOTAL: Final[int] = int(os.getenv("DNSBL_MAX_DOMAINS", "1000000"))
    MAX_FILE_SIZE_MB: Final[int] = int(os.getenv("DNSBL_MAX_FILE_MB", "50"))
    STREAM_BUFFER_SIZE: Final[int] = int(os.getenv("DNSBL_BUFFER_SIZE", "8192"))
    
    # Domain validation
    MAX_DOMAIN_LEN: Final[int] = 253
    MAX_LABEL_LEN: Final[int] = 63
    MIN_DOMAIN_LEN: Final[int] = 3
    MAX_INPUT_LEN: Final[int] = 1024  # ReDoS protection
    
    # Cache settings
    DNS_CACHE_SIZE: Final[int] = 10000
    DNS_CACHE_TTL: Final[int] = 300
    AI_CACHE_SIZE: Final[int] = 10000
    AI_CACHE_TTL: Final[int] = 3600
    
    # Performance tuning - НОВЫЕ ПАРАМЕТРЫ
    BLOOM_FILTER_ERROR_RATE: Final[float] = float(os.getenv("DNSBL_BLOOM_ERROR_RATE", "0.001"))
    BLOOM_FILTER_CAPACITY: Final[int] = int(os.getenv("DNSBL_BLOOM_CAPACITY", "1000000"))
    FLUSH_INTERVAL: Final[int] = int(os.getenv("DNSBL_FLUSH_INTERVAL", "10000"))
    USE_BLOOM_FILTER: Final[bool] = os.getenv("DNSBL_USE_BLOOM", "true").lower() == "true" and BLOOM_AVAILABLE
    
    # Security - Blocked IP ranges (RFC 1918 and special use)
    BLOCKED_IP_RANGES: Final[Tuple[str, ...]] = (
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96',
        '100.64.0.0/10', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'
    )
    
    # Allowed domains for download sources (SSRF protection)
    ALLOWED_DOMAINS: Final[Set[str]] = {
        'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
        'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
        'hole.cert.pl', 'github.com', 'gitlab.com', 'bitbucket.org'
    }
    
    # AI Detection threshold
    AI_CONFIDENCE_THRESHOLD: Final[float] = 0.65
    
    @classmethod
    def validate(cls) -> None:
        """Validate configuration values"""
        assert cls.HTTP_TIMEOUT > 0, "HTTP_TIMEOUT must be positive"
        assert cls.MAX_CONCURRENT_DOWNLOADS > 0, "MAX_CONCURRENT_DOWNLOADS must be positive"
        assert 0 <= cls.AI_CONFIDENCE_THRESHOLD <= 1, "AI_CONFIDENCE_THRESHOLD must be between 0 and 1"
        assert cls.MAX_RETRIES >= 0, "MAX_RETRIES must be non-negative"
        
        # Validate blocked IP ranges
        for net in cls.BLOCKED_IP_RANGES:
            try:
                ipaddress.ip_network(net)
            except ValueError as e:
                raise ValueError(f"Invalid blocked IP range {net}: {e}")


# ============================================================================
# УЛУЧШЕННАЯ ДЕДУПЛИКАЦИЯ С BLOOM FILTER
# ============================================================================

class DeduplicationManager:
    """
    Управляет дедупликацией доменов с использованием Bloom filter.
    Экономит память для больших наборов данных.
    """
    
    def __init__(self, expected_elements: int, error_rate: float = 0.001, logger: Optional[StructuredLogger] = None):
        self.logger = logger.bind(component="deduplicator") if logger else None
        self.expected_elements = expected_elements
        self.error_rate = error_rate
        
        if AppConfig.USE_BLOOM_FILTER:
            self.bloom = ScalableBloomFilter(
                initial_capacity=expected_elements,
                error_rate=error_rate
            )
            self.confirmed: Set[str] = set()  # Для проверки false positives
            self._false_positives = 0
            self._use_bloom = True
            if self.logger:
                self.logger.info("Using Bloom filter for deduplication", 
                                capacity=expected_elements,
                                error_rate=error_rate)
        else:
            self.domains: Set[str] = set()
            self._use_bloom = False
            if self.logger:
                self.logger.info("Using set for deduplication (fallback mode)")
    
    def add(self, domain: str) -> bool:
        """
        Добавляет домен и возвращает True если домен уже существовал.
        Для Bloom filter может давать false positives.
        """
        if not self._use_bloom:
            if domain in self.domains:
                return True
            self.domains.add(domain)
            return False
        
        # Bloom filter mode
        if domain in self.confirmed:
            return True
        
        if domain in self.bloom:
            # Проверяем false positive
            self.confirmed.add(domain)
            self._false_positives += 1
            if self.logger and self._false_positives % 1000 == 0:
                self.logger.warning(f"False positive count: {self._false_positives}")
            return True
        
        self.bloom.add(domain)
        return False
    
    def __len__(self) -> int:
        """Возвращает количество уникальных доменов"""
        if self._use_bloom:
            # Приблизительное значение
            return len(self.bloom)
        return len(self.domains)
    
    def get_stats(self) -> Dict[str, Any]:
        """Возвращает статистику дедупликации"""
        stats = {
            "use_bloom": self._use_bloom,
            "unique_count": len(self)
        }
        if self._use_bloom:
            stats["false_positives"] = self._false_positives
            stats["error_rate"] = self.error_rate
        return stats
    
    def clear(self) -> None:
        """Очищает все данные"""
        if self._use_bloom:
            self.bloom = ScalableBloomFilter(
                initial_capacity=self.expected_elements,
                error_rate=self.error_rate
            )
            self.confirmed.clear()
            self._false_positives = 0
        else:
            self.domains.clear()


# ============================================================================
# ДЕКОРАТОР ДЛЯ ЕДИНООБРАЗНОЙ ОБРАБОТКИ ОШИБОК
# ============================================================================

def with_retry_and_logging(max_retries: int = AppConfig.MAX_RETRIES):
    """
    Декоратор для автоматических ретраев с экспоненциальной задержкой
    и единообразным логированием ошибок.
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return await func(self, *args, **kwargs)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    last_error = e
                    if attempt == max_retries - 1:
                        if hasattr(self, 'logger'):
                            self.logger.error(
                                f"Operation failed after {max_retries} attempts",
                                operation=func.__name__,
                                error=str(e),
                                exc_info=True
                            )
                        raise
                    
                    delay = min(
                        AppConfig.RETRY_BACKOFF_BASE * (2 ** attempt),
                        AppConfig.RETRY_MAX_BACKOFF
                    )
                    if hasattr(self, 'logger'):
                        self.logger.warning(
                            f"Attempt {attempt + 1} failed, retrying in {delay:.2f}s",
                            operation=func.__name__,
                            error=str(e)
                        )
                    await asyncio.sleep(delay)
            raise last_error
        return wrapper
    return decorator


# ============================================================================
# УЛУЧШЕННЫЙ SSRF PROTECTOR С АСИНХРОННЫМ DNS
# ============================================================================

class SSRFProtector:
    """
    Hardened SSRF protection with DNS rebinding detection.
    Использует асинхронный DNS резолвинг через executor.
    """
    
    def __init__(self, logger: StructuredLogger):
        self.logger = logger.bind(component="ssrf_protector")
        self._blocked_networks: List[ipaddress.IPv4Network] = []
        self._blocked_networks_v6: List[ipaddress.IPv6Network] = []
        
        # Parse blocked IP ranges
        for net in AppConfig.BLOCKED_IP_RANGES:
            try:
                network = ipaddress.ip_network(net)
                if isinstance(network, ipaddress.IPv4Network):
                    self._blocked_networks.append(network)
                else:
                    self._blocked_networks_v6.append(network)
            except ValueError as e:
                self.logger.error("Invalid blocked network", network=net, error=str(e))
        
        self._checked_urls: TTLCache[bool] = TTLCache(maxsize=10000, ttl_seconds=3600)
        self._dns_cache: TTLCache[List[str]] = TTLCache(
            maxsize=AppConfig.DNS_CACHE_SIZE,
            ttl_seconds=AppConfig.DNS_CACHE_TTL
        )
        self._rate_limiter = asyncio.Semaphore(5)
    
    @with_retry_and_logging(max_retries=2)
    async def validate_url(self, url: str) -> None:
        """
        Validate URL against SSRF attacks with retries.
        
        Args:
            url: URL to validate
            
        Raises:
            ValueError: If URL is considered unsafe
        """
        normalized = self._normalize_url(url)
        
        # Check cache
        cached = await self._checked_urls.get(normalized)
        if cached is not None:
            return
        
        async with self._rate_limiter:
            await self._validate_url_impl(normalized)
        
        await self._checked_urls.set(normalized, True)
        self.logger.debug("URL validated", url=url)
    
    async def _validate_url_impl(self, url: str) -> None:
        """Implementation of URL validation"""
        parsed = urlparse(url)
        
        # Validate scheme
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        if not parsed.hostname:
            raise ValueError(f"No hostname in URL: {url}")
        
        # Check against allowed domains whitelist
        if parsed.hostname not in AppConfig.ALLOWED_DOMAINS:
            await self._validate_ip_with_rebinding_protection(parsed.hostname)
    
    async def _validate_ip_with_rebinding_protection(self, hostname: str) -> None:
        """Validate hostname with DNS rebinding protection"""
        results: List[Set[str]] = []
        
        for attempt in range(AppConfig.DNS_REBINDING_CHECKS):
            ips = await self._resolve_hostname(hostname)
            results.append(set(ips))
            
            if attempt < AppConfig.DNS_REBINDING_CHECKS - 1:
                await asyncio.sleep(AppConfig.DNS_REBINDING_DELAY)
        
        # Check for DNS rebinding
        if len(results) > 1 and results[0] != results[-1]:
            raise ValueError(f"DNS rebinding detected for {hostname}")
        
        # Validate resolved IPs
        for ip_str in results[-1]:
            await self._validate_ip_address(ip_str, hostname)
    
    async def _validate_ip_address(self, ip_str: str, hostname: str) -> None:
        """Validate IP address against blocked ranges"""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip_str} for {hostname}") from e
        
        networks = self._blocked_networks if isinstance(ip, ipaddress.IPv4Address) else self._blocked_networks_v6
        
        for blocked_net in networks:
            if ip in blocked_net:
                raise ValueError(f"IP {ip} for {hostname} is in blocked range {blocked_net}")
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        """
        Асинхронный DNS резолвинг с использованием executor.
        Не блокирует event loop.
        """
        # Check cache
        cached = await self._dns_cache.get(hostname)
        if cached is not None:
            return cached
        
        # Perform DNS resolution with executor
        loop = asyncio.get_running_loop()
        try:
            ips = await asyncio.wait_for(
                loop.run_in_executor(
                    None, 
                    socket.getaddrinfo, 
                    hostname, None, 0, socket.SOCK_STREAM, 0
                ),
                timeout=AppConfig.DNS_TIMEOUT
            )
            result = list(set(ip[4][0] for ip in ips))
            await self._dns_cache.set(hostname, result)
            return result
        except (socket.gaierror, asyncio.TimeoutError) as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for caching"""
        parsed = urlparse(url)
        normalized = parsed._replace(
            netloc=parsed.hostname or '',
            fragment='',
            query=''
        )
        return normalized.geturl()


# ============================================================================
# УЛУЧШЕННЫЙ BLOCKLIST BUILDER С РАЗДЕЛЕННЫМИ КЛАССАМИ
# ============================================================================

class BuildStats:
    """Статистика сборки блоклиста"""
    
    def __init__(self):
        self.sources_processed = 0
        self.sources_failed = 0
        self.total_valid = 0
        self.duplicates = 0
        self.ai_detected = 0
        self.start_time = 0.0
        self._lock = asyncio.Lock()
    
    async def increment(self, metric: str, value: int = 1) -> None:
        """Безопасное увеличение счетчика"""
        async with self._lock:
            current = getattr(self, metric, 0)
            setattr(self, metric, current + value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для логирования"""
        return {
            "sources_processed": self.sources_processed,
            "sources_failed": self.sources_failed,
            "total_valid": self.total_valid,
            "duplicates": self.duplicates,
            "ai_detected": self.ai_detected,
            "duration": time.time() - self.start_time if self.start_time else 0
        }


class BuildOrchestrator:
    """Оркестрирует процесс сборки блоклиста с разделением ответственности"""
    
    def __init__(
        self,
        deduplicator: DeduplicationManager,
        stats: BuildStats,
        logger: StructuredLogger
    ):
        self.deduplicator = deduplicator
        self.stats = stats
        self.logger = logger.bind(component="orchestrator")
    
    async def process_source(
        self,
        source: SourceDefinition,
        session: aiohttp.ClientSession,
        validator: DomainValidator,
        detector: Optional[AITrackerDetector]
    ) -> AsyncGenerator[DomainRecord, None]:
        """
        Обрабатывает один источник и возвращает доменные записи.
        
        Args:
            source: Определение источника
            session: HTTP сессия
            validator: Валидатор доменов
            detector: AI детектор (опционально)
            
        Yields:
            DomainRecord для каждого валидного домена
        """
        processor = StreamingSourceProcessor(session, validator, detector, self.logger)
        
        async for record in processor.process_source_streaming(source):
            # Дедупликация
            if self.deduplicator.add(record.domain):
                await self.stats.increment("duplicates")
                continue
            
            await self.stats.increment("total_valid")
            
            if record.ai_confidence >= AppConfig.AI_CONFIDENCE_THRESHOLD:
                await self.stats.increment("ai_detected")
            
            yield record
        
        await self.stats.increment("sources_processed")


class BlocklistBuilder:
    """
    Main blocklist builder with streaming processing.
    Улучшенная версия с разделенной логикой и безопасным shutdown.
    """
    
    def __init__(self, output_path: Path, logger: StructuredLogger):
        self.output_path = PathValidator.validate_output_path(output_path)
        self.logger = logger.bind(component="blocklist_builder")
        self._shutdown_requested = False
        self._shutdown_event = asyncio.Event()
        self._start_time: float = 0.0
        self._write_buffer: List[str] = []
        self._buffer_size = 0
        self.stats = BuildStats()
        self.deduplicator = DeduplicationManager(
            expected_elements=AppConfig.MAX_DOMAINS_TOTAL,
            error_rate=AppConfig.BLOOM_FILTER_ERROR_RATE,
            logger=self.logger
        )
        self.orchestrator = BuildOrchestrator(self.deduplicator, self.stats, self.logger)
    
    async def build(self, sources: List[SourceDefinition]) -> bool:
        """
        Build blocklist from sources.
        
        Args:
            sources: List of source definitions
            
        Returns:
            True if build succeeded, False otherwise
        """
        self._start_time = time.time()
        self.stats.start_time = self._start_time
        
        # Setup signal handlers
        await self._setup_signal_handlers()
        
        self.logger.info("Starting blocklist build", 
                        version="15.1.0", 
                        sources=len(sources),
                        use_bloom=AppConfig.USE_BLOOM_FILTER)
        
        try:
            async with self._managed_resources() as (session, validator, detector):
                async with aiofiles.open(self.output_path, 'w', encoding='utf-8') as outfile:
                    await self._write_header(outfile)
                    
                    for source in sorted(sources, key=lambda s: s.priority):
                        if self._shutdown_requested:
                            self.logger.warning("Shutdown requested, stopping build")
                            break
                        
                        try:
                            async for record in self.orchestrator.process_source(
                                source, session, validator, detector
                            ):
                                await self._write_record(outfile, record)
                                
                        except Exception as e:
                            await self.stats.increment("sources_failed")
                            self.logger.error(
                                "Source failed",
                                source=source.name,
                                error=str(e),
                                exc_info=True
                            )
                    
                    await self._flush_buffer(outfile)
                    await self._write_footer(outfile)
                    
            self._print_summary()
            return True
            
        except asyncio.CancelledError:
            self.logger.warning("Build cancelled")
            return False
        except Exception as e:
            self.logger.critical("Build failed", error=str(e), exc_info=True)
            return False
    
    async def _managed_resources(self) -> AsyncIterator[Tuple[aiohttp.ClientSession, DomainValidator, AITrackerDetector]]:
        """Контекстный менеджер для управления ресурсами"""
        session = None
        validator = None
        detector = None
        
        try:
            session = await self._create_session()
            validator = DomainValidator(self.logger)
            detector = AITrackerDetector(self.logger)
            
            yield session, validator, detector
            
        finally:
            if session:
                await session.close()
            if validator:
                await validator.cleanup()
            if detector:
                await detector.cleanup()
    
    async def _create_session(self) -> aiohttp.ClientSession:
        """Create secure HTTP session with TLS verification"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        connector = aiohttp.TCPConnector(
            limit=AppConfig.MAX_CONCURRENT_DOWNLOADS,
            limit_per_host=AppConfig.CONNECTION_LIMIT_PER_HOST,
            ttl_dns_cache=300,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        timeout = ClientTimeout(total=AppConfig.HTTP_TIMEOUT)
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': f'DNS-Blocklist-Builder/15.1.0',
                'Accept': 'text/plain',
                'Accept-Encoding': 'gzip, deflate'
            }
        )
    
    async def _write_record(self, outfile, record: DomainRecord) -> None:
        """Буферизированная запись записи"""
        line = record.to_hosts_entry() + "\n"
        self._write_buffer.append(line)
        self._buffer_size += len(line)
        
        # Flush при достижении лимита
        if len(self._write_buffer) >= AppConfig.FLUSH_INTERVAL:
            await self._flush_buffer(outfile)
    
    async def _flush_buffer(self, outfile) -> None:
        """Сброс буфера в файл"""
        if not self._write_buffer:
            return
        
        await outfile.writelines(self._write_buffer)
        self._write_buffer.clear()
        self._buffer_size = 0
    
    async def _write_header(self, outfile) -> None:
        """Write blocklist header"""
        await outfile.write("# DNS Security Blocklist v15.1.0\n")
        await outfile.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        await outfile.write("# Format: 0.0.0.0 domain [optional: AI detection info]\n")
        await outfile.write("\n")
    
    async def _write_footer(self, outfile) -> None:
        """Write blocklist footer with statistics"""
        await outfile.write("\n")
        await outfile.write("# Statistics:\n")
        await outfile.write(f"# - Total domains: {len(self.deduplicator):,}\n")
        await outfile.write(f"# - AI detected: {self.stats.ai_detected:,}\n")
        await outfile.write(f"# - Build time: {time.time() - self._start_time:.2f}s\n")
        await outfile.write(f"# - Sources processed: {self.stats.sources_processed}\n")
        
        if AppConfig.USE_BLOOM_FILTER:
            stats = self.deduplicator.get_stats()
            await outfile.write(f"# - Deduplication: Bloom filter (error rate: {stats['error_rate']:.3%})\n")
            await outfile.write(f"# - False positives: {stats['false_positives']:,}\n")
    
    async def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        loop = asyncio.get_running_loop()
        
        def _create_handler(sig: signal.Signals) -> Callable[[], None]:
            """Create safe signal handler"""
            def handler() -> None:
                if not self._shutdown_requested:
                    self._shutdown_requested = True
                    self.logger.warning(f"Received signal {sig.name}, initiating graceful shutdown")
                    asyncio.create_task(self._shutdown())
            return handler
        
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _create_handler(sig))
            except (NotImplementedError, RuntimeError):
                # Windows doesn't support add_signal_handler for SIGTERM
                pass
    
    async def _shutdown(self) -> None:
        """Graceful shutdown with timeout"""
        self._shutdown_event.set()
        
        # Wait for completion or timeout
        try:
            await asyncio.wait_for(
                self._shutdown_event.wait(),
                timeout=AppConfig.GRACEFUL_SHUTDOWN_TIMEOUT
            )
        except asyncio.TimeoutError:
            self.logger.error("Graceful shutdown timeout, forcing exit")
            # Force exit after timeout
            os._exit(1)
    
    def _print_summary(self) -> None:
        """Print build summary"""
        duration = time.time() - self._start_time
        stats = self.stats.to_dict()
        
        print("\n" + "=" * 70)
        print("DNS Blocklist Build Complete")
        print("=" * 70)
        print(f"Duration: {duration:.2f}s")
        print(f"Sources: {stats['sources_processed']} processed, "
              f"{stats['sources_failed']} failed")
        print(f"Domains: {stats['total_valid']:,} unique")
        print(f"Duplicates: {stats['duplicates']:,}")
        print(f"AI Detected: {stats['ai_detected']:,}")
        print(f"Output: {self.output_path}")
        
        if AppConfig.USE_BLOOM_FILTER:
            dedup_stats = self.deduplicator.get_stats()
            print(f"Deduplication: Bloom filter (error rate: {dedup_stats['error_rate']:.3%})")
            print(f"False positives: {dedup_stats['false_positives']:,}")
        
        print("=" * 70)


# ============================================================================
# MAIN ENTRY POINT (обновлен)
# ============================================================================

async def main_async() -> int:
    """
    Asynchronous main entry point
    
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = argparse.ArgumentParser(
        description="DNS Security Blocklist Builder v15.1.0 - Enterprise Hardened",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("./blocklist.txt"),
        help="Output file path (default: ./blocklist.txt)"
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=AppConfig.MAX_DOMAINS_TOTAL,
        help=f"Maximum domains to process (default: {AppConfig.MAX_DOMAINS_TOTAL})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=AppConfig.HTTP_TIMEOUT,
        help=f"Download timeout in seconds (default: {AppConfig.HTTP_TIMEOUT})"
    )
    parser.add_argument(
        "--no-bloom",
        action="store_true",
        help="Disable Bloom filter (use set for deduplication)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="DNS Blocklist Builder v15.1.0"
    )
    
    args = parser.parse_args()
    
    # Override config if needed
    if args.no_bloom:
        os.environ["DNSBL_USE_BLOOM"] = "false"
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = StructuredLogger("dns_blocklist", log_level)
    
    # Validate configuration
    try:
        AppConfig.validate()
    except Exception as e:
        logger.critical("Invalid configuration", error=str(e))
        return 1
    
    # Validate output path
    try:
        output_path = PathValidator.validate_output_path(args.output)
    except ValueError as e:
        logger.critical("Invalid output path", error=str(e))
        return 1
    
    # Override config with command line arguments
    os.environ["DNSBL_MAX_DOMAINS"] = str(args.max_domains)
    os.environ["DNSBL_HTTP_TIMEOUT"] = str(args.timeout)
    
    # Create builder and run
    builder = BlocklistBuilder(output_path, logger)
    
    try:
        sources = SourceManager.get_default_sources()
        success = await builder.build(sources)
        return 0 if success else 1
        
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.critical("Fatal error", error=str(e), exc_info=args.verbose)
        return 1


def main() -> int:
    """Synchronous main entry point"""
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
