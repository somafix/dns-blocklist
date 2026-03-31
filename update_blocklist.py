#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - ENTERPRISE EDITION (v16.0.2)
Fixed: Made defusedxml optional, removed hard requirement
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import wraps
from pathlib import Path
from typing import (
    Any, AsyncIterator, Dict, Final, List, Optional, 
    Set, Tuple, Callable, AsyncGenerator, TypeVar, Generic
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientTimeout, ClientError
from aiohttp.client_exceptions import ServerTimeoutError

# Optional dependencies with graceful fallback
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False
    print("⚠️  Warning: pybloom-live not installed. Using fallback deduplication (set).", file=sys.stderr)
    print("   To install: pip install pybloom-live", file=sys.stderr)

# defusedxml is optional - only needed for XML sources
try:
    import defusedxml.ElementTree as ET
    DEFUSED_XML_AVAILABLE = True
except ImportError:
    DEFUSED_XML_AVAILABLE = False
    # Not a hard requirement for hosts/domains sources
    print("ℹ️  Info: defusedxml not installed. XML sources will use standard parser.", file=sys.stderr)
    print("   To install: pip install defusedxml (recommended for security)", file=sys.stderr)
    import xml.etree.ElementTree as ET

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass(frozen=True)
class AppConfig:
    """Immutable configuration from environment variables."""
    
    # Timeouts
    HTTP_TIMEOUT: int = int(os.getenv("DNSBL_HTTP_TIMEOUT", "30"))
    DNS_TIMEOUT: int = int(os.getenv("DNSBL_DNS_TIMEOUT", "10"))
    GRACEFUL_SHUTDOWN_TIMEOUT: int = int(os.getenv("DNSBL_SHUTDOWN_TIMEOUT", "30"))
    DNS_REBINDING_DELAY: float = float(os.getenv("DNSBL_REBINDING_DELAY", "0.5"))
    DNS_REBINDING_CHECKS: int = int(os.getenv("DNSBL_REBINDING_CHECKS", "2"))
    
    # Concurrency
    MAX_CONCURRENT_DOWNLOADS: int = int(os.getenv("DNSBL_MAX_CONCURRENT", "10"))
    CONNECTION_LIMIT_PER_HOST: int = int(os.getenv("DNSBL_CONN_LIMIT", "5"))
    
    # Retry strategy
    MAX_RETRIES: int = int(os.getenv("DNSBL_MAX_RETRIES", "3"))
    RETRY_BACKOFF_BASE: float = float(os.getenv("DNSBL_RETRY_BACKOFF", "1.0"))
    RETRY_MAX_BACKOFF: float = float(os.getenv("DNSBL_MAX_BACKOFF", "30.0"))
    
    # Performance limits
    MAX_DOMAINS_TOTAL: int = int(os.getenv("DNSBL_MAX_DOMAINS", "2000000"))
    MAX_FILE_SIZE_MB: int = int(os.getenv("DNSBL_MAX_FILE_MB", "100"))
    STREAM_BUFFER_SIZE: int = int(os.getenv("DNSBL_BUFFER_SIZE", "16384"))
    
    # Domain validation
    MAX_DOMAIN_LEN: int = 253
    MAX_LABEL_LEN: int = 63
    MIN_DOMAIN_LEN: int = 3
    MAX_INPUT_LEN: int = 1024
    
    # Cache settings
    DNS_CACHE_SIZE: int = int(os.getenv("DNSBL_DNS_CACHE_SIZE", "50000"))
    DNS_CACHE_TTL: int = int(os.getenv("DNSBL_DNS_CACHE_TTL", "600"))
    AI_CACHE_SIZE: int = int(os.getenv("DNSBL_AI_CACHE_SIZE", "20000"))
    AI_CACHE_TTL: int = int(os.getenv("DNSBL_AI_CACHE_TTL", "7200"))
    
    # Performance tuning
    BLOOM_FILTER_ERROR_RATE: float = float(os.getenv("DNSBL_BLOOM_ERROR_RATE", "0.001"))
    BLOOM_FILTER_CAPACITY: int = int(os.getenv("DNSBL_BLOOM_CAPACITY", "2000000"))
    FLUSH_INTERVAL: int = int(os.getenv("DNSBL_FLUSH_INTERVAL", "50000"))
    USE_BLOOM_FILTER: bool = os.getenv("DNSBL_USE_BLOOM", "true").lower() == "true" and BLOOM_AVAILABLE
    
    # Security - Blocked IP ranges
    BLOCKED_IP_RANGES: Tuple[str, ...] = (
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96',
        '100.64.0.0/10', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'
    )
    
    # AI Detection threshold
    AI_CONFIDENCE_THRESHOLD: float = float(os.getenv("DNSBL_AI_THRESHOLD", "0.65"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("DNSBL_LOG_LEVEL", "INFO")
    LOG_JSON: bool = os.getenv("DNSBL_LOG_JSON", "true").lower() == "true"


# Define ALLOWED_DOMAINS as a global constant
ALLOWED_DOMAINS: Set[str] = {
    'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
    'raw.github.com', 'github.com', 'gist.github.com',
    'gitlab.com', 'bitbucket.org', 'oisd.nl', 'adaway.org',
    'urlhaus.abuse.ch', 'threatfox.abuse.ch', 'hole.cert.pl',
    'someonewhocares.org', 'pgl.yoyo.org', 's3.amazonaws.com',
    'hosts-file.net', 'ransomwaretracker.abuse.ch', 'feodotracker.abuse.ch'
}


def validate_config() -> None:
    """Validate configuration values."""
    assert AppConfig.HTTP_TIMEOUT > 0, "HTTP_TIMEOUT must be positive"
    assert AppConfig.MAX_CONCURRENT_DOWNLOADS > 0, "MAX_CONCURRENT_DOWNLOADS must be positive"
    assert 0 <= AppConfig.AI_CONFIDENCE_THRESHOLD <= 1, "AI_CONFIDENCE_THRESHOLD must be between 0 and 1"
    assert AppConfig.MAX_RETRIES >= 0, "MAX_RETRIES must be non-negative"
    
    # Validate blocked IP ranges
    for net in AppConfig.BLOCKED_IP_RANGES:
        try:
            ipaddress.ip_network(net)
        except ValueError as e:
            raise ValueError(f"Invalid blocked IP range {net}: {e}")


# ============================================================================
# STRUCTURED LOGGING
# ============================================================================

class StructuredLogger:
    """JSON-structured logging with context binding."""
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.handlers.clear()
        
        handler = logging.StreamHandler(sys.stderr)
        if AppConfig.LOG_JSON:
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        
        self.logger.addHandler(handler)
        self._context: Dict[str, Any] = {
            "app": "dns-blocklist-builder",
            "version": "16.0.2"
        }
    
    def bind(self, **kwargs: Any) -> 'StructuredLogger':
        child = StructuredLogger(self.logger.name, self.logger.level)
        child._context.update(self._context)
        child._context.update(kwargs)
        return child
    
    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        data = {
            "message": msg,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "logger": self.logger.name,
            **self._context,
            **kwargs
        }
        self.logger.log(level, json.dumps(data) if AppConfig.LOG_JSON else msg)
    
    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)
    
    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)
    
    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)
    
    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)
    
    def critical(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, msg, **kwargs)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        return record.getMessage()


# ============================================================================
# TTLCache
# ============================================================================

T = TypeVar('T')

class TTLCache(Generic[T]):
    """Thread-safe cache with TTL."""
    
    __slots__ = ('maxsize', 'ttl', '_cache', '_access_order', '_lock', '_hits', '_misses')
    
    def __init__(self, maxsize: int, ttl_seconds: int):
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[T, float]] = {}
        self._access_order: Deque[str] = deque()
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
    
    async def get(self, key: str) -> Optional[T]:
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            value, timestamp = self._cache[key]
            if time.monotonic() - timestamp > self.ttl:
                del self._cache[key]
                self._misses += 1
                return None
            
            self._access_order.remove(key)
            self._access_order.append(key)
            self._hits += 1
            return value
    
    async def set(self, key: str, value: T) -> None:
        async with self._lock:
            if len(self._cache) >= self.maxsize:
                oldest = self._access_order.popleft()
                del self._cache[oldest]
            
            if key in self._cache:
                self._access_order.remove(key)
            
            self._cache[key] = (value, time.monotonic())
            self._access_order.append(key)
    
    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._hits = 0
            self._misses = 0
    
    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0


# ============================================================================
# ENUMS
# ============================================================================

class SourceType(Enum):
    HOSTS = auto()
    DOMAINS = auto()
    ADBLOCK = auto()


class DomainStatus(Enum):
    VALID = auto()
    INVALID = auto()
    DUPLICATE = auto()
    AI_DETECTED = auto()
    BLOCKED = auto()


# ============================================================================
# DOMAIN RECORD
# ============================================================================

@dataclass(frozen=True, slots=True)
class DomainRecord:
    """Immutable domain record."""
    
    domain: str
    source: str
    status: DomainStatus
    ai_confidence: float = 0.0
    ai_reasons: Tuple[str, ...] = field(default_factory=tuple)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_hosts_entry(self) -> str:
        # Safe domain sanitization
        safe_domain = re.sub(r'[\x00-\x1f\x7f\s#|&]', '', self.domain)[:AppConfig.MAX_DOMAIN_LEN]
        
        if self.ai_confidence >= AppConfig.AI_CONFIDENCE_THRESHOLD:
            safe_reasons = [re.sub(r'[^\w\-]', '_', r)[:50] for r in self.ai_reasons[:2]]
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{','.join(safe_reasons)}]"
        
        return f"0.0.0.0 {safe_domain}"


# ============================================================================
# PATH VALIDATOR
# ============================================================================

class PathValidator:
    """Prevent path traversal attacks."""
    
    @staticmethod
    def validate_output_path(path: Path, working_dir: Optional[Path] = None) -> Path:
        if working_dir is None:
            working_dir = Path.cwd()
        
        try:
            resolved = path.resolve()
            working_resolved = working_dir.resolve()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"Invalid path: {path}") from e
        
        allowed_dirs = [
            working_resolved,
            working_resolved / "output",
            working_resolved / "blocklists",
            Path("/tmp") / f"dnsbl_{os.getenv('USER', 'unknown')}",
            Path("/home/runner/work") / "dns-blocklist" / "dns-blocklist",  # GitHub Actions
        ]
        
        allowed = False
        for allowed_dir in allowed_dirs:
            try:
                resolved.relative_to(allowed_dir.resolve())
                allowed = True
                break
            except (ValueError, OSError):
                continue
        
        if not allowed:
            raise ValueError(f"Path {path} escapes allowed directories")
        
        resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        
        if resolved.exists() and not os.access(resolved, os.W_OK):
            raise PermissionError(f"File {resolved} exists but is not writable")
        
        return resolved


# ============================================================================
# DEDUPLICATION MANAGER
# ============================================================================

class DeduplicationManager:
    """Manages domain deduplication with optional Bloom filter."""
    
    __slots__ = ('_use_bloom', '_bloom', '_confirmed', '_domains', '_false_positives', '_logger')
    
    def __init__(self, expected_elements: int, error_rate: float = 0.001, logger: Optional[StructuredLogger] = None):
        self._use_bloom = AppConfig.USE_BLOOM_FILTER
        self._logger = logger
        self._false_positives = 0
        
        if self._use_bloom:
            self._bloom = ScalableBloomFilter(
                initial_capacity=expected_elements,
                error_rate=error_rate
            )
            self._confirmed: Set[str] = set()
            self._domains = None
        else:
            self._domains: Set[str] = set()
            self._bloom = None
            self._confirmed = None
    
    def add(self, domain: str) -> bool:
        if not self._use_bloom:
            if domain in self._domains:
                return True
            self._domains.add(domain)
            return False
        
        # Bloom filter mode
        if domain in self._confirmed:
            return True
        
        if domain in self._bloom:
            self._confirmed.add(domain)
            self._false_positives += 1
            if self._logger and self._false_positives % 10000 == 0:
                self._logger.warning(f"Bloom filter false positives: {self._false_positives}")
            return True
        
        self._bloom.add(domain)
        return False
    
    def __len__(self) -> int:
        if self._use_bloom:
            return len(self._bloom)
        return len(self._domains)
    
    @property
    def stats(self) -> Dict[str, Any]:
        if self._use_bloom:
            return {
                "use_bloom": True,
                "unique": len(self._bloom),
                "false_positives": self._false_positives
            }
        return {"use_bloom": False, "unique": len(self._domains)}


# ============================================================================
# SSRF PROTECTOR
# ============================================================================

class SSRFProtector:
    """SSRF protection with DNS rebinding detection."""
    
    def __init__(self, logger: StructuredLogger):
        self._logger = logger.bind(component="ssrf_protector")
        self._blocked_networks: List[ipaddress.IPv4Network] = []
        self._blocked_networks_v6: List[ipaddress.IPv6Network] = []
        
        for net in AppConfig.BLOCKED_IP_RANGES:
            try:
                network = ipaddress.ip_network(net)
                if isinstance(network, ipaddress.IPv4Network):
                    self._blocked_networks.append(network)
                else:
                    self._blocked_networks_v6.append(network)
            except ValueError:
                pass
        
        self._checked_urls: TTLCache[bool] = TTLCache(maxsize=10000, ttl_seconds=3600)
        self._dns_cache: TTLCache[List[str]] = TTLCache(
            maxsize=AppConfig.DNS_CACHE_SIZE, 
            ttl_seconds=AppConfig.DNS_CACHE_TTL
        )
        self._rate_limiter = asyncio.Semaphore(10)
    
    async def validate_url(self, url: str) -> None:
        normalized = self._normalize_url(url)
        
        cached = await self._checked_urls.get(normalized)
        if cached is not None:
            return
        
        async with self._rate_limiter:
            await self._validate_url_impl(normalized)
        
        await self._checked_urls.set(normalized, True)
        self._logger.debug("URL validated", url=url)
    
    async def _validate_url_impl(self, url: str) -> None:
        parsed = urlparse(url)
        
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        if not parsed.hostname:
            raise ValueError(f"No hostname in URL: {url}")
        
        if parsed.hostname not in ALLOWED_DOMAINS:
            await self._validate_ip_with_rebinding_protection(parsed.hostname)
    
    async def _validate_ip_with_rebinding_protection(self, hostname: str) -> None:
        results: List[Set[str]] = []
        
        for attempt in range(AppConfig.DNS_REBINDING_CHECKS):
            ips = await self._resolve_hostname(hostname)
            results.append(set(ips))
            
            if attempt < AppConfig.DNS_REBINDING_CHECKS - 1:
                await asyncio.sleep(AppConfig.DNS_REBINDING_DELAY)
        
        if len(results) > 1 and results[0] != results[-1]:
            raise ValueError(f"DNS rebinding detected for {hostname}")
        
        for ip_str in results[-1]:
            await self._validate_ip_address(ip_str, hostname)
    
    async def _validate_ip_address(self, ip_str: str, hostname: str) -> None:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip_str} for {hostname}") from e
        
        networks = self._blocked_networks if isinstance(ip, ipaddress.IPv4Address) else self._blocked_networks_v6
        
        for blocked_net in networks:
            if ip in blocked_net:
                raise ValueError(f"IP {ip} for {hostname} is in blocked range {blocked_net}")
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        cached = await self._dns_cache.get(hostname)
        if cached is not None:
            return cached
        
        loop = asyncio.get_running_loop()
        try:
            ips = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM, 0),
                timeout=AppConfig.DNS_TIMEOUT
            )
            result = list(set(ip[4][0] for ip in ips))
            await self._dns_cache.set(hostname, result)
            return result
        except (socket.gaierror, asyncio.TimeoutError) as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
    
    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed._replace(netloc=parsed.hostname or '', fragment='', query='').geturl()


# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """ReDoS-safe domain validator."""
    
    DOMAIN_PATTERN = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$', re.IGNORECASE)
    RESERVED_TLDS = {'localhost', 'local', 'example', 'invalid', 'test', 'lan', 'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p'}
    
    def __init__(self, logger: StructuredLogger):
        self._logger = logger.bind(component="domain_validator")
        self._cache: TTLCache[bool] = TTLCache(
            maxsize=AppConfig.DNS_CACHE_SIZE, 
            ttl_seconds=AppConfig.DNS_CACHE_TTL
        )
    
    async def is_valid(self, domain: str) -> bool:
        if len(domain) > AppConfig.MAX_INPUT_LEN:
            return False
        
        domain_lower = domain.lower().strip()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        valid = self._validate_syntax(domain_lower)
        await self._cache.set(domain_lower, valid)
        return valid
    
    def _validate_syntax(self, domain: str) -> bool:
        if len(domain) < AppConfig.MIN_DOMAIN_LEN or len(domain) > AppConfig.MAX_DOMAIN_LEN:
            return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        if parts[-1] in self.RESERVED_TLDS:
            return False
        
        for label in parts:
            if not label or len(label) > AppConfig.MAX_LABEL_LEN:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        try:
            return bool(self.DOMAIN_PATTERN.match(domain))
        except re.error:
            return False
    
    async def cleanup(self) -> None:
        await self._cache.clear()


# ============================================================================
# AI TRACKER DETECTOR
# ============================================================================

class AITrackerDetector:
    """AI-powered tracker detection with pattern matching."""
    
    TRACKER_PATTERNS = (
        (r'\banalytics\b', 'analytics', 0.82),
        (r'\bgoogle[-_]analytics\b', 'google_analytics', 0.95),
        (r'\bgoogletagmanager\b', 'google_tag_manager', 0.92),
        (r'\bgtm\b', 'google_tag_manager', 0.85),
        (r'\bfirebase\b', 'firebase_analytics', 0.92),
        (r'\bamplitude\b', 'amplitude', 0.90),
        (r'\bmixpanel\b', 'mixpanel', 0.90),
        (r'\bsegment\b', 'segment', 0.90),
        (r'\btracking\b', 'tracking', 0.80),
        (r'\bpixel\b', 'tracking_pixel', 0.85),
        (r'\bbeacon\b', 'tracking_beacon', 0.85),
        (r'\bdoubleclick\b', 'doubleclick', 0.95),
        (r'\badservice\b', 'ad_service', 0.85),
        (r'\bcriteo\b', 'criteo', 0.85),
        (r'\bfacebook\b', 'facebook_pixel', 0.95),
        (r'\btwitter\b', 'twitter_tracker', 0.82),
        (r'\bsentry\b', 'error_tracking', 0.75),
        (r'\bhotjar\b', 'user_behavior', 0.85),
        (r'\bclarity\b', 'microsoft_analytics', 0.85),
        (r'\bappsflyer\b', 'appsflyer', 0.90),
    )
    
    def __init__(self, logger: StructuredLogger):
        self._logger = logger.bind(component="ai_detector")
        self._cache: TTLCache[Tuple[float, Tuple[str, ...]]] = TTLCache(
            maxsize=AppConfig.AI_CACHE_SIZE, 
            ttl_seconds=AppConfig.AI_CACHE_TTL
        )
        self._patterns = [(re.compile(p, re.IGNORECASE), r, c) for p, r, c in self.TRACKER_PATTERNS]
    
    async def analyze(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        if len(domain) > AppConfig.MAX_INPUT_LEN:
            return (0.0, ())
        
        domain_lower = domain.lower()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        confidence = 0.0
        reasons: List[str] = []
        
        for pattern, reason, base_conf in self._patterns:
            try:
                if pattern.search(domain_lower):
                    if base_conf > confidence:
                        confidence = base_conf
                    if reason not in reasons:
                        reasons.append(reason)
            except re.error:
                continue
        
        result = (min(1.0, confidence), tuple(reasons))
        await self._cache.set(domain_lower, result)
        return result
    
    async def cleanup(self) -> None:
        await self._cache.clear()


# ============================================================================
# SOURCE DEFINITION
# ============================================================================

@dataclass
class SourceDefinition:
    name: str
    url: str
    source_type: SourceType
    enabled: bool = True
    priority: int = 0
    max_size_mb: int = AppConfig.MAX_FILE_SIZE_MB


# ============================================================================
# STREAMING SOURCE PROCESSOR
# ============================================================================

class StreamingSourceProcessor:
    def __init__(self, session: aiohttp.ClientSession, validator: DomainValidator, 
                 detector: Optional[AITrackerDetector], logger: StructuredLogger):
        self._session = session
        self._validator = validator
        self._detector = detector
        self._logger = logger.bind(component="source_processor")
        self._ssrf_protector = SSRFProtector(logger)
        self._valid_count = 0
    
    async def process_source_streaming(self, source: SourceDefinition) -> AsyncGenerator[DomainRecord, None]:
        if not source.enabled:
            return
        
        try:
            await self._ssrf_protector.validate_url(source.url)
            
            async for line in self._stream_download(source):
                domain = self._parse_line(line, source.source_type)
                if not domain:
                    continue
                
                if not await self._validator.is_valid(domain):
                    continue
                
                self._valid_count += 1
                
                ai_confidence = 0.0
                ai_reasons: Tuple[str, ...] = ()
                
                if self._detector:
                    ai_confidence, ai_reasons = await self._detector.analyze(domain)
                
                yield DomainRecord(
                    domain=domain,
                    source=source.name,
                    status=DomainStatus.VALID,
                    ai_confidence=ai_confidence,
                    ai_reasons=ai_reasons
                )
                
                if self._valid_count >= AppConfig.MAX_DOMAINS_TOTAL:
                    self._logger.info("Reached domain limit", limit=AppConfig.MAX_DOMAINS_TOTAL)
                    break
            
            self._logger.info("Source processed", source=source.name, valid_count=self._valid_count)
            
        except Exception as e:
            self._logger.error("Source processing failed", source=source.name, error=str(e))
    
    async def _stream_download(self, source: SourceDefinition) -> AsyncGenerator[str, None]:
        for attempt in range(AppConfig.MAX_RETRIES):
            try:
                timeout = ClientTimeout(total=AppConfig.HTTP_TIMEOUT)
                async with self._session.get(source.url, timeout=timeout, max_redirects=3, raise_for_status=True) as response:
                    content_length = response.headers.get('Content-Length')
                    if content_length:
                        size_mb = int(content_length) / (1024 * 1024)
                        if size_mb > source.max_size_mb:
                            raise ValueError(f"File too large: {size_mb:.1f} MB")
                    
                    async for line in response.content:
                        if len(line) > AppConfig.MAX_INPUT_LEN:
                            continue
                        
                        try:
                            yield line.decode('utf-8', errors='replace')
                        except UnicodeDecodeError:
                            continue
                    
                    return
                    
            except (asyncio.TimeoutError, ClientError, ServerTimeoutError) as e:
                if attempt == AppConfig.MAX_RETRIES - 1:
                    raise
                
                delay = min(AppConfig.RETRY_BACKOFF_BASE * (2 ** attempt), AppConfig.RETRY_MAX_BACKOFF)
                self._logger.warning("Download failed, retrying", source=source.name, attempt=attempt + 1, delay=delay, error=str(e))
                await asyncio.sleep(delay)
    
    def _parse_line(self, line: str, source_type: SourceType) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        if source_type == SourceType.HOSTS:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                domain = parts[1].split('#')[0].strip()
                if domain and len(domain) <= AppConfig.MAX_DOMAIN_LEN:
                    return domain
        
        elif source_type == SourceType.DOMAINS:
            domain = line.split('#')[0].strip()
            if domain and len(domain) <= AppConfig.MAX_DOMAIN_LEN:
                return domain
        
        return None


# ============================================================================
# BLOCKLIST BUILDER
# ============================================================================

class BlocklistBuilder:
    def __init__(self, output_path: Path, logger: StructuredLogger):
        self._output_path = PathValidator.validate_output_path(output_path)
        self._logger = logger.bind(component="blocklist_builder")
        self._shutdown_requested = False
        self._start_time = 0.0
        self._deduplicator = DeduplicationManager(
            expected_elements=AppConfig.MAX_DOMAINS_TOTAL,
            error_rate=AppConfig.BLOOM_FILTER_ERROR_RATE,
            logger=self._logger
        )
        self._sources_processed = 0
        self._sources_failed = 0
        self._total_valid = 0
        self._duplicates = 0
        self._ai_detected = 0
    
    async def build(self, sources: List[SourceDefinition]) -> bool:
        self._start_time = time.time()
        
        self._logger.info("Starting blocklist build", 
                         version="16.0.2", 
                         sources=len(sources),
                         use_bloom=AppConfig.USE_BLOOM_FILTER,
                         max_domains=AppConfig.MAX_DOMAINS_TOTAL)
        
        try:
            async with self._create_session() as session:
                validator = DomainValidator(self._logger)
                detector = AITrackerDetector(self._logger)
                
                async with aiofiles.open(self._output_path, 'w', encoding='utf-8') as outfile:
                    await self._write_header(outfile)
                    
                    write_buffer = []
                    flush_interval = AppConfig.FLUSH_INTERVAL
                    
                    for source in sorted(sources, key=lambda s: s.priority):
                        if self._shutdown_requested:
                            self._logger.warning("Shutdown requested, stopping build")
                            break
                        
                        try:
                            processor = StreamingSourceProcessor(session, validator, detector, self._logger)
                            
                            async for record in processor.process_source_streaming(source):
                                if self._deduplicator.add(record.domain):
                                    self._duplicates += 1
                                    continue
                                
                                self._total_valid += 1
                                
                                if record.ai_confidence >= AppConfig.AI_CONFIDENCE_THRESHOLD:
                                    self._ai_detected += 1
                                
                                write_buffer.append(record.to_hosts_entry() + "\n")
                                
                                if len(write_buffer) >= flush_interval:
                                    await outfile.writelines(write_buffer)
                                    write_buffer.clear()
                            
                            self._sources_processed += 1
                            
                        except Exception as e:
                            self._sources_failed += 1
                            self._logger.error("Source failed", source=source.name, error=str(e))
                    
                    if write_buffer:
                        await outfile.writelines(write_buffer)
                    
                    await self._write_footer(outfile)
                
                await validator.cleanup()
                await detector.cleanup()
                
                self._print_summary()
                return True
                
        except Exception as e:
            self._logger.critical("Build failed", error=str(e), exc_info=True)
            return False
    
    @asynccontextmanager
    async def _create_session(self) -> AsyncIterator[aiohttp.ClientSession]:
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
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': f'DNS-Blocklist-Builder/16.0.2 (+https://github.com/security/dns-blocklist)'}
        ) as session:
            yield session
    
    async def _write_header(self, outfile) -> None:
        await outfile.write("# DNS Security Blocklist v16.0.2\n")
        await outfile.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        await outfile.write(f"# Build ID: {uuid.uuid4().hex[:8]}\n")
        await outfile.write("# Format: 0.0.0.0 domain [AI detection info]\n")
        await outfile.write("# This blocklist protects against trackers, ads, and malicious domains\n\n")
    
    async def _write_footer(self, outfile) -> None:
        duration = time.time() - self._start_time
        
        await outfile.write("\n# ============================================================================\n")
        await outfile.write("# Statistics:\n")
        await outfile.write(f"# - Total unique domains: {self._total_valid:,}\n")
        await outfile.write(f"# - AI detected trackers: {self._ai_detected:,}\n")
        await outfile.write(f"# - Duplicates removed: {self._duplicates:,}\n")
        await outfile.write(f"# - Sources processed: {self._sources_processed}\n")
        await outfile.write(f"# - Sources failed: {self._sources_failed}\n")
        await outfile.write(f"# - Build time: {duration:.2f}s\n")
        await outfile.write(f"# - Build timestamp: {datetime.now(timezone.utc).isoformat()}\n")
        
        if AppConfig.USE_BLOOM_FILTER:
            stats = self._deduplicator.stats
            await outfile.write(f"# - Deduplication: Bloom filter (error rate: {AppConfig.BLOOM_FILTER_ERROR_RATE:.3%})\n")
            await outfile.write(f"# - False positives: {stats.get('false_positives', 0):,}\n")
        
        await outfile.write("# ============================================================================\n")
    
    def _print_summary(self) -> None:
        duration = time.time() - self._start_time
        
        output = {
            "status": "success",
            "duration_seconds": duration,
            "unique_domains": self._total_valid,
            "duplicates": self._duplicates,
            "ai_detected": self._ai_detected,
            "sources_processed": self._sources_processed,
            "sources_failed": self._sources_failed,
            "use_bloom": AppConfig.USE_BLOOM_FILTER,
            "output_path": str(self._output_path)
        }
        
        # Output machine-readable result for CI/CD
        print(json.dumps(output, indent=2))
        
        # Human-readable summary to stderr
        print("\n" + "=" * 70, file=sys.stderr)
        print("DNS Blocklist Build Complete", file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print(f"Duration: {duration:.2f}s", file=sys.stderr)
        print(f"Sources: {self._sources_processed} processed, {self._sources_failed} failed", file=sys.stderr)
        print(f"Domains: {self._total_valid:,} unique", file=sys.stderr)
        print(f"Duplicates: {self._duplicates:,}", file=sys.stderr)
        print(f"AI Detected: {self._ai_detected:,}", file=sys.stderr)
        print(f"Output: {self._output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)


# ============================================================================
# SOURCE MANAGER
# ============================================================================

class SourceManager:
    @staticmethod
    def get_default_sources() -> List[SourceDefinition]:
        return [
            SourceDefinition("OISD Big", "https://big.oisd.nl/domains", SourceType.DOMAINS, priority=1),
            SourceDefinition("AdAway", "https://adaway.org/hosts.txt", SourceType.HOSTS, priority=2),
            SourceDefinition("URLhaus", "https://urlhaus.abuse.ch/downloads/hostfile/", SourceType.HOSTS, priority=3),
            SourceDefinition("ThreatFox", "https://threatfox.abuse.ch/downloads/hostfile/", SourceType.HOSTS, priority=4),
            SourceDefinition("Cert Poland", "https://hole.cert.pl/domains/domains_hosts.txt", SourceType.HOSTS, priority=5),
        ]


# ============================================================================
# MAIN FUNCTION
# ============================================================================

async def main_async() -> int:
    """Async main entry point."""
    parser = argparse.ArgumentParser(
        description="DNS Security Blocklist Builder v16.0.2",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("./blocklist.txt"), 
                       help="Output file path (default: ./blocklist.txt)")
    parser.add_argument("--max-domains", type=int, 
                       help=f"Maximum domains to process (default: {AppConfig.MAX_DOMAINS_TOTAL})")
    parser.add_argument("--timeout", type=int, 
                       help=f"Download timeout in seconds (default: {AppConfig.HTTP_TIMEOUT})")
    parser.add_argument("--no-bloom", action="store_true", help="Disable Bloom filter")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--version", action="version", version="DNS Blocklist Builder v16.0.2")
    
    args = parser.parse_args()
    
    # Override config from command line
    if args.no_bloom:
        os.environ["DNSBL_USE_BLOOM"] = "false"
    if args.max_domains:
        os.environ["DNSBL_MAX_DOMAINS"] = str(args.max_domains)
    if args.timeout:
        os.environ["DNSBL_HTTP_TIMEOUT"] = str(args.timeout)
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else getattr(logging, AppConfig.LOG_LEVEL)
    logger = StructuredLogger("dns_blocklist", log_level)
    
    try:
        validate_config()
    except Exception as e:
        logger.critical("Invalid configuration", error=str(e))
        return 1
    
    try:
        output_path = PathValidator.validate_output_path(args.output)
    except (ValueError, PermissionError) as e:
        logger.critical("Invalid output path", error=str(e))
        return 1
    
    builder = BlocklistBuilder(output_path, logger)
    sources = SourceManager.get_default_sources()
    
    try:
        success = await builder.build(sources)
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.critical("Fatal error", error=str(e), exc_info=args.verbose)
        return 1


def main() -> int:
    """Synchronous main entry point."""
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
