#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION EDITION (v17.0.0)
Enterprise-grade DNS blocklist builder with security hardening, async I/O, and comprehensive validation.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import ssl
import sys
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, AsyncIterator, Callable, Deque, Dict, Final, List, Optional, 
    Set, Tuple, TypeVar, Union, cast, AsyncGenerator, Awaitable
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientTimeout, ClientError
from aiohttp.client_exceptions import ServerTimeoutError, ClientResponseError
from pydantic import BaseModel, Field, ValidationError, validator, HttpUrl, conint, confloat
from pydantic_settings import BaseSettings
import tenacity

# Optional dependencies
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False

try:
    import defusedxml.ElementTree as ET
    DEFUSED_XML_AVAILABLE = True
except ImportError:
    DEFUSED_XML_AVAILABLE = False
    import xml.etree.ElementTree as ET

# ============================================================================
# CONFIGURATION MODELS (Pydantic)
# ============================================================================

class SecurityConfig(BaseModel):
    """Security-related configuration."""
    
    allowed_domains: Set[str] = Field(
        default_factory=lambda: {
            'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
            'raw.github.com', 'github.com', 'gist.github.com', 'gitlab.com',
            'bitbucket.org', 'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch',
            'threatfox.abuse.ch', 'hole.cert.pl', 'someonewhocares.org',
            'pgl.yoyo.org', 's3.amazonaws.com', 'hosts-file.net'
        },
        description="Allowed domains for source URLs"
    )
    
    blocked_ip_ranges: List[str] = Field(
        default=[
            '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
            '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96',
            '100.64.0.0/10', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'
        ],
        description="Blocked IP ranges (RFC 1918, multicast, reserved)"
    )
    
    max_redirects: int = Field(3, ge=0, le=10, description="Maximum HTTP redirects")
    user_agent: str = Field("DNS-Blocklist-Builder/17.0.0", description="HTTP User-Agent")
    
    @validator('blocked_ip_ranges', each_item=True)
    def validate_ip_range(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid IP network: {v}") from e
        return v


class PerformanceConfig(BaseModel):
    """Performance tuning configuration."""
    
    max_concurrent_downloads: conint(ge=1, le=50) = Field(10, description="Max concurrent downloads")
    connection_limit_per_host: conint(ge=1, le=20) = Field(5, description="Connections per host")
    
    http_timeout: conint(ge=1, le=300) = Field(30, description="HTTP timeout in seconds")
    dns_timeout: conint(ge=1, le=60) = Field(10, description="DNS timeout in seconds")
    
    max_domains_total: conint(ge=1000, le=10000000) = Field(2000000, description="Max domains to process")
    max_file_size_mb: conint(ge=1, le=1024) = Field(100, description="Max source file size in MB")
    
    stream_buffer_size: conint(ge=1024, le=1048576) = Field(16384, description="Stream buffer size in bytes")
    flush_interval: conint(ge=1000, le=100000) = Field(50000, description="Flush interval for writes")
    
    bloom_filter_error_rate: confloat(ge=0.0001, le=0.1) = Field(0.001, description="Bloom filter error rate")
    bloom_filter_capacity: conint(ge=10000, le=10000000) = Field(2000000, description="Bloom filter capacity")
    
    dns_cache_size: conint(ge=1000, le=500000) = Field(50000, description="DNS cache size")
    dns_cache_ttl: conint(ge=60, le=3600) = Field(600, description="DNS cache TTL in seconds")
    
    use_bloom_filter: bool = Field(True, description="Use Bloom filter for deduplication")
    
    @validator('use_bloom_filter', always=True)
    def validate_bloom_availability(cls, v: bool) -> bool:
        if v and not BLOOM_AVAILABLE:
            logging.warning("Bloom filter requested but pybloom-live not installed. Falling back to set.")
            return False
        return v


class SourceConfig(BaseModel):
    """Source configuration."""
    
    name: str = Field(..., min_length=1, max_length=100)
    url: HttpUrl = Field(..., description="Source URL")
    source_type: str = Field(..., pattern='^(hosts|domains|adblock)$')
    enabled: bool = Field(True)
    priority: conint(ge=0, le=100) = Field(0)
    max_size_mb: conint(ge=1, le=1024) = Field(100)
    verify_ssl: bool = Field(True)
    
    @validator('source_type')
    def validate_source_type(cls, v: str) -> str:
        if v not in ['hosts', 'domains', 'adblock']:
            raise ValueError(f"Invalid source type: {v}")
        return v


class AppSettings(BaseSettings):
    """Application settings with environment variable support."""
    
    # Security
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    
    # Performance
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    
    # Logging
    log_level: str = Field("INFO", pattern='^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    log_json: bool = Field(True)
    log_file: Optional[Path] = Field(None)
    
    # Output
    output_path: Path = Field(Path("./blocklist.txt"))
    output_compression: bool = Field(False)
    
    class Config:
        env_prefix = "DNSBL_"
        env_nested_delimiter = "__"
        case_sensitive = False


# ============================================================================
# DOMAIN MODELS
# ============================================================================

class DomainStatus(Enum):
    """Domain validation status."""
    VALID = "valid"
    INVALID = "invalid"
    DUPLICATE = "duplicate"
    AI_DETECTED = "ai_detected"
    BLOCKED = "blocked"


class DomainRecord(BaseModel):
    """Immutable domain record with validation."""
    
    domain: str = Field(..., min_length=3, max_length=253)
    source: str = Field(..., min_length=1, max_length=100)
    status: DomainStatus
    ai_confidence: float = Field(0.0, ge=0.0, le=1.0)
    ai_reasons: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @validator('domain')
    def validate_domain(cls, v: str) -> str:
        """ReDoS-safe domain validation."""
        v = v.lower().strip()
        
        # Basic length checks
        if len(v) < 3 or len(v) > 253:
            raise ValueError(f"Domain length {len(v)} outside valid range")
        
        # Split into labels
        labels = v.split('.')
        if len(labels) < 2:
            raise ValueError("Domain must have at least two labels")
        
        # Check each label
        for label in labels:
            if not label or len(label) > 63:
                raise ValueError(f"Invalid label length: {label}")
            if label.startswith('-') or label.endswith('-'):
                raise ValueError(f"Label cannot start/end with hyphen: {label}")
            if not re.match(r'^[a-z0-9-]+$', label):
                raise ValueError(f"Invalid characters in label: {label}")
        
        # Reserved TLDs
        reserved_tlds = {'localhost', 'local', 'example', 'invalid', 'test', 'lan'}
        if labels[-1] in reserved_tlds:
            raise ValueError(f"Reserved TLD: {labels[-1]}")
        
        return v
    
    def to_hosts_entry(self) -> str:
        """Convert to hosts file format with sanitization."""
        safe_domain = re.sub(r'[\x00-\x1f\x7f\s#|&]', '', self.domain)
        safe_domain = safe_domain[:253]
        
        if self.ai_confidence >= 0.65:
            safe_reasons = [re.sub(r'[^\w\-]', '_', r)[:50] for r in self.ai_reasons[:2]]
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{','.join(safe_reasons)}]"
        
        return f"0.0.0.0 {safe_domain}"
    
    class Config:
        frozen = True


# ============================================================================
# CACHE IMPLEMENTATION
# ============================================================================

T = TypeVar('T')

class AsyncTTLCache(Generic[T]):
    """Async thread-safe cache with TTL."""
    
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
        """Get value from cache if not expired."""
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            value, timestamp = self._cache[key]
            if time.monotonic() - timestamp > self.ttl:
                del self._cache[key]
                self._misses += 1
                return None
            
            # Update access order (LRU)
            self._access_order.remove(key)
            self._access_order.append(key)
            self._hits += 1
            return value
    
    async def set(self, key: str, value: T) -> None:
        """Set value in cache."""
        async with self._lock:
            # Evict oldest if at capacity
            if len(self._cache) >= self.maxsize:
                oldest = self._access_order.popleft()
                del self._cache[oldest]
            
            # Remove existing key if present
            if key in self._cache:
                self._access_order.remove(key)
            
            self._cache[key] = (value, time.monotonic())
            self._access_order.append(key)
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._hits = 0
            self._misses = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0


# ============================================================================
# DEDUPLICATION MANAGER
# ============================================================================

class DeduplicationManager:
    """Domain deduplication with Bloom filter fallback."""
    
    def __init__(self, expected_elements: int, error_rate: float = 0.001, use_bloom: bool = True):
        self._use_bloom = use_bloom and BLOOM_AVAILABLE
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
        """Add domain and return True if duplicate."""
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
            return True
        
        self._bloom.add(domain)
        return False
    
    @property
    def unique_count(self) -> int:
        """Get number of unique domains."""
        if self._use_bloom:
            return len(self._bloom)
        return len(self._domains)
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        if self._use_bloom:
            return {
                "use_bloom": True,
                "unique": len(self._bloom),
                "false_positives": self._false_positives
            }
        return {"use_bloom": False, "unique": len(self._domains)}


# ============================================================================
# SSRF PROTECTOR WITH DNS REBINDING DETECTION
# ============================================================================

class SSRFProtector:
    """Protection against SSRF and DNS rebinding attacks."""
    
    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        
        # Pre-parse blocked networks
        self._blocked_networks_v4: List[ipaddress.IPv4Network] = []
        self._blocked_networks_v6: List[ipaddress.IPv6Network] = []
        
        for net in settings.security.blocked_ip_ranges:
            try:
                network = ipaddress.ip_network(net, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    self._blocked_networks_v4.append(network)
                else:
                    self._blocked_networks_v6.append(network)
            except ValueError as e:
                self._logger.warning(f"Invalid blocked IP range {net}: {e}")
        
        self._checked_urls: AsyncTTLCache[bool] = AsyncTTLCache(maxsize=10000, ttl_seconds=3600)
        self._dns_cache: AsyncTTLCache[List[str]] = AsyncTTLCache(
            maxsize=settings.performance.dns_cache_size,
            ttl_seconds=settings.performance.dns_cache_ttl
        )
        self._rate_limiter = asyncio.Semaphore(20)
    
    async def validate_url(self, url: str) -> None:
        """Validate URL for SSRF vulnerabilities."""
        normalized = self._normalize_url(url)
        
        # Check cache
        cached = await self._checked_urls.get(normalized)
        if cached is not None:
            return
        
        async with self._rate_limiter:
            await self._validate_url_impl(normalized)
        
        await self._checked_urls.set(normalized, True)
    
    async def _validate_url_impl(self, url: str) -> None:
        """Implementation of URL validation."""
        parsed = urlparse(url)
        
        # Validate scheme
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        if not parsed.hostname:
            raise ValueError(f"No hostname in URL: {url}")
        
        # Check against allowed domains
        if parsed.hostname not in self._settings.security.allowed_domains:
            await self._validate_with_rebinding_protection(parsed.hostname)
    
    async def _validate_with_rebinding_protection(self, hostname: str) -> None:
        """Validate hostname with DNS rebinding protection."""
        results: List[Set[str]] = []
        rebinding_checks = 2
        rebinding_delay = 0.5
        
        for attempt in range(rebinding_checks):
            ips = await self._resolve_hostname(hostname)
            results.append(set(ips))
            
            if attempt < rebinding_checks - 1:
                await asyncio.sleep(rebinding_delay)
        
        # Check for DNS rebinding
        if len(results) > 1 and results[0] != results[-1]:
            raise ValueError(f"DNS rebinding detected for {hostname}")
        
        # Validate all IPs
        for ip_str in results[-1]:
            await self._validate_ip_address(ip_str, hostname)
    
    async def _validate_ip_address(self, ip_str: str, hostname: str) -> None:
        """Validate IP address against blocked ranges."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip_str} for {hostname}") from e
        
        networks = (self._blocked_networks_v4 if isinstance(ip, ipaddress.IPv4Address) 
                   else self._blocked_networks_v6)
        
        for blocked_net in networks:
            if ip in blocked_net:
                raise ValueError(f"IP {ip} for {hostname} is in blocked range {blocked_net}")
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses with caching."""
        cached = await self._dns_cache.get(hostname)
        if cached is not None:
            return cached
        
        loop = asyncio.get_running_loop()
        try:
            # Use getaddrinfo with timeout
            ips = await asyncio.wait_for(
                loop.run_in_executor(
                    None, 
                    socket.getaddrinfo, 
                    hostname, None, 0, socket.SOCK_STREAM, 0
                ),
                timeout=self._settings.performance.dns_timeout
            )
            result = list(set(ip[4][0] for ip in ips))
            await self._dns_cache.set(hostname, result)
            return result
        except (socket.gaierror, asyncio.TimeoutError) as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for caching."""
        parsed = urlparse(url)
        return parsed._replace(
            netloc=parsed.hostname or '',
            fragment='',
            query='',
            params=''
        ).geturl()
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        await self._checked_urls.clear()
        await self._dns_cache.clear()


# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """ReDoS-safe domain validator with caching."""
    
    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        self._cache: AsyncTTLCache[bool] = AsyncTTLCache(
            maxsize=settings.performance.dns_cache_size,
            ttl_seconds=settings.performance.dns_cache_ttl
        )
    
    async def is_valid(self, domain: str) -> bool:
        """Validate domain syntax."""
        if len(domain) > 1024:  # Max input length
            return False
        
        domain_lower = domain.lower().strip()
        
        # Check cache
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        # Validate
        try:
            DomainRecord(
                domain=domain_lower,
                source="validator",
                status=DomainStatus.VALID
            )
            valid = True
        except ValidationError:
            valid = False
        
        await self._cache.set(domain_lower, valid)
        return valid
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        await self._cache.clear()


# ============================================================================
# AI TRACKER DETECTOR
# ============================================================================

class AITrackerDetector:
    """AI-powered tracker detection with pattern matching."""
    
    TRACKER_PATTERNS: Final[List[Tuple[re.Pattern, str, float]]] = [
        (re.compile(r'\banalytics\b', re.IGNORECASE), 'analytics', 0.82),
        (re.compile(r'\bgoogle[-_]analytics\b', re.IGNORECASE), 'google_analytics', 0.95),
        (re.compile(r'\bgoogletagmanager\b', re.IGNORECASE), 'google_tag_manager', 0.92),
        (re.compile(r'\bgtm\b', re.IGNORECASE), 'google_tag_manager', 0.85),
        (re.compile(r'\bfirebase\b', re.IGNORECASE), 'firebase_analytics', 0.92),
        (re.compile(r'\bamplitude\b', re.IGNORECASE), 'amplitude', 0.90),
        (re.compile(r'\bmixpanel\b', re.IGNORECASE), 'mixpanel', 0.90),
        (re.compile(r'\bsegment\b', re.IGNORECASE), 'segment', 0.90),
        (re.compile(r'\btracking\b', re.IGNORECASE), 'tracking', 0.80),
        (re.compile(r'\bpixel\b', re.IGNORECASE), 'tracking_pixel', 0.85),
        (re.compile(r'\bbeacon\b', re.IGNORECASE), 'tracking_beacon', 0.85),
        (re.compile(r'\bdoubleclick\b', re.IGNORECASE), 'doubleclick', 0.95),
        (re.compile(r'\badservice\b', re.IGNORECASE), 'ad_service', 0.85),
        (re.compile(r'\bcriteo\b', re.IGNORECASE), 'criteo', 0.85),
        (re.compile(r'\bfacebook\b', re.IGNORECASE), 'facebook_pixel', 0.95),
        (re.compile(r'\btwitter\b', re.IGNORECASE), 'twitter_tracker', 0.82),
        (re.compile(r'\bsentry\b', re.IGNORECASE), 'error_tracking', 0.75),
        (re.compile(r'\bhotjar\b', re.IGNORECASE), 'user_behavior', 0.85),
        (re.compile(r'\bclarity\b', re.IGNORECASE), 'microsoft_analytics', 0.85),
        (re.compile(r'\bappsflyer\b', re.IGNORECASE), 'appsflyer', 0.90),
    ]
    
    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        self._cache: AsyncTTLCache[Tuple[float, List[str]]] = AsyncTTLCache(
            maxsize=settings.performance.dns_cache_size,
            ttl_seconds=7200
        )
    
    async def analyze(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze domain for tracker patterns."""
        if len(domain) > 1024:
            return (0.0, [])
        
        domain_lower = domain.lower()
        
        # Check cache
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        confidence = 0.0
        reasons: List[str] = []
        
        for pattern, reason, base_conf in self.TRACKER_PATTERNS:
            try:
                if pattern.search(domain_lower):
                    confidence = max(confidence, base_conf)
                    if reason not in reasons:
                        reasons.append(reason)
            except re.error:
                continue
        
        result = (min(1.0, confidence), reasons)
        await self._cache.set(domain_lower, result)
        return result
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        await self._cache.clear()


# ============================================================================
# STREAMING SOURCE PROCESSOR
# ============================================================================

class SourceProcessor:
    """Streaming processor for DNS blocklist sources."""
    
    def __init__(self, session: aiohttp.ClientSession, settings: AppSettings):
        self._session = session
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        self._ssrf_protector = SSRFProtector(settings)
        self._validator = DomainValidator(settings)
        self._detector = AITrackerDetector(settings)
        self._valid_count = 0
    
    async def process_source(self, source: SourceConfig) -> AsyncGenerator[DomainRecord, None]:
        """Process a single source and yield valid domains."""
        if not source.enabled:
            return
        
        try:
            await self._ssrf_protector.validate_url(str(source.url))
            
            async for line in self._stream_download(source):
                domain = self._parse_line(line, source.source_type)
                if not domain:
                    continue
                
                if not await self._validator.is_valid(domain):
                    continue
                
                self._valid_count += 1
                
                # AI analysis
                ai_confidence, ai_reasons = await self._detector.analyze(domain)
                
                yield DomainRecord(
                    domain=domain,
                    source=source.name,
                    status=DomainStatus.VALID,
                    ai_confidence=ai_confidence,
                    ai_reasons=ai_reasons
                )
                
                if self._valid_count >= self._settings.performance.max_domains_total:
                    self._logger.info("Reached domain limit", extra={
                        "limit": self._settings.performance.max_domains_total
                    })
                    break
            
            self._logger.info("Source processed", extra={
                "source": source.name,
                "valid_count": self._valid_count
            })
            
        except Exception as e:
            self._logger.error("Source processing failed", extra={
                "source": source.name,
                "error": str(e)
            }, exc_info=True)
            raise
    
    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=1, max=30),
        retry=tenacity.retry_if_exception_type((ClientError, ServerTimeoutError, asyncio.TimeoutError))
    )
    async def _stream_download(self, source: SourceConfig) -> AsyncGenerator[str, None]:
        """Stream download with retries and size limits."""
        timeout = ClientTimeout(total=self._settings.performance.http_timeout)
        
        async with self._session.get(
            str(source.url),
            timeout=timeout,
            max_redirects=self._settings.security.max_redirects,
            raise_for_status=True,
            ssl=source.verify_ssl
        ) as response:
            # Check content length
            content_length = response.headers.get('Content-Length')
            if content_length:
                size_mb = int(content_length) / (1024 * 1024)
                if size_mb > source.max_size_mb:
                    raise ValueError(f"File too large: {size_mb:.1f} MB > {source.max_size_mb} MB")
            
            # Stream content
            buffer = bytearray()
            async for chunk in response.content.iter_chunked(self._settings.performance.stream_buffer_size):
                buffer.extend(chunk)
                
                # Process complete lines
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    if len(line) > 1024:  # Skip too long lines
                        continue
                    
                    try:
                        yield line.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        continue
            
            # Process remaining buffer
            if buffer and len(buffer) <= 1024:
                try:
                    yield buffer.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    pass
    
    def _parse_line(self, line: str, source_type: str) -> Optional[str]:
        """Parse line based on source type."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        if source_type == 'hosts':
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                domain = parts[1].split('#')[0].strip()
                if domain and len(domain) <= 253:
                    return domain
        
        elif source_type == 'domains':
            domain = line.split('#')[0].strip()
            if domain and len(domain) <= 253:
                return domain
        
        return None
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        await self._ssrf_protector.cleanup()
        await self._validator.cleanup()
        await self._detector.cleanup()


# ============================================================================
# BLOCKLIST BUILDER
# ============================================================================

class BlocklistBuilder:
    """Main blocklist builder with progress tracking."""
    
    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        self._output_path = settings.output_path
        self._start_time: float = 0.0
        
        # Statistics
        self._sources_processed = 0
        self._sources_failed = 0
        self._total_valid = 0
        self._duplicates = 0
        self._ai_detected = 0
        
        # Deduplication
        self._deduplicator = DeduplicationManager(
            expected_elements=settings.performance.max_domains_total,
            error_rate=settings.performance.bloom_filter_error_rate,
            use_bloom=settings.performance.use_bloom_filter
        )
        
        self._shutdown_requested = False
        self._shutdown_event = asyncio.Event()
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self) -> None:
        """Setup graceful shutdown signal handlers."""
        loop = asyncio.get_running_loop()
        
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self._shutdown()))
    
    async def _shutdown(self) -> None:
        """Graceful shutdown."""
        self._logger.warning("Shutdown requested, stopping build...")
        self._shutdown_requested = True
        self._shutdown_event.set()
    
    async def build(self, sources: List[SourceConfig]) -> bool:
        """Build the blocklist."""
        self._start_time = time.time()
        
        self._logger.info("Starting blocklist build", extra={
            "version": "17.0.0",
            "sources": len(sources),
            "use_bloom": self._settings.performance.use_bloom_filter,
            "max_domains": self._settings.performance.max_domains_total
        })
        
        try:
            async with self._create_session() as session:
                processor = SourceProcessor(session, self._settings)
                
                # Ensure output directory exists
                self._output_path.parent.mkdir(parents=True, exist_ok=True)
                
                async with aiofiles.open(self._output_path, 'w', encoding='utf-8') as outfile:
                    await self._write_header(outfile)
                    
                    write_buffer = []
                    flush_interval = self._settings.performance.flush_interval
                    
                    for source in sorted(sources, key=lambda s: s.priority):
                        if self._shutdown_requested:
                            self._logger.warning("Shutdown requested, stopping build")
                            break
                        
                        try:
                            async for record in processor.process_source(source):
                                if self._shutdown_requested:
                                    break
                                
                                if self._deduplicator.add(record.domain):
                                    self._duplicates += 1
                                    continue
                                
                                self._total_valid += 1
                                
                                if record.ai_confidence >= 0.65:
                                    self._ai_detected += 1
                                
                                write_buffer.append(record.to_hosts_entry() + "\n")
                                
                                if len(write_buffer) >= flush_interval:
                                    await outfile.writelines(write_buffer)
                                    write_buffer.clear()
                            
                            self._sources_processed += 1
                            
                        except Exception as e:
                            self._sources_failed += 1
                            self._logger.error("Source failed", extra={
                                "source": source.name,
                                "error": str(e)
                            }, exc_info=True)
                    
                    # Write remaining buffer
                    if write_buffer:
                        await outfile.writelines(write_buffer)
                    
                    await self._write_footer(outfile)
                
                await processor.cleanup()
                
                self._print_summary()
                return True
                
        except Exception as e:
            self._logger.critical("Build failed", extra={"error": str(e)}, exc_info=True)
            return False
    
    @asynccontextmanager
    async def _create_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        """Create configured HTTP session."""
        # SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        connector = aiohttp.TCPConnector(
            limit=self._settings.performance.max_concurrent_downloads,
            limit_per_host=self._settings.performance.connection_limit_per_host,
            ttl_dns_cache=300,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        timeout = ClientTimeout(total=self._settings.performance.http_timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self._settings.security.user_agent}
        ) as session:
            yield session
    
    async def _write_header(self, outfile) -> None:
        """Write blocklist header."""
        await outfile.write("# DNS Security Blocklist v17.0.0\n")
        await outfile.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        await outfile.write(f"# Build ID: {uuid.uuid4().hex[:8]}\n")
        await outfile.write("# Format: 0.0.0.0 domain [AI detection info]\n")
        await outfile.write("# This blocklist protects against trackers, ads, and malicious domains\n\n")
    
    async def _write_footer(self, outfile) -> None:
        """Write blocklist footer with statistics."""
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
        
        if self._settings.performance.use_bloom_filter:
            stats = self._deduplicator.stats
            await outfile.write(f"# - Deduplication: Bloom filter (error rate: {self._settings.performance.bloom_filter_error_rate:.3%})\n")
            await outfile.write(f"# - False positives: {stats.get('false_positives', 0):,}\n")
        
        await outfile.write("# ============================================================================\n")
    
    def _print_summary(self) -> None:
        """Print build summary."""
        duration = time.time() - self._start_time
        
        output = {
            "status": "success",
            "duration_seconds": duration,
            "unique_domains": self._total_valid,
            "duplicates": self._duplicates,
            "ai_detected": self._ai_detected,
            "sources_processed": self._sources_processed,
            "sources_failed": self._sources_failed,
            "use_bloom": self._settings.performance.use_bloom_filter,
            "output_path": str(self._output_path)
        }
        
        # Machine-readable output
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
    """Manage blocklist sources."""
    
    @staticmethod
    def get_default_sources() -> List[SourceConfig]:
        """Get default source list."""
        return [
            SourceConfig(
                name="OISD Big",
                url="https://big.oisd.nl/domains",
                source_type="domains",
                priority=1
            ),
            SourceConfig(
                name="AdAway",
                url="https://adaway.org/hosts.txt",
                source_type="hosts",
                priority=2
            ),
            SourceConfig(
                name="URLhaus",
                url="https://urlhaus.abuse.ch/downloads/hostfile/",
                source_type="hosts",
                priority=3
            ),
            SourceConfig(
                name="ThreatFox",
                url="https://threatfox.abuse.ch/downloads/hostfile/",
                source_type="hosts",
                priority=4
            ),
            SourceConfig(
                name="Cert Poland",
                url="https://hole.cert.pl/domains/domains_hosts.txt",
                source_type="hosts",
                priority=5
            ),
        ]
    
    @staticmethod
    def load_from_file(path: Path) -> List[SourceConfig]:
        """Load sources from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)
        
        sources = []
        for item in data:
            sources.append(SourceConfig(**item))
        
        return sources


# ============================================================================
# MAIN APPLICATION
# ============================================================================

async def main_async() -> int:
    """Async main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="DNS Security Blocklist Builder v17.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-o", "--output", type=Path, help="Output file path")
    parser.add_argument("--config", type=Path, help="Configuration file path")
    parser.add_argument("--sources", type=Path, help="Sources JSON file path")
    parser.add_argument("--max-domains", type=int, help="Maximum domains to process")
    parser.add_argument("--timeout", type=int, help="Download timeout in seconds")
    parser.add_argument("--no-bloom", action="store_true", help="Disable Bloom filter")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--version", action="version", version="DNS Blocklist Builder v17.0.0")
    
    args = parser.parse_args()
    
    # Load settings
    settings = AppSettings()
    
    # Override with command line arguments
    if args.output:
        settings.output_path = args.output
    if args.max_domains:
        settings.performance.max_domains_total = args.max_domains
    if args.timeout:
        settings.performance.http_timeout = args.timeout
    if args.no_bloom:
        settings.performance.use_bloom_filter = False
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else settings.log_level
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(settings.log_file) if settings.log_file else logging.NullHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Load sources
        if args.sources and args.sources.exists():
            sources = SourceManager.load_from_file(args.sources)
        else:
            sources = SourceManager.get_default_sources()
        
        # Build blocklist
        builder = BlocklistBuilder(settings)
        success = await builder.build(sources)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.critical("Fatal error", exc_info=True)
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
