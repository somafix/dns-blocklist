#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION READY (v12.0.0)
ENHANCED: AI Detection, Streaming Processing, Change Tracking
"""

import argparse
import asyncio
import gzip
import hashlib
import ipaddress
import json
import logging
import re
import signal
import ssl
import sys
import time
import warnings
from collections import defaultdict, deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from functools import lru_cache, wraps
from pathlib import Path
from typing import (
    Any, AsyncIterator, ClassVar, Deque, Dict, Final, List, 
    Optional, Set, Tuple, Union, cast
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientResponse, ClientTimeout
from aiohttp.client_exceptions import ClientError, ClientConnectorError

# Suppress specific warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ============================================================================
# VERSION & METADATA
# ============================================================================

VERSION: Final[str] = "12.0.0"
__version__ = VERSION
__author__ = "DNS Security Team"
__license__ = "MIT"

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

class Constants:
    """Centralized constants with type safety and validation"""
    
    # Domain validation
    MAX_DOMAIN_LEN: Final[int] = 253
    MAX_LABEL_LEN: Final[int] = 63
    MIN_DOMAIN_LEN: Final[int] = 3
    
    # File operations
    TEMP_SUFFIX: Final[str] = '.tmp'
    BACKUP_SUFFIX: Final[str] = '.backup'
    BATCH_WRITE_SIZE: Final[int] = 131072  # 128KB
    COMPRESSION_LEVEL: Final[int] = 6
    STREAMING_BATCH_SIZE: Final[int] = 50000  # Для потоковой обработки
    
    # Network settings
    MAX_CONCURRENT_DOWNLOADS: Final[int] = 10
    DEFAULT_TIMEOUT: Final[int] = 30
    MAX_RETRIES: Final[int] = 3
    RETRY_BACKOFF: Final[float] = 1.5
    MAX_FILE_SIZE_MB: Final[int] = 100
    MAX_REDIRECTS: Final[int] = 5
    CONNECTION_LIMIT_PER_HOST: Final[int] = 2
    RATE_LIMIT_REQUESTS: Final[int] = 5
    RATE_LIMIT_WINDOW: Final[int] = 1
    
    # Cache settings
    DNS_CACHE_SIZE: Final[int] = 200000
    DNS_CACHE_TTL: Final[int] = 300
    AI_CACHE_SIZE: Final[int] = 200000
    AI_CACHE_TTL: Final[int] = 3600
    AI_BATCH_SIZE: Final[int] = 500
    
    # Security
    ALLOWED_SCHEMES: Final[Set[str]] = {'http', 'https'}
    BLOCKED_IP_RANGES: Final[Tuple[str, ...]] = (
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96'
    )
    
    ALLOWED_DOMAINS: Final[Set[str]] = {
        'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
        'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
        'hole.cert.pl'
    }
    
    RESERVED_TLDS: Final[Set[str]] = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p',
        'corp', 'private', 'intranet'
    }
    
    # AI Detection - Улучшенные паттерны
    USER_AGENT: Final[str] = f'Mozilla/5.0 (compatible; DNS-Blocklist-Builder/{VERSION})'
    AI_CONFIDENCE_THRESHOLD: Final[float] = 0.65
    SUSPICIOUS_SUBDOMAIN_DEPTH: Final[int] = 5
    RANDOM_SUBDOMAIN_LEN: Final[int] = 30  # Поддомены длиннее этого считаем подозрительными
    
    # Performance
    MAX_DOMAINS_DEFAULT: Final[int] = 1000000
    MEMORY_LIMIT_MB: Final[int] = 512
    GC_THRESHOLD: Final[int] = 10000
    
    # Health checks
    HEALTH_CHECK_INTERVAL: Final[int] = 30
    TASK_TIMEOUT: Final[int] = 300
    
    @classmethod
    def validate(cls) -> None:
        """Validate all constants for consistency"""
        assert cls.MAX_CONCURRENT_DOWNLOADS > 0
        assert cls.DEFAULT_TIMEOUT > 0
        assert 0 <= cls.AI_CONFIDENCE_THRESHOLD <= 1
        assert cls.MAX_DOMAINS_DEFAULT > 0


# ============================================================================
# ENUMS
# ============================================================================

class SourceType(Enum):
    """Type of source file format"""
    HOSTS = auto()
    DOMAINS = auto()
    ADBLOCK = auto()


class DomainStatus(Enum):
    """Status of domain in processing pipeline"""
    VALID = auto()
    INVALID = auto()
    DUPLICATE = auto()
    AI_DETECTED = auto()
    BLOCKED = auto()
    WHITELISTED = auto()


class Severity(Enum):
    """Severity levels for monitoring"""
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass(frozen=True, slots=True)
class DomainRecord:
    """Immutable domain record with metadata"""
    domain: str
    source: str
    status: DomainStatus
    ai_confidence: float = 0.0
    ai_reasons: Tuple[str, ...] = field(default_factory=tuple)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self) -> None:
        """Validate record after initialization"""
        if not self.domain or not isinstance(self.domain, str):
            raise ValueError(f"Invalid domain: {self.domain}")
        if not 0 <= self.ai_confidence <= 1:
            raise ValueError(f"Invalid confidence: {self.ai_confidence}")
    
    def to_hosts_entry(self) -> str:
        """Convert to hosts file format with sanitization"""
        safe_domain = self._sanitize_domain()
        
        if self.ai_confidence > Constants.AI_CONFIDENCE_THRESHOLD:
            reasons = ','.join(r.replace(',', '\\,').replace('"', '\\"') 
                              for r in self.ai_reasons[:2])
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{reasons}]"
        return f"0.0.0.0 {safe_domain}"
    
    def _sanitize_domain(self) -> str:
        """Sanitize domain to prevent injection"""
        return re.sub(r'[\n\r\t\v\f\x00-\x1f\x7f]', '', self.domain)
    
    def to_json(self) -> Dict[str, Any]:
        """Serialize to JSON"""
        return {
            'domain': self.domain,
            'source': self.source,
            'status': self.status.name,
            'ai_confidence': self.ai_confidence,
            'ai_reasons': list(self.ai_reasons),
            'timestamp': self.timestamp.isoformat()
        }


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    """Immutable source definition"""
    name: str
    url: str
    source_type: SourceType
    enabled: bool = True
    priority: int = 0
    max_size_mb: int = Constants.MAX_FILE_SIZE_MB
    etag_file: Optional[Path] = None
    
    def __post_init__(self) -> None:
        """Validate source"""
        if not self.name or not self.url:
            raise ValueError(f"Invalid source: {self.name}")
        parsed = urlparse(self.url)
        if parsed.scheme not in Constants.ALLOWED_SCHEMES:
            raise ValueError(f"Invalid scheme: {parsed.scheme}")


@dataclass
class AIDetectionStats:
    """Statistics for AI detection"""
    total_analyzed: int = 0
    detected_trackers: int = 0
    avg_confidence: float = 0.0
    pattern_hits: Dict[str, int] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
    
    def update(self, domain: str, confidence: float, reasons: Tuple[str, ...]) -> None:
        """Update statistics with detection results"""
        self.total_analyzed += 1
        if confidence > 0:
            self.detected_trackers += 1
            total_conf = self.avg_confidence * (self.detected_trackers - 1) + confidence
            self.avg_confidence = total_conf / self.detected_trackers
            
            for reason in reasons:
                self.pattern_hits[reason] = self.pattern_hits.get(reason, 0) + 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_analyzed': self.total_analyzed,
            'detected_trackers': self.detected_trackers,
            'detection_rate': self.detected_trackers / max(1, self.total_analyzed),
            'avg_confidence': round(self.avg_confidence, 3),
            'top_patterns': dict(sorted(self.pattern_hits.items(), key=lambda x: x[1], reverse=True)[:10]),
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses
        }


@dataclass
class BuildStats:
    """Build statistics for monitoring"""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    sources_processed: int = 0
    sources_failed: int = 0
    sources_unchanged: int = 0
    total_raw_domains: int = 0
    valid_domains: int = 0
    ai_detected: int = 0
    duplicates_removed: int = 0
    invalid_domains: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    ai_stats: AIDetectionStats = field(default_factory=AIDetectionStats)
    
    @property
    def duration(self) -> float:
        """Get build duration in seconds"""
        end = self.end_time or time.time()
        return end - self.start_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'version': VERSION,
            'duration_seconds': round(self.duration, 2),
            'sources_processed': self.sources_processed,
            'sources_failed': self.sources_failed,
            'sources_unchanged': self.sources_unchanged,
            'total_raw_domains': self.total_raw_domains,
            'valid_domains': self.valid_domains,
            'ai_detected': self.ai_detected,
            'duplicates_removed': self.duplicates_removed,
            'invalid_domains': self.invalid_domains,
            'ai_stats': self.ai_stats.to_dict(),
            'errors': self.errors[:10],
            'warnings': self.warnings[:10]
        }


@dataclass
class Config:
    """Configuration with validation"""
    output_dynamic: Path = Path('./dynamic-blocklist.txt')
    output_simple: Path = Path('./blocklist.txt')
    output_compressed: Optional[Path] = None
    output_json: Optional[Path] = None
    output_ai_report: Optional[Path] = None
    max_domains: int = Constants.MAX_DOMAINS_DEFAULT
    timeout: int = Constants.DEFAULT_TIMEOUT
    max_retries: int = Constants.MAX_RETRIES
    concurrent_downloads: int = Constants.MAX_CONCURRENT_DOWNLOADS
    ai_enabled: bool = True
    ai_confidence_threshold: float = Constants.AI_CONFIDENCE_THRESHOLD
    verbose: bool = False
    quiet: bool = False
    enable_compression: bool = True
    enable_json: bool = False
    enable_change_tracking: bool = True
    memory_limit_mb: int = Constants.MEMORY_LIMIT_MB
    streaming_mode: bool = False  # Для обработки очень больших списков
    
    def __post_init__(self) -> None:
        """Validate and setup configuration"""
        self._validate()
        self._create_directories()
    
    def _validate(self) -> None:
        """Validate configuration values"""
        if self.max_domains <= 0:
            raise ValueError(f"Invalid max_domains: {self.max_domains}")
        if not 1 <= self.timeout <= 300:
            raise ValueError(f"Invalid timeout: {self.timeout}")
        if not 1 <= self.concurrent_downloads <= 50:
            raise ValueError(f"Invalid concurrent_downloads: {self.concurrent_downloads}")
        if not 0 <= self.ai_confidence_threshold <= 1:
            raise ValueError(f"Invalid threshold: {self.ai_confidence_threshold}")
        
        # Автоматически включаем streaming для больших списков
        if self.max_domains > 500000:
            self.streaming_mode = True
    
    def _create_directories(self) -> None:
        """Create output directories if they don't exist"""
        self.output_dynamic.parent.mkdir(parents=True, exist_ok=True)
        self.output_simple.parent.mkdir(parents=True, exist_ok=True)
        if self.output_compressed:
            self.output_compressed.parent.mkdir(parents=True, exist_ok=True)
        if self.output_json:
            self.output_json.parent.mkdir(parents=True, exist_ok=True)
        if self.output_ai_report:
            self.output_ai_report.parent.mkdir(parents=True, exist_ok=True)


# ============================================================================
# CACHE IMPLEMENTATION
# ============================================================================

class TTLCache:
    """Thread-safe cache with TTL support"""
    
    def __init__(self, maxsize: int, ttl_seconds: int) -> None:
        """Initialize cache with size limit and TTL"""
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            value, timestamp = self._cache[key]
            if time.time() - timestamp > self.ttl:
                del self._cache[key]
                self._misses += 1
                return None
            
            self._hits += 1
            return value
    
    async def set(self, key: str, value: Any) -> None:
        """Set value in cache"""
        async with self._lock:
            self._evict_if_needed()
            self._cache[key] = (value, time.time())
    
    async def clear(self) -> None:
        """Clear all cache entries"""
        async with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics"""
        return {'hits': self._hits, 'misses': self._misses}
    
    def _evict_if_needed(self) -> None:
        """Evict oldest entries if cache is full"""
        if len(self._cache) >= self.maxsize:
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]


# ============================================================================
# SSRF PROTECTION
# ============================================================================

class SSRFProtector:
    """Enhanced SSRF protection with rate limiting"""
    
    def __init__(self, session: aiohttp.ClientSession, config: Config) -> None:
        """Initialize SSRF protector"""
        self.session = session
        self.config = config
        self._blocked_networks = [ipaddress.ip_network(net) for net in Constants.BLOCKED_IP_RANGES]
        self._checked_urls: TTLCache = TTLCache(maxsize=10000, ttl_seconds=3600)
        self._dns_cache: TTLCache = TTLCache(
            maxsize=Constants.DNS_CACHE_SIZE, 
            ttl_seconds=Constants.DNS_CACHE_TTL
        )
        self._rate_limiter = asyncio.Semaphore(Constants.RATE_LIMIT_REQUESTS)
    
    async def validate_url(self, url: str) -> None:
        """Validate URL with caching and rate limiting"""
        normalized = self._normalize_url(url)
        
        cached = await self._checked_urls.get(normalized)
        if cached is not None:
            return
        
        async with self._rate_limiter:
            await self._validate_url_impl(normalized)
        
        await self._checked_urls.set(normalized, True)
    
    async def _validate_url_impl(self, url: str) -> None:
        """Implementation of URL validation"""
        parsed = urlparse(url)
        
        if parsed.scheme not in Constants.ALLOWED_SCHEMES:
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        if not parsed.hostname:
            raise ValueError(f"No hostname in URL: {url}")
        
        if parsed.hostname not in Constants.ALLOWED_DOMAINS:
            await self._validate_ip(parsed.hostname)
    
    async def validate_response(self, response: ClientResponse, final_url: str) -> None:
        """Validate response URL"""
        await self.validate_url(final_url)
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for caching"""
        parsed = urlparse(url)
        normalized = parsed._replace(
            netloc=parsed.hostname or '',
            fragment='',
            query=''
        )
        return normalized.geturl()
    
    async def _validate_ip(self, hostname: str) -> None:
        """Validate IP address against blocked ranges"""
        ips = await self._resolve_hostname(hostname)
        for ip_str in ips:
            ip = ipaddress.ip_address(ip_str)
            for blocked_net in self._blocked_networks:
                if ip in blocked_net:
                    raise ValueError(f"IP {ip} is in blocked range {blocked_net}")
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname with caching"""
        cached = await self._dns_cache.get(hostname)
        if cached is not None:
            return cast(List[str], cached)
        
        loop = asyncio.get_event_loop()
        try:
            ips = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=0, type=0, proto=0),
                timeout=10
            )
            result = list(set(ip[4][0] for ip in ips))
            await self._dns_cache.set(hostname, result)
            return result
        except asyncio.TimeoutError:
            raise ValueError(f"DNS resolution timeout for {hostname}")
        except Exception as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")


# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """High-performance domain validator with caching"""
    
    DOMAIN_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$',
        re.IGNORECASE
    )
    
    IDNA_PATTERN: ClassVar[re.Pattern] = re.compile(r'^xn--')
    
    def __init__(self) -> None:
        """Initialize validator with cache"""
        self._cache: TTLCache = TTLCache(
            maxsize=Constants.DNS_CACHE_SIZE,
            ttl_seconds=Constants.DNS_CACHE_TTL
        )
    
    async def is_valid(self, domain: str) -> bool:
        """Check if domain is valid with caching"""
        domain_lower = domain.lower().strip()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        valid = self._validate_syntax(domain_lower)
        await self._cache.set(domain_lower, valid)
        
        return valid
    
    def _validate_syntax(self, domain: str) -> bool:
        """Validate domain syntax"""
        if len(domain) < Constants.MIN_DOMAIN_LEN:
            return False
        if len(domain) > Constants.MAX_DOMAIN_LEN:
            return False
        
        if self.IDNA_PATTERN.match(domain):
            try:
                domain.encode('idna').decode('ascii')
            except (UnicodeError, ValueError):
                return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        if parts[-1] in Constants.RESERVED_TLDS:
            return False
        
        for label in parts:
            if not label or len(label) > Constants.MAX_LABEL_LEN:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        return bool(self.DOMAIN_PATTERN.match(domain))
    
    async def get_stats(self) -> Dict[str, int]:
        """Get validator statistics"""
        return await self._cache.get_stats()
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        await self._cache.clear()


# ============================================================================
# AI TRACKER DETECTOR - УЛУЧШЕННАЯ ВЕРСИЯ
# ============================================================================

class AITrackerDetector:
    """Enhanced ML-inspired tracker detection with context analysis"""
    
    # Расширенные паттерны для современных трекеров
    TRACKER_PATTERNS: ClassVar[Tuple[Tuple[str, str, float], ...]] = (
        # Analytics platforms
        (r'analytics?', 'analytics', 0.82),
        (r'google-analytics', 'google_analytics', 0.95),
        (r'googletagmanager|gtm', 'google_tag_manager', 0.92),
        (r'firebase.*analytics', 'firebase_analytics', 0.92),
        (r'amplitude', 'amplitude', 0.90),
        (r'mixpanel', 'mixpanel', 0.90),
        (r'segment\.com', 'segment', 0.90),
        (r'heap\.io', 'heap_analytics', 0.85),
        
        # Tracking pixels and beacons
        (r'track(?:ing)?', 'tracking', 0.80),
        (r'pixel', 'tracking_pixel', 0.85),
        (r'beacon', 'tracking_beacon', 0.85),
        (r'collect', 'data_collector', 0.80),
        (r'telemetry', 'telemetry', 0.85),
        (r'metrics', 'metrics', 0.78),
        
        # Ad networks
        (r'doubleclick', 'doubleclick', 0.95),
        (r'adservice', 'ad_service', 0.85),
        (r'ads?\.', 'ad_domain', 0.75),
        (r'criteo', 'criteo', 0.85),
        (r'taboola', 'taboola', 0.85),
        (r'outbrain', 'outbrain', 0.85),
        
        # Social media trackers
        (r'facebook\.com/tr', 'facebook_pixel', 0.95),
        (r'twitter\.com/i', 'twitter_tracker', 0.82),
        (r'linkedin.*track', 'linkedin_tracker', 0.85),
        (r'pinterest.*track', 'pinterest_tracker', 0.85),
        
        # CDN analytics
        (r'cdn\..*analytics', 'cdn_analytics', 0.88),
        (r'cloudfront.*analytics', 'cloudfront_analytics', 0.80),
        
        # Error tracking
        (r'sentry\.io', 'error_tracking', 0.75),
        (r'crashlytics', 'crash_reporting', 0.80),
        (r'bugsnag', 'error_tracking', 0.75),
        
        # User behavior
        (r'hotjar', 'user_behavior', 0.85),
        (r'clarity\.ms', 'microsoft_analytics', 0.85),
        (r'fullstory', 'session_recording', 0.85),
        
        # Marketing automation
        (r'marketing.*cloud', 'marketing_cloud', 0.78),
        (r'hubspot', 'marketing_automation', 0.80),
        (r'intercom', 'customer_messaging', 0.75),
        (r'drift', 'chat_tracker', 0.70),
        
        # A/B testing
        (r'optimizely', 'ab_testing', 0.75),
        (r'vwo\.com', 'ab_testing', 0.75),
        
        # App analytics
        (r'appsflyer', 'appsflyer', 0.90),
        (r'appmetrica', 'yandex_metrics', 0.85),
        (r'flurry', 'app_analytics', 0.80),
        
        # Search analytics
        (r'algolia', 'search_analytics', 0.70),
        (r'elastic.*analytics', 'search_analytics', 0.70),
        
        # Stats
        (r'stat(?:s|istic)?', 'statistics', 0.75),
        (r'counter', 'hit_counter', 0.70),
    )
    
    def __init__(self, threshold: float = Constants.AI_CONFIDENCE_THRESHOLD) -> None:
        """Initialize detector with threshold"""
        self.threshold = threshold
        self._cache: TTLCache = TTLCache(
            maxsize=Constants.AI_CACHE_SIZE,
            ttl_seconds=Constants.AI_CACHE_TTL
        )
        self._patterns = [(re.compile(p, re.IGNORECASE), r, c) 
                         for p, r, c in self.TRACKER_PATTERNS]
        self._stats = AIDetectionStats()
    
    async def analyze(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Analyze domain for tracker patterns with caching"""
        domain_lower = domain.lower()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            self._stats.cache_hits += 1
            confidence, reasons = cached
            self._stats.update(domain, confidence, reasons)
            return confidence, reasons
        
        self._stats.cache_misses += 1
        confidence, reasons = self._analyze_with_context(domain_lower)
        
        result = (confidence, reasons)
        await self._cache.set(domain_lower, result)
        self._stats.update(domain, confidence, reasons)
        
        return result
    
    def _analyze_with_context(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Analyze domain with context awareness"""
        confidence, reasons = self._analyze_patterns(domain)
        reasons_list = list(reasons)
        
        # Контекстный анализ поддоменов
        parts = domain.split('.')
        
        # Проверка на очень глубокие поддомены (обычно трекеры)
        if len(parts) > Constants.SUSPICIOUS_SUBDOMAIN_DEPTH:
            confidence = max(confidence, 0.75)
            if 'tracking_depth' not in reasons_list:
                reasons_list.append('tracking_depth')
        
        # Проверка на случайные/длинные поддомены
        for part in parts[:-1]:  # Исключаем TLD
            if len(part) > Constants.RANDOM_SUBDOMAIN_LEN:
                confidence = max(confidence, 0.80)
                if 'random_subdomain' not in reasons_list:
                    reasons_list.append('random_subdomain')
                break
        
        # Проверка на хешированные поддомены (часто используются для трекинга)
        if any(re.match(r'^[a-f0-9]{16,}$', part) for part in parts[:-1]):
            confidence = max(confidence, 0.85)
            if 'hashed_subdomain' not in reasons_list:
                reasons_list.append('hashed_subdomain')
        
        # Проверка на timestamp в поддоменах
        if any(re.search(r'\d{8,}', part) for part in parts[:-1]):
            confidence = max(confidence, 0.75)
            if 'timestamp_subdomain' not in reasons_list:
                reasons_list.append('timestamp_subdomain')
        
        return (confidence, tuple(reasons_list))
    
    def _analyze_patterns(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Analyze domain against patterns"""
        confidence = 0.0
        reasons = []
        
        for pattern, reason, base_conf in self._patterns:
            if pattern.search(domain):
                if base_conf > confidence:
                    confidence = base_conf
                if reason not in reasons:
                    reasons.append(reason)
        
        return (confidence, tuple(reasons))
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics"""
        stats_dict = self._stats.to_dict()
        stats_dict['cache'] = await self._cache.get_stats()
        return stats_dict
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        await self._cache.clear()


# ============================================================================
# SOURCE PROCESSOR - С УЛУЧШЕННЫМ ОБНОВЛЕНИЕМ
# ============================================================================

class SourceProcessor:
    """Process individual source files with change tracking"""
    
    def __init__(
        self,
        session: aiohttp.ClientSession,
        validator: DomainValidator,
        detector: Optional[AITrackerDetector],
        config: Config,
        stats: BuildStats
    ) -> None:
        """Initialize source processor"""
        self.session = session
        self.validator = validator
        self.detector = detector
        self.config = config
        self.stats = stats
        self.ssrf_protector = SSRFProtector(session, config)
        self.ai_results: Dict[str, Tuple[float, Tuple[str, ...]]] = {}
        self._etag_cache: Dict[str, str] = {}
    
    async def process_source(self, source: SourceDefinition) -> Set[str]:
        """Process a single source and return valid domains"""
        if not source.enabled:
            return set()
        
        try:
            # Загрузка с проверкой изменений
            content, changed = await self._download_with_change_tracking(source)
            
            if not changed:
                logging.info(f"{source.name} unchanged, using cached data")
                self.stats.sources_unchanged += 1
                return await self._load_cached_domains(source)
            
            content = content or ""
            domains = await self._extract_domains(content, source)
            valid_domains = await self._validate_domains(domains, source)
            
            # Сохраняем кэш для будущих запусков
            await self._cache_domains(source, valid_domains)
            
            # AI детекция
            if self.detector and self.config.ai_enabled:
                await self._process_ai_detection(valid_domains, source)
            
            self.stats.sources_processed += 1
            return valid_domains
            
        except Exception as e:
            self.stats.sources_failed += 1
            error_msg = f"Failed to process {source.name}: {e}"
            self.stats.errors.append(error_msg)
            logging.error(error_msg, exc_info=self.config.verbose)
            return set()
    
    async def _download_with_change_tracking(self, source: SourceDefinition) -> Tuple[Optional[str], bool]:
        """Download source with ETag/Last-Modified tracking"""
        await self.ssrf_protector.validate_url(source.url)
        
        headers = {'User-Agent': Constants.USER_AGENT}
        
        # Загружаем сохраненный ETag
        if self.config.enable_change_tracking and source.etag_file and source.etag_file.exists():
            try:
                async with aiofiles.open(source.etag_file, 'r') as f:
                    etag = await f.read()
                    headers['If-None-Match'] = etag.strip()
            except Exception as e:
                logging.debug(f"Failed to read ETag for {source.name}: {e}")
        
        for attempt in range(self.config.max_retries):
            try:
                timeout = ClientTimeout(total=self.config.timeout)
                async with self.session.get(
                    source.url,
                    timeout=timeout,
                    headers=headers,
                    max_redirects=Constants.MAX_REDIRECTS
                ) as response:
                    await self.ssrf_protector.validate_response(response, str(response.url))
                    
                    if response.status == 304:
                        # Не изменялось
                        return None, False
                    
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}")
                    
                    content = await response.text()
                    
                    if len(content) > source.max_size_mb * 1024 * 1024:
                        raise ValueError(f"File too large: {len(content)} bytes")
                    
                    # Сохраняем новый ETag
                    if self.config.enable_change_tracking and source.etag_file and 'ETag' in response.headers:
                        async with aiofiles.open(source.etag_file, 'w') as f:
                            await f.write(response.headers['ETag'])
                    
                    return content, True
                    
            except (asyncio.TimeoutError, ClientError) as e:
                if attempt == self.config.max_retries - 1:
                    raise
                wait_time = Constants.RETRY_BACKOFF ** attempt
                logging.warning(f"Retry {attempt + 1} for {source.name} in {wait_time}s")
                await asyncio.sleep(wait_time)
        
        raise RuntimeError(f"Failed after {self.config.max_retries} attempts")
    
    async def _extract_domains(self, content: str, source: SourceDefinition) -> Set[str]:
        """Extract domains from content"""
        domains = set()
        
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            domain = self._parse_line(line, source.source_type)
            if domain:
                domains.add(domain)
        
        self.stats.total_raw_domains += len(domains)
        return domains
    
    def _parse_line(self, line: str, source_type: SourceType) -> Optional[str]:
        """Parse a single line based on source type"""
        if source_type == SourceType.HOSTS:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                return parts[1].split('#')[0].strip()
        elif source_type == SourceType.DOMAINS:
            return line.split('#')[0].strip()
        
        return None
    
    async def _validate_domains(self, domains: Set[str], source: SourceDefinition) -> Set[str]:
        """Validate domains with concurrency control"""
        valid_domains = set()
        
        for domain in domains:
            if len(valid_domains) >= self.config.max_domains:
                break
            
            if await self.validator.is_valid(domain):
                valid_domains.add(domain)
            else:
                self.stats.invalid_domains += 1
        
        self.stats.valid_domains += len(valid_domains)
        return valid_domains
    
    async def _process_ai_detection(self, domains: Set[str], source: SourceDefinition) -> None:
        """Process AI detection for domains and store results"""
        if not self.detector or not self.config.ai_enabled:
            return
        
        # Обрабатываем домены пакетами для производительности
        domains_list = list(domains)
        for i in range(0, len(domains_list), Constants.AI_BATCH_SIZE):
            batch = domains_list[i:i + Constants.AI_BATCH_SIZE]
            tasks = [self.detector.analyze(domain) for domain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for domain, result in zip(batch, results):
                if isinstance(result, Exception):
                    logging.debug(f"AI analysis failed for {domain}: {result}")
                    continue
                
                confidence, reasons = result
                if confidence >= self.config.ai_confidence_threshold:
                    self.stats.ai_detected += 1
                    self.ai_results[domain] = (confidence, reasons)
    
    async def _cache_domains(self, source: SourceDefinition, domains: Set[str]) -> None:
        """Cache processed domains for future runs"""
        if not self.config.enable_change_tracking:
            return
        
        cache_file = Path(f".cache/{source.name}.domains.gz")
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with gzip.open(cache_file, 'wt', compresslevel=Constants.COMPRESSION_LEVEL) as f:
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
        except Exception as e:
            logging.warning(f"Failed to cache domains for {source.name}: {e}")
    
    async def _load_cached_domains(self, source: SourceDefinition) -> Set[str]:
        """Load cached domains from previous run"""
        cache_file = Path(f".cache/{source.name}.domains.gz")
        
        if not cache_file.exists():
            return set()
        
        domains = set()
        try:
            with gzip.open(cache_file, 'rt') as f:
                for line in f:
                    domain = line.strip()
                    if domain:
                        domains.add(domain)
            logging.info(f"Loaded {len(domains)} cached domains for {source.name}")
            return domains
        except Exception as e:
            logging.warning(f"Failed to load cached domains for {source.name}: {e}")
            return set()
    
    def get_ai_confidence(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Get AI confidence for a domain"""
        return self.ai_results.get(domain, (0.0, ()))


# ============================================================================
# BLOCKLIST BUILDER - С УЛУЧШЕННОЙ ЗАПИСЬЮ
# ============================================================================

class BlocklistBuilder:
    """Main blocklist builder orchestrator"""
    
    def __init__(self, config: Config) -> None:
        """Initialize builder with configuration"""
        self.config = config
        self.stats = BuildStats()
        self.validator = DomainValidator()
        self.detector = AITrackerDetector(config.ai_confidence_threshold) if config.ai_enabled else None
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        level = logging.DEBUG if self.config.verbose else logging.INFO
        if self.config.quiet:
            level = logging.ERROR
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        
        # Устанавливаем уровень для aiohttp
        logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    async def build(self, sources: List[SourceDefinition]) -> bool:
        """Build blocklist from sources"""
        start_time = time.time()
        logging.info(f"Starting blocklist build v{VERSION}")
        logging.info(f"Configuration: AI={'enabled' if self.config.ai_enabled else 'disabled'}, "
                    f"Threshold={self.config.ai_confidence_threshold}, "
                    f"Max domains={self.config.max_domains:,}")
        
        try:
            async with self._create_session() as session:
                all_domains = await self._process_all_sources(session, sources)
                await self._write_outputs(all_domains)
                
                self.stats.end_time = time.time()
                self._print_summary()
                
                return True
                
        except Exception as e:
            logging.critical(f"Build failed: {e}", exc_info=True)
            self.stats.errors.append(str(e))
            return False
        finally:
            await self.cleanup()
    
    @asynccontextmanager
    async def _create_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        """Create configured HTTP session"""
        connector = aiohttp.TCPConnector(
            limit=Constants.MAX_CONCURRENT_DOWNLOADS,
            limit_per_host=Constants.CONNECTION_LIMIT_PER_HOST,
            ttl_dns_cache=300,
            ssl=ssl.create_default_context()
        )
        
        timeout = ClientTimeout(total=self.config.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': Constants.USER_AGENT}
        ) as session:
            yield session
    
    async def _process_all_sources(
        self,
        session: aiohttp.ClientSession,
        sources: List[SourceDefinition]
    ) -> Set[str]:
        """Process all sources in parallel"""
        processor = SourceProcessor(
            session, self.validator, self.detector, self.config, self.stats
        )
        
        # Обновляем AI статистику
        if self.detector:
            self.stats.ai_stats = self.detector._stats
        
        tasks = [processor.process_source(source) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_domains = set()
        ai_results = {}
        
        for i, result in enumerate(results):
            if isinstance(result, set):
                all_domains.update(result)
                # Собираем AI результаты от всех процессоров
                if hasattr(processor, 'ai_results'):
                    ai_results.update(processor.ai_results)
            elif isinstance(result, Exception):
                logging.error(f"Source {sources[i].name} processing failed: {result}")
        
        # Сохраняем AI результаты в stats для использования при записи
        if ai_results:
            self._ai_results = ai_results
        
        self.stats.duplicates_removed = self.stats.valid_domains - len(all_domains)
        return all_domains
    
    async def _write_outputs(self, domains: Set[str]) -> None:
        """Write blocklist to output files"""
        # Конвертируем в список для сортировки
        sorted_domains = sorted(domains)
        
        # Записываем динамический блоклист (с AI метками)
        await self._write_blocklist_with_ai(sorted_domains, self.config.output_dynamic, include_ai=True)
        
        # Записываем простой блоклист (без AI меток)
        await self._write_blocklist_with_ai(sorted_domains, self.config.output_simple, include_ai=False)
        
        # Записываем сжатый если включено
        if self.config.enable_compression and self.config.output_compressed:
            await self._write_compressed(sorted_domains, self.config.output_compressed)
        
        # Записываем JSON если включено
        if self.config.enable_json and self.config.output_json:
            await self._write_json(sorted_domains, self.config.output_json)
        
        # Записываем AI отчет если включено
        if self.config.output_ai_report and self.detector:
            await self._write_ai_report(self.config.output_ai_report)
    
    async def _write_blocklist_with_ai(self, domains: List[str], path: Path, include_ai: bool = True) -> None:
        """Write blocklist with optional AI annotations"""
        header = f"# DNS Security Blocklist v{VERSION}\n"
        header += f"# Generated: {datetime.now(timezone.utc).isoformat()}\n"
        header += f"# Total domains: {len(domains)}\n"
        if include_ai and self.config.ai_enabled:
            header += f"# AI Detection: Enabled (threshold={self.config.ai_confidence_threshold})\n"
        header += "\n"
        
        # Для больших списков используем потоковую запись
        if self.config.streaming_mode and len(domains) > Constants.STREAMING_BATCH_SIZE:
            await self._write_blocklist_streaming(domains, path, include_ai)
            return
        
        # Обычная запись
        async with aiofiles.open(path, 'w') as f:
            await f.write(header)
            
            for domain in domains:
                record = await self._create_domain_record(domain, include_ai)
                await f.write(record.to_hosts_entry() + "\n")
    
    async def _write_blocklist_streaming(self, domains: List[str], path: Path, include_ai: bool) -> None:
        """Write blocklist in streaming mode for large lists"""
        async with aiofiles.open(path, 'w') as f:
            await f.write(f"# DNS Security Blocklist v{VERSION} (Streaming Mode)\n")
            await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            await f.write(f"# Total domains: {len(domains)}\n\n")
            
            # Обрабатываем пакетами
            for i in range(0, len(domains), Constants.STREAMING_BATCH_SIZE):
                batch = domains[i:i + Constants.STREAMING_BATCH_SIZE]
                records = []
                
                for domain in batch:
                    record = await self._create_domain_record(domain, include_ai)
                    records.append(record.to_hosts_entry())
                
                await f.write("\n".join(records) + "\n")
                
                # Освобождаем память
                records.clear()
    
    async def _create_domain_record(self, domain: str, include_ai: bool) -> DomainRecord:
        """Create domain record with AI info if available"""
        if include_ai and self.detector and self.config.ai_enabled:
            confidence, reasons = await self.detector.analyze(domain)
            if confidence >= self.config.ai_confidence_threshold:
                return DomainRecord(
                    domain=domain,
                    source="builder",
                    status=DomainStatus.AI_DETECTED,
                    ai_confidence=confidence,
                    ai_reasons=reasons
                )
        
        return DomainRecord(
            domain=domain,
            source="builder",
            status=DomainStatus.BLOCKED
        )
    
    async def _write_compressed(self, domains: List[str], path: Path) -> None:
        """Write compressed blocklist"""
        with gzip.open(path, 'wt', compresslevel=Constants.COMPRESSION_LEVEL) as f:
            for domain in domains:
                f.write(f"0.0.0.0 {domain}\n")
    
    async def _write_json(self, domains: List[str], path: Path) -> None:
        """Write JSON output"""
        data = {
            'version': VERSION,
            'generated': datetime.now(timezone.utc).isoformat(),
            'config': {
                'ai_enabled': self.config.ai_enabled,
                'ai_threshold': self.config.ai_confidence_threshold,
                'max_domains': self.config.max_domains
            },
            'stats': self.stats.to_dict(),
            'domains': domains[:self.config.max_domains]
        }
        
        async with aiofiles.open(path, 'w') as f:
            await f.write(json.dumps(data, indent=2))
    
    async def _write_ai_report(self, path: Path) -> None:
        """Write detailed AI detection report"""
        if not self.detector:
            return
        
        stats = await self.detector.get_stats()
        
        report = {
            'version': VERSION,
            'generated': datetime.now(timezone.utc).isoformat(),
            'configuration': {
                'threshold': self.config.ai_confidence_threshold,
                'enabled': self.config.ai_enabled
            },
            'statistics': stats
        }
        
        async with aiofiles.open(path, 'w') as f:
            await f.write(json.dumps(report, indent=2))
    
    def _print_summary(self) -> None:
        """Print build summary"""
        print("\n" + "=" * 70)
        print(f"Blocklist Build Complete v{VERSION}")
        print("=" * 70)
        print(f"Duration: {self.stats.duration:.2f}s")
        print(f"Sources: {self.stats.sources_processed} processed, "
              f"{self.stats.sources_unchanged} unchanged, "
              f"{self.stats.sources_failed} failed")
        print(f"Domains: {self.stats.total_raw_domains:,} raw → "
              f"{self.stats.valid_domains:,} valid → "
              f"{self.stats.valid_domains - self.stats.duplicates_removed:,} unique")
        print(f"Invalid: {self.stats.invalid_domains:,}")
        
        if self.config.ai_enabled and self.stats.ai_detected > 0:
            print(f"\nAI Detection:")
            print(f"  Detected: {self.stats.ai_detected:,} tracker domains")
            if self.stats.ai_stats.total_analyzed > 0:
                detection_rate = self.stats.ai_stats.detected_trackers / self.stats.ai_stats.total_analyzed * 100
                print(f"  Detection rate: {detection_rate:.1f}%")
                print(f"  Avg confidence: {self.stats.ai_stats.avg_confidence:.1%}")
                if self.stats.ai_stats.pattern_hits:
                    print(f"  Top patterns: {', '.join(list(self.stats.ai_stats.pattern_hits.keys())[:5])}")
        
        if self.stats.errors:
            print(f"\n⚠️  Errors ({len(self.stats.errors)}):")
            for error in self.stats.errors[:5]:
                print(f"  - {error[:100]}")
        
        print("=" * 70)
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        await self.validator.cleanup()
        if self.detector:
            await self.detector.cleanup()


# ============================================================================
# SOURCE MANAGER - С УЛУЧШЕННЫМИ ИСТОЧНИКАМИ
# ============================================================================

class SourceManager:
    """Manage blocklist sources"""
    
    @staticmethod
    def get_default_sources() -> List[SourceDefinition]:
        """Get default blocklist sources with ETag tracking"""
        cache_dir = Path("./cache")
        cache_dir.mkdir(exist_ok=True)
        
        return [
            SourceDefinition(
                name="OISD Big",
                url="https://big.oisd.nl/domains",
                source_type=SourceType.DOMAINS,
                priority=1,
                etag_file=cache_dir / "oisd.etag"
            ),
            SourceDefinition(
                name="AdAway",
                url="https://adaway.org/hosts.txt",
                source_type=SourceType.HOSTS,
                priority=2,
                etag_file=cache_dir / "adaway.etag"
            ),
            SourceDefinition(
                name="URLhaus",
                url="https://urlhaus.abuse.ch/downloads/hostfile/",
                source_type=SourceType.HOSTS,
                priority=3,
                etag_file=cache_dir / "urlhaus.etag"
            ),
            SourceDefinition(
                name="ThreatFox",
                url="https://threatfox.abuse.ch/downloads/hostfile/",
                source_type=SourceType.HOSTS,
                priority=4,
                etag_file=cache_dir / "threatfox.etag"
            ),
            SourceDefinition(
                name="Cert Poland",
                url="https://hole.cert.pl/domains/domains_hosts.txt",
                source_type=SourceType.HOSTS,
                priority=5,
                etag_file=cache_dir / "certpoland.etag"
            ),
            SourceDefinition(
                name="StevenBlack",
                url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                source_type=SourceType.HOSTS,
                priority=6,
                etag_file=cache_dir / "stevenblack.etag"
            ),
        ]


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main_async() -> int:
    """Async main entry point"""
    parser = argparse.ArgumentParser(
        description="DNS Security Blocklist Builder v12.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  %(prog)s -o blocklist.txt
  
  # Enable AI detection with custom threshold
  %(prog)s --ai-threshold 0.75 --ai-report ai_report.json
  
  # Disable AI, enable JSON output
  %(prog)s --no-ai --json-output stats.json
  
  # Process large lists with streaming mode
  %(prog)s --max-domains 2000000 --streaming
        """
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("./blocklist.txt"),
        help="Output file path (default: ./blocklist.txt)"
    )
    parser.add_argument(
        "--dynamic-output",
        type=Path,
        default=Path("./dynamic-blocklist.txt"),
        help="Dynamic blocklist output path with AI annotations"
    )
    parser.add_argument(
        "--compressed-output",
        type=Path,
        help="Compressed output path (.gz)"
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="JSON output path with statistics"
    )
    parser.add_argument(
        "--ai-report",
        type=Path,
        help="AI detection report output path (JSON)"
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=Constants.MAX_DOMAINS_DEFAULT,
        help=f"Maximum domains to process (default: {Constants.MAX_DOMAINS_DEFAULT})"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=Constants.DEFAULT_TIMEOUT,
        help=f"Download timeout in seconds (default: {Constants.DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        default=Constants.MAX_CONCURRENT_DOWNLOADS,
        help=f"Concurrent downloads (default: {Constants.MAX_CONCURRENT_DOWNLOADS})"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI tracker detection"
    )
    parser.add_argument(
        "--ai-threshold",
        type=float,
        default=Constants.AI_CONFIDENCE_THRESHOLD,
        help=f"AI confidence threshold (default: {Constants.AI_CONFIDENCE_THRESHOLD})"
    )
    parser.add_argument(
        "--no-change-tracking",
        action="store_true",
        help="Disable ETag/Last-Modified change tracking"
    )
    parser.add_argument(
        "--streaming",
        action="store_true",
        help="Enable streaming mode for large lists (reduces memory usage)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    
    args = parser.parse_args()
    
    # Validate constants
    Constants.validate()
    
    # Create configuration
    config = Config(
        output_dynamic=args.dynamic_output,
        output_simple=args.output,
        output_compressed=args.compressed_output,
        output_json=args.json_output,
        output_ai_report=args.ai_report,
        max_domains=args.max_domains,
        timeout=args.timeout,
        concurrent_downloads=args.concurrent,
        ai_enabled=not args.no_ai,
        ai_confidence_threshold=args.ai_threshold,
        verbose=args.verbose,
        quiet=args.quiet,
        enable_change_tracking=not args.no_change_tracking,
        streaming_mode=args.streaming
    )
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()
    
    def signal_handler() -> None:
        """Handle shutdown signals"""
        logging.warning("Received shutdown signal")
        shutdown_event.set()
    
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    # Build blocklist
    builder = BlocklistBuilder(config)
    
    try:
        sources = SourceManager.get_default_sources()
        success = await builder.build(sources)
        
        if shutdown_event.is_set():
            logging.warning("Build interrupted by shutdown signal")
            return 130
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        logging.warning("Build interrupted by user")
        return 130
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=True)
        return 1
    finally:
        await builder.cleanup()


def main() -> int:
    """Synchronous main entry point"""
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
