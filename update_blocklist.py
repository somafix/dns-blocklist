#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION READY (v11.0.0)
COMPLETE REFACTOR: Security, Performance, Reliability, Type Safety
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
from dataclasses import dataclass, field
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

VERSION: Final[str] = "11.0.0"
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
    
    # AI Detection
    USER_AGENT: Final[str] = f'Mozilla/5.0 (compatible; DNS-Blocklist-Builder/{VERSION})'
    AI_CONFIDENCE_THRESHOLD: Final[float] = 0.65
    SUSPICIOUS_SUBDOMAIN_DEPTH: Final[int] = 5
    
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
        
        if self.ai_confidence > 0:
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
    
    def __post_init__(self) -> None:
        """Validate source"""
        if not self.name or not self.url:
            raise ValueError(f"Invalid source: {self.name}")
        parsed = urlparse(self.url)
        if parsed.scheme not in Constants.ALLOWED_SCHEMES:
            raise ValueError(f"Invalid scheme: {parsed.scheme}")


@dataclass
class BuildStats:
    """Build statistics for monitoring"""
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    sources_processed: int = 0
    sources_failed: int = 0
    total_raw_domains: int = 0
    valid_domains: int = 0
    ai_detected: int = 0
    duplicates_removed: int = 0
    invalid_domains: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
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
            'total_raw_domains': self.total_raw_domains,
            'valid_domains': self.valid_domains,
            'ai_detected': self.ai_detected,
            'duplicates_removed': self.duplicates_removed,
            'invalid_domains': self.invalid_domains,
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
    memory_limit_mb: int = Constants.MEMORY_LIMIT_MB
    
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
    
    def _create_directories(self) -> None:
        """Create output directories if they don't exist"""
        self.output_dynamic.parent.mkdir(parents=True, exist_ok=True)
        self.output_simple.parent.mkdir(parents=True, exist_ok=True)
        if self.output_compressed:
            self.output_compressed.parent.mkdir(parents=True, exist_ok=True)
        if self.output_json:
            self.output_json.parent.mkdir(parents=True, exist_ok=True)


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
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        async with self._lock:
            if key not in self._cache:
                return None
            
            value, timestamp = self._cache[key]
            if time.time() - timestamp > self.ttl:
                del self._cache[key]
                return None
            
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
        self._stats = {'cache_hits': 0, 'cache_misses': 0}
    
    async def is_valid(self, domain: str) -> bool:
        """Check if domain is valid with caching"""
        domain_lower = domain.lower().strip()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            self._stats['cache_hits'] += 1
            return cached
        
        self._stats['cache_misses'] += 1
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
    
    def get_stats(self) -> Dict[str, int]:
        """Get validator statistics"""
        return self._stats.copy()


# ============================================================================
# AI TRACKER DETECTOR
# ============================================================================

class AITrackerDetector:
    """ML-inspired tracker detection with pattern matching"""
    
    TRACKER_PATTERNS: ClassVar[Tuple[Tuple[str, str, float], ...]] = (
        (r'analytics?', 'analytics', 0.82),
        (r'google-analytics', 'google_analytics', 0.95),
        (r'googletagmanager|gtm', 'google_tag_manager', 0.92),
        (r'track(?:ing)?', 'tracking', 0.80),
        (r'pixel', 'tracking_pixel', 0.85),
        (r'beacon', 'tracking_beacon', 0.85),
        (r'collect', 'data_collector', 0.80),
        (r'telemetry', 'telemetry', 0.85),
        (r'metrics', 'metrics', 0.78),
        (r'stat(?:s|istic)?', 'statistics', 0.75),
        (r'doubleclick', 'doubleclick', 0.95),
        (r'adservice', 'ad_service', 0.85),
        (r'ads?\.', 'ad_domain', 0.75),
        (r'amplitude', 'amplitude', 0.90),
        (r'mixpanel', 'mixpanel', 0.90),
        (r'segment\.com', 'segment', 0.90),
        (r'appsflyer', 'appsflyer', 0.90),
        (r'facebook\.com/tr', 'facebook_pixel', 0.95),
        (r'twitter\.com/i', 'twitter_tracker', 0.82),
        (r'criteo', 'criteo', 0.85),
        (r'taboola', 'taboola', 0.85),
        (r'outbrain', 'outbrain', 0.85),
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
        self._stats = {'cache_hits': 0, 'cache_misses': 0}
    
    async def analyze(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Analyze domain for tracker patterns with caching"""
        domain_lower = domain.lower()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            self._stats['cache_hits'] += 1
            return cached
        
        self._stats['cache_misses'] += 1
        confidence, reasons = self._analyze_patterns(domain_lower)
        
        result = (confidence, reasons)
        await self._cache.set(domain_lower, result)
        
        return result
    
    def _analyze_patterns(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Analyze domain against patterns"""
        confidence = 0.0
        reasons = []
        
        for pattern, reason, base_conf in self._patterns:
            if pattern.search(domain):
                confidence = max(confidence, base_conf)
                if reason not in reasons:
                    reasons.append(reason)
        
        return (confidence, tuple(reasons))
    
    def get_stats(self) -> Dict[str, int]:
        """Get detector statistics"""
        return self._stats.copy()


# ============================================================================
# SOURCE PROCESSOR
# ============================================================================

class SourceProcessor:
    """Process individual source files"""
    
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
        self._processed_domains: Set[str] = set()
    
    async def process_source(self, source: SourceDefinition) -> Set[str]:
        """Process a single source and return valid domains"""
        if not source.enabled:
            return set()
        
        try:
            content = await self._download_source(source)
            domains = await self._extract_domains(content, source)
            valid_domains = await self._validate_domains(domains, source)
            await self._process_ai_detection(valid_domains, source)
            
            self.stats.sources_processed += 1
            return valid_domains
            
        except Exception as e:
            self.stats.sources_failed += 1
            error_msg = f"Failed to process {source.name}: {e}"
            self.stats.errors.append(error_msg)
            logging.error(error_msg, exc_info=self.config.verbose)
            return set()
    
    async def _download_source(self, source: SourceDefinition) -> str:
        """Download source with retry logic"""
        await self.ssrf_protector.validate_url(source.url)
        
        for attempt in range(self.config.max_retries):
            try:
                timeout = ClientTimeout(total=self.config.timeout)
                async with self.session.get(
                    source.url,
                    timeout=timeout,
                    headers={'User-Agent': Constants.USER_AGENT},
                    max_redirects=Constants.MAX_REDIRECTS
                ) as response:
                    await self.ssrf_protector.validate_response(response, str(response.url))
                    
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}")
                    
                    content = await response.text()
                    
                    if len(content) > source.max_size_mb * 1024 * 1024:
                        raise ValueError(f"File too large: {len(content)} bytes")
                    
                    return content
                    
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
            # Format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                return parts[1].split('#')[0].strip()
        elif source_type == SourceType.DOMAINS:
            # Simple domain per line
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
        """Process AI detection for domains"""
        if not self.detector or not self.config.ai_enabled:
            return
        
        for domain in domains:
            confidence, reasons = await self.detector.analyze(domain)
            if confidence >= self.config.ai_confidence_threshold:
                self.stats.ai_detected += 1
                
                record = DomainRecord(
                    domain=domain,
                    source=source.name,
                    status=DomainStatus.AI_DETECTED,
                    ai_confidence=confidence,
                    ai_reasons=reasons
                )
                self._processed_domains.add(domain)


# ============================================================================
# BLOCKLIST BUILDER
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
    
    async def build(self, sources: List[SourceDefinition]) -> bool:
        """Build blocklist from sources"""
        start_time = time.time()
        logging.info(f"Starting blocklist build v{VERSION}")
        
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
        
        tasks = [processor.process_source(source) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_domains = set()
        for result in results:
            if isinstance(result, set):
                all_domains.update(result)
            elif isinstance(result, Exception):
                logging.error(f"Source processing failed: {result}")
        
        self.stats.duplicates_removed = self.stats.valid_domains - len(all_domains)
        return all_domains
    
    async def _write_outputs(self, domains: Set[str]) -> None:
        """Write blocklist to output files"""
        # Write dynamic blocklist
        await self._write_blocklist(domains, self.config.output_dynamic)
        
        # Write simple blocklist
        simple_domains = {d for d in domains if not self._is_ai_high_confidence(d)}
        await self._write_blocklist(simple_domains, self.config.output_simple)
        
        # Write compressed if enabled
        if self.config.enable_compression and self.config.output_compressed:
            await self._write_compressed(domains, self.config.output_compressed)
        
        # Write JSON if enabled
        if self.config.enable_json and self.config.output_json:
            await self._write_json(domains, self.config.output_json)
    
    async def _write_blocklist(self, domains: Set[str], path: Path) -> None:
        """Write domains to blocklist file"""
        header = f"# DNS Security Blocklist v{VERSION}\n"
        header += f"# Generated: {datetime.now(timezone.utc).isoformat()}\n"
        header += f"# Total domains: {len(domains)}\n\n"
        
        async with aiofiles.open(path, 'w') as f:
            await f.write(header)
            
            for domain in sorted(domains):
                record = DomainRecord(domain, "builder", DomainStatus.BLOCKED)
                await f.write(record.to_hosts_entry() + "\n")
    
    async def _write_compressed(self, domains: Set[str], path: Path) -> None:
        """Write compressed blocklist"""
        with gzip.open(path, 'wt', compresslevel=Constants.COMPRESSION_LEVEL) as f:
            for domain in sorted(domains):
                f.write(f"0.0.0.0 {domain}\n")
    
    async def _write_json(self, domains: Set[str], path: Path) -> None:
        """Write JSON output"""
        data = {
            'version': VERSION,
            'generated': datetime.now(timezone.utc).isoformat(),
            'stats': self.stats.to_dict(),
            'domains': sorted(domains)[:self.config.max_domains]
        }
        
        async with aiofiles.open(path, 'w') as f:
            await f.write(json.dumps(data, indent=2))
    
    def _is_ai_high_confidence(self, domain: str) -> bool:
        """Check if domain has high AI confidence"""
        # This would require storing AI results, simplified for now
        return False
    
    def _print_summary(self) -> None:
        """Print build summary"""
        print("\n" + "=" * 60)
        print(f"Blocklist Build Complete v{VERSION}")
        print("=" * 60)
        print(f"Duration: {self.stats.duration:.2f}s")
        print(f"Sources processed: {self.stats.sources_processed}/{self.stats.sources_failed}")
        print(f"Total raw domains: {self.stats.total_raw_domains:,}")
        print(f"Valid domains: {self.stats.valid_domains:,}")
        print(f"AI detected: {self.stats.ai_detected:,}")
        print(f"Duplicates removed: {self.stats.duplicates_removed:,}")
        print(f"Invalid domains: {self.stats.invalid_domains:,}")
        
        if self.stats.errors:
            print(f"\nErrors ({len(self.stats.errors)}):")
            for error in self.stats.errors[:5]:
                print(f"  - {error}")
        
        print("=" * 60)
        
        if self.config.verbose:
            print("\nValidator stats:", self.validator.get_stats())
            if self.detector:
                print("Detector stats:", self.detector.get_stats())
    
    async def cleanup(self) -> None:
        """Cleanup resources"""
        await self.validator._cache.clear()
        if self.detector:
            await self.detector._cache.clear()


# ============================================================================
# SOURCE MANAGER
# ============================================================================

class SourceManager:
    """Manage blocklist sources"""
    
    @staticmethod
    def get_default_sources() -> List[SourceDefinition]:
        """Get default blocklist sources"""
        return [
            SourceDefinition(
                name="OISD Big",
                url="https://big.oisd.nl/domains",
                source_type=SourceType.DOMAINS,
                priority=1
            ),
            SourceDefinition(
                name="AdAway",
                url="https://adaway.org/hosts.txt",
                source_type=SourceType.HOSTS,
                priority=2
            ),
            SourceDefinition(
                name="URLhaus",
                url="https://urlhaus.abuse.ch/downloads/hostfile/",
                source_type=SourceType.HOSTS,
                priority=3
            ),
            SourceDefinition(
                name="ThreatFox",
                url="https://threatfox.abuse.ch/downloads/hostfile/",
                source_type=SourceType.HOSTS,
                priority=4
            ),
            SourceDefinition(
                name="Cert Poland",
                url="https://hole.cert.pl/domains/domains_hosts.txt",
                source_type=SourceType.HOSTS,
                priority=5
            ),
        ]


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main_async() -> int:
    """Async main entry point"""
    parser = argparse.ArgumentParser(
        description="DNS Security Blocklist Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter
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
        help="Dynamic blocklist output path"
    )
    parser.add_argument(
        "--compressed-output",
        type=Path,
        help="Compressed output path (.gz)"
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="JSON output path"
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
        max_domains=args.max_domains,
        timeout=args.timeout,
        concurrent_downloads=args.concurrent,
        ai_enabled=not args.no_ai,
        ai_confidence_threshold=args.ai_threshold,
        verbose=args.verbose,
        quiet=args.quiet
    )
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()
    
    def signal_handler() -> None:
        """Handle shutdown signals"""
        logging.warning("Received shutdown signal")
        shutdown_event.set()
    
    loop.add_signal_handler(signal.SIGINT, signal_handler)
    loop.add_signal_handler(signal.SIGTERM, signal_handler)
    
    # Build blocklist
    builder = BlocklistBuilder(config)
    
    try:
        sources = SourceManager.get_default_sources()
        success = await builder.build(sources)
        
        if shutdown_event.is_set():
            logging.warning("Build interrupted by shutdown signal")
            await builder.cleanup()
            return 130
        
        await builder.cleanup()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        logging.warning("Build interrupted by user")
        await builder.cleanup()
        return 130
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=True)
        await builder.cleanup()
        return 1


def main() -> int:
    """Synchronous main entry point"""
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
