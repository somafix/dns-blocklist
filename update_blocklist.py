#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION READY (v10.0.0)
COMPLETE REFACTOR: Security, Performance, Reliability
"""

import sys
import asyncio
import logging
import re
import signal
import time
import shutil
import argparse
import gzip
import json
import hashlib
import ssl
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import (
    Set, Dict, List, Optional, Tuple, ClassVar, Final, Any, 
    AsyncIterator, Deque, Union, cast
)
from urllib.parse import urlparse
import ipaddress
from collections import deque, defaultdict
from functools import lru_cache, wraps
import asyncio.locks

import aiohttp
from aiohttp import ClientTimeout, ClientResponse, ClientConnectorError, ServerDisconnectedError
from aiohttp.client_exceptions import ClientError
import aiofiles
from aiofiles.os import wrap as aio_wrap

# ============================================================================
# VERSION & METADATA
# ============================================================================

VERSION: Final[str] = "10.0.0"
__version__ = VERSION
__author__ = "DNS Security Team"
__license__ = "MIT"

# ============================================================================
# IMPROVED CONSTANTS
# ============================================================================

class Constants:
    """Centralized constants with type safety"""
    
    # Domain validation
    MAX_DOMAIN_LEN: int = 253
    MAX_LABEL_LEN: int = 63
    MIN_DOMAIN_LEN: int = 3
    
    # File operations
    TEMP_SUFFIX: str = '.tmp'
    BACKUP_SUFFIX: str = '.backup'
    BATCH_WRITE_SIZE: int = 131072  # 128KB for better performance
    COMPRESSION_LEVEL: int = 6
    
    # Network settings
    MAX_CONCURRENT_DOWNLOADS: int = 10
    DEFAULT_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    RETRY_BACKOFF: float = 1.5
    MAX_FILE_SIZE_MB: int = 100
    MAX_REDIRECTS: int = 5
    CONNECTION_LIMIT_PER_HOST: int = 2
    RATE_LIMIT_REQUESTS: int = 5
    RATE_LIMIT_WINDOW: int = 1  # seconds
    
    # Cache settings with TTL
    DNS_CACHE_SIZE: int = 200000
    DNS_CACHE_TTL: int = 300  # seconds
    AI_CACHE_SIZE: int = 200000
    AI_CACHE_TTL: int = 3600  # seconds
    AI_BATCH_SIZE: int = 500  # Reduced for better memory management
    
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
        'hole.cert.pl', 'raw.githubusercontent.com'
    }
    
    RESERVED_TLDS: Final[Set[str]] = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p',
        'corp', 'private', 'intranet'
    }
    
    # AI Detection
    USER_AGENT: Final[str] = f'Mozilla/5.0 (compatible; DNS-Blocklist-Builder/{VERSION})'
    AI_CONFIDENCE_THRESHOLD: float = 0.65
    SUSPICIOUS_SUBDOMAIN_DEPTH: int = 5
    
    # Performance
    MAX_DOMAINS_DEFAULT: int = 1000000
    MEMORY_LIMIT_MB: int = 512
    GC_THRESHOLD: int = 10000
    
    # Health checks
    HEALTH_CHECK_INTERVAL: int = 30  # seconds
    TASK_TIMEOUT: int = 300  # seconds


# ============================================================================
# ENHANCED ENUMS
# ============================================================================

class SourceType(Enum):
    """Type of source file format"""
    HOSTS = auto()
    DOMAINS = auto()
    ADBLOCK = auto()  # Added for future compatibility


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
# IMPROVED DATA MODELS
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
        if self.ai_confidence < 0 or self.ai_confidence > 1:
            raise ValueError(f"Invalid confidence: {self.ai_confidence}")
    
    def to_hosts_entry(self) -> str:
        """Convert to hosts file format with sanitization"""
        # Sanitize domain to prevent injection
        safe_domain = re.sub(r'[\n\r\t\v\f\x00-\x1f\x7f]', '', self.domain)
        
        if self.ai_confidence > 0:
            reasons = ','.join(r.replace(',', '\\,').replace('"', '\\"') for r in self.ai_reasons[:2])
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{reasons}]"
        return f"0.0.0.0 {safe_domain}"
    
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
    expected_format: Optional[str] = None
    
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
            'duration_seconds': self.duration,
            'sources_processed': self.sources_processed,
            'sources_failed': self.sources_failed,
            'total_raw_domains': self.total_raw_domains,
            'valid_domains': self.valid_domains,
            'ai_detected': self.ai_detected,
            'duplicates_removed': self.duplicates_removed,
            'invalid_domains': self.invalid_domains,
            'errors': self.errors[:10],  # Limit errors in report
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
        """Validate configuration"""
        if self.max_domains <= 0:
            raise ValueError(f"Invalid max_domains: {self.max_domains}")
        if self.timeout <= 0:
            raise ValueError(f"Invalid timeout: {self.timeout}")
        if self.concurrent_downloads <= 0 or self.concurrent_downloads > 50:
            raise ValueError(f"Invalid concurrent_downloads: {self.concurrent_downloads}")
        if not 0 <= self.ai_confidence_threshold <= 1:
            raise ValueError(f"Invalid threshold: {self.ai_confidence_threshold}")
        
        # Ensure output directories exist
        self.output_dynamic.parent.mkdir(parents=True, exist_ok=True)
        self.output_simple.parent.mkdir(parents=True, exist_ok=True)
        if self.output_compressed:
            self.output_compressed.parent.mkdir(parents=True, exist_ok=True)
        if self.output_json:
            self.output_json.parent.mkdir(parents=True, exist_ok=True)


# ============================================================================
# ENHANCED CACHE WITH TTL
# ============================================================================

class TTLCache:
    """Thread-safe cache with TTL support"""
    
    def __init__(self, maxsize: int, ttl_seconds: int):
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
            if len(self._cache) >= self.maxsize:
                # Remove oldest entry (simple FIFO)
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            
            self._cache[key] = (value, time.time())
    
    async def clear(self) -> None:
        """Clear all cache entries"""
        async with self._lock:
            self._cache.clear()


# ============================================================================
# ADVANCED SSRF PROTECTION
# ============================================================================

class SSRFProtector:
    """Enhanced SSRF protection with rate limiting"""
    
    def __init__(self, session: aiohttp.ClientSession, config: Config):
        self.session = session
        self.config = config
        self._blocked_networks = [ipaddress.ip_network(net) for net in Constants.BLOCKED_IP_RANGES]
        self._checked_urls: TTLCache = TTLCache(maxsize=10000, ttl_seconds=3600)
        self._dns_cache: TTLCache = TTLCache(maxsize=Constants.DNS_CACHE_SIZE, ttl_seconds=Constants.DNS_CACHE_TTL)
        self._rate_limiter = asyncio.Semaphore(Constants.RATE_LIMIT_REQUESTS)
    
    async def validate_url(self, url: str) -> None:
        """Validate URL with caching and rate limiting"""
        normalized = self._normalize_url(url)
        
        # Check cache first
        cached = await self._checked_urls.get(normalized)
        if cached is not None:
            return
        
        async with self._rate_limiter:
            parsed = urlparse(normalized)
            
            # Validate scheme
            if parsed.scheme not in Constants.ALLOWED_SCHEMES:
                raise ValueError(f"Scheme not allowed: {parsed.scheme}")
            
            # Validate hostname
            if not parsed.hostname:
                raise ValueError(f"No hostname in URL: {url}")
            
            # Check against whitelist
            if parsed.hostname not in Constants.ALLOWED_DOMAINS:
                await self._validate_ip(parsed.hostname)
        
        await self._checked_urls.set(normalized, True)
    
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
            # Add timeout for DNS resolution
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
# OPTIMIZED DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """High-performance domain validator with caching"""
    
    DOMAIN_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$',
        re.IGNORECASE
    )
    
    IDNA_PATTERN: ClassVar[re.Pattern] = re.compile(r'^xn--')
    
    def __init__(self):
        self._cache: TTLCache = TTLCache(
            maxsize=Constants.DNS_CACHE_SIZE,
            ttl_seconds=Constants.DNS_CACHE_TTL
        )
        self._stats = {'cache_hits': 0, 'cache_misses': 0}
    
    async def is_valid(self, domain: str) -> bool:
        """Check if domain is valid with caching"""
        domain_lower = domain.lower().strip()
        
        # Check cache
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
        # Length checks
        if len(domain) < Constants.MIN_DOMAIN_LEN:
            return False
        if len(domain) > Constants.MAX_DOMAIN_LEN:
            return False
        
        # Check for valid IDNA
        if self.IDNA_PATTERN.match(domain):
            try:
                domain.encode('idna').decode('ascii')
            except (UnicodeError, ValueError):
                return False
        
        # Split and validate parts
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # Check TLD
        tld = parts[-1]
        if tld in Constants.RESERVED_TLDS:
            return False
        
        # Check each label
        for label in parts:
            if not label or len(label) > Constants.MAX_LABEL_LEN:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        # Final pattern match
        return bool(self.DOMAIN_PATTERN.match(domain))
    
    def get_stats(self) -> Dict[str, int]:
        """Get validator statistics"""
        return self._stats.copy()


# ============================================================================
# ENHANCED AI DETECTOR
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
    
    def __init__(self, threshold: float = Constants.AI_CONFIDENCE_THRESHOLD):
        self.threshold = threshold
        self._cache: TTLCache = TTLCache(
            maxsize=Constants.AI_CACHE_SIZE,
            ttl_seconds=Constants.AI_CACHE_TTL
        )
        self._patterns = [(re.compile(p, re.IGNORECASE), r, c) for p, r, c in self.TRACKER_PATTERNS]
        self._stats = {'cache_hits': 0, 'cache_misses': 0}
    
    async def analyze(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        """Analyze domain for tracker patterns with caching"""
        domain_lower = domain.lower()
        
        # Check cache
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
        
        # Check for suspicious subdomain depth
        if not reasons and domain.count('.') > Constants.SUSPICIOUS_SUBDOMAIN_DEPTH:
            confidence = max(confidence, 0.60)
            reasons.append('many_subdomains')
        
        # Cap confidence and reasons
        confidence = min(confidence, 1.0)
        return confidence, tuple(reasons[:3])
    
    def get_stats(self) -> Dict[str, int]:
        """Get detector statistics"""
        return self._stats.copy()


# ============================================================================
# IMPROVED SOURCE PARSERS
# ============================================================================

class SourceParser:
    """Safe source parsing with validation"""
    
    @staticmethod
    def parse_hosts(content: str) -> Set[str]:
        """Parse hosts file format safely"""
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line[0] == '#':
                continue
            
            # Handle comments at end of line
            if '#' in line:
                line = line.split('#')[0].strip()
            
            parts = line.split(maxsplit=2)
            if len(parts) >= 2:
                domain = parts[1].lower()
                # Skip reserved domains
                if domain not in ('localhost', 'localhost.localdomain', 'local', 'broadcasthost'):
                    domains.add(domain)
        
        return domains
    
    @staticmethod
    def parse_domains(content: str) -> Set[str]:
        """Parse simple domain list format"""
        domains = set()
        for line in content.splitlines():
            line = line.strip().lower()
            if not line or line[0] in ('#', '!', ';'):
                continue
            
            # Strip inline comments
            if '#' in line:
                line = line.split('#', 1)[0].strip()
            if '!' in line:
                line = line.split('!', 1)[0].strip()
            
            # Skip IP-based entries
            if line and not line.startswith(('0.0.0.0', '127.0.0.1', '::1')):
                domains.add(line)
        
        return domains
    
    @staticmethod
    def parse_adblock(content: str) -> Set[str]:
        """Parse AdBlock format (future compatibility)"""
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(('!', '[', '##', '#@')):
                continue
            
            # Extract domain from ||domain^ format
            if line.startswith('||') and '^' in line:
                domain = line[2:line.index('^')]
                domains.add(domain)
            elif line.startswith('|') and '|' in line:
                domain = line.split('|')[1]
                domains.add(domain)
        
        return domains


# ============================================================================
# ENHANCED SOURCE MANAGER
# ============================================================================

class SourceManager:
    """Async source manager with rate limiting and retries"""
    
    SOURCES: ClassVar[List[SourceDefinition]] = [
        SourceDefinition('StevenBlack', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', SourceType.HOSTS, priority=1),
        SourceDefinition('OISD', 'https://big.oisd.nl/domains', SourceType.DOMAINS, priority=2),
        SourceDefinition('AdAway', 'https://adaway.org/hosts.txt', SourceType.HOSTS, priority=3),
        SourceDefinition('URLhaus', 'https://urlhaus.abuse.ch/downloads/hostfile/', SourceType.HOSTS, priority=4),
        SourceDefinition('ThreatFox', 'https://threatfox.abuse.ch/downloads/hostfile/', SourceType.HOSTS, priority=5),
        SourceDefinition('CERT.PL', 'https://hole.cert.pl/domains/domains_hosts.txt', SourceType.HOSTS, priority=6),
    ]
    
    def __init__(self, config: Config, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.logger = logging.getLogger(__name__)
        self.ssrf = SSRFProtector(session, config)
        self.stats = BuildStats()
        self._semaphore = asyncio.Semaphore(config.concurrent_downloads)
    
    async def fetch_all(self) -> Dict[str, Set[str]]:
        """Fetch all sources with concurrency control"""
        # Sort by priority
        sources = sorted([s for s in self.SOURCES if s.enabled], key=lambda x: x.priority)
        
        # Create tasks with semaphore
        async def fetch_with_semaphore(source: SourceDefinition):
            async with self._semaphore:
                return await self._fetch_with_retry(source)
        
        tasks = [fetch_with_semaphore(s) for s in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domains_by_source = {}
        for source, result in zip(sources, results):
            if isinstance(result, Exception):
                self.stats.sources_failed += 1
                self.stats.errors.append(f"{source.name}: {str(result)[:100]}")
                self.logger.error(f"❌ {source.name} failed: {result}")
            elif result is not None:
                self.stats.sources_processed += 1
                name, domains = result
                domains_by_source[name] = domains
                self.stats.total_raw_domains += len(domains)
        
        return domains_by_source
    
    async def _fetch_with_retry(self, source: SourceDefinition) -> Optional[Tuple[str, Set[str]]]:
        """Fetch source with retry logic"""
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                await self.ssrf.validate_url(source.url)
                content = await self._download_safe(source.url, source.max_size_mb)
                
                # Parse based on type
                if source.source_type == SourceType.HOSTS:
                    domains = SourceParser.parse_hosts(content)
                elif source.source_type == SourceType.DOMAINS:
                    domains = SourceParser.parse_domains(content)
                else:
                    domains = SourceParser.parse_adblock(content)
                
                self.logger.info(f"✅ {source.name}: {len(domains):,} domains")
                return source.name, domains
                
            except asyncio.TimeoutError as e:
                last_error = e
                self.logger.warning(f"⚠️ {source.name} attempt {attempt + 1} timeout: {e}")
            except ClientError as e:
                last_error = e
                self.logger.warning(f"⚠️ {source.name} attempt {attempt + 1} client error: {e}")
            except Exception as e:
                last_error = e
                self.logger.warning(f"⚠️ {source.name} attempt {attempt + 1}: {e}")
            
            if attempt < self.config.max_retries - 1:
                wait_time = Constants.RETRY_BACKOFF ** attempt
                await asyncio.sleep(wait_time)
        
        if last_error:
            self.logger.error(f"❌ {source.name} failed after {self.config.max_retries} attempts")
        return None
    
    async def _download_safe(self, url: str, max_size_mb: int = Constants.MAX_FILE_SIZE_MB) -> str:
        """Download with size limits and timeout"""
        max_bytes = max_size_mb * 1024 * 1024
        
        try:
            async with self.session.get(
                url,
                timeout=ClientTimeout(total=self.config.timeout),
                headers={'User-Agent': Constants.USER_AGENT},
                max_redirects=Constants.MAX_REDIRECTS,
                ssl=ssl.create_default_context()
            ) as resp:
                final_url = str(resp.url)
                await self.ssrf.validate_response(resp, final_url)
                
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                
                # Stream download with size limit
                data = bytearray()
                async for chunk in resp.content.iter_chunked(8192):
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise Exception(f"Size limit exceeded ({max_size_mb}MB)")
                
                # Try UTF-8, fallback to latin1
                try:
                    return data.decode('utf-8')
                except UnicodeDecodeError:
                    self.logger.warning(f"Fallback to latin1 encoding for {url}")
                    return data.decode('latin-1', errors='ignore')
                    
        except asyncio.TimeoutError:
            raise Exception(f"Download timeout after {self.config.timeout}s")
        except aiohttp.ClientResponseError as e:
            raise Exception(f"HTTP error: {e.status}")
        except Exception as e:
            raise Exception(f"Download failed: {e}")


# ============================================================================
# OPTIMIZED DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    """Streaming domain processor with memory efficiency"""
    
    def __init__(self, config: Config, validator: DomainValidator, ai_detector: Optional[AITrackerDetector] = None):
        self.config = config
        self.validator = validator
        self.ai_detector = ai_detector
        self.logger = logging.getLogger(__name__)
        self.domains: Dict[str, DomainRecord] = {}
        self.stats = BuildStats()
        
    async def process_sources(self, domains_by_source: Dict[str, Set[str]]) -> None:
        """Process all sources with streaming"""
        self.logger.info(f"Processing {self.stats.total_raw_domains:,} raw domains...")
        
        # Process domains with memory limit
        for source_name, domains in domains_by_source.items():
            for domain in domains:
                # Check memory limit
                if len(self.domains) >= self.config.max_domains:
                    self.logger.warning(f"Reached domain limit ({self.config.max_domains:,})")
                    break
                
                # Validate domain
                if not await self.validator.is_valid(domain):
                    self.stats.invalid_domains += 1
                    continue
                
                # Check for duplicate
                if domain in self.domains:
                    self.stats.duplicates_removed += 1
                    continue
                
                # Add domain
                self.domains[domain] = DomainRecord(
                    domain=domain,
                    source=source_name,
                    status=DomainStatus.VALID
                )
                self.stats.valid_domains += 1
        
        # AI analysis
        if self.ai_detector and self.config.ai_enabled:
            await self._ai_analysis_streaming()
        
        self.logger.info(f"✅ Final: {len(self.domains):,} unique domains (AI: {self.stats.ai_detected:,})")
    
    async def _ai_analysis_streaming(self) -> None:
        """Streaming AI analysis with batching"""
        self.logger.info("🤖 Running AI tracker detection...")
        
        # Convert to list for batching
        domains_list = list(self.domains.keys())
        total = len(domains_list)
        
        for i in range(0, total, Constants.AI_BATCH_SIZE):
            batch = domains_list[i:i + Constants.AI_BATCH_SIZE]
            
            for domain in batch:
                confidence, reasons = await self.ai_detector.analyze(domain)
                
                if confidence >= self.config.ai_confidence_threshold:
                    old = self.domains[domain]
                    self.domains[domain] = DomainRecord(
                        domain=old.domain,
                        source=f"{old.source}+ai",
                        status=DomainStatus.AI_DETECTED,
                        ai_confidence=confidence,
                        ai_reasons=reasons
                    )
                    self.stats.ai_detected += 1
            
            # Yield control
            await asyncio.sleep(0)
            
            # Progress reporting
            if (i + Constants.AI_BATCH_SIZE) % (Constants.AI_BATCH_SIZE * 10) == 0:
                progress = min(i + Constants.AI_BATCH_SIZE, total) / total * 100
                self.logger.debug(f"AI Progress: {progress:.1f}%")
        
        self.logger.info(f"✅ AI complete: {self.stats.ai_detected:,} trackers detected")
    
    def get_records(self) -> List[DomainRecord]:
        """Get all domain records"""
        return list(self.domains.values())
    
    def get_stats(self) -> BuildStats:
        """Get processing statistics"""
        self.stats.valid_domains = len(self.domains)
        return self.stats


# ============================================================================
# ENHANCED OUTPUT GENERATOR
# ============================================================================

class OutputGenerator:
    """Atomic file writer with compression support"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._write_lock = asyncio.Lock()
    
    async def generate(self, records: List[DomainRecord]) -> None:
        """Generate all output files"""
        tasks = []
        
        # Generate hosts file
        tasks.append(self._generate_hosts_file(records, self.config.output_dynamic))
        
        # Generate simple domains file
        tasks.append(self._generate_simple_file(records, self.config.output_simple))
        
        # Generate compressed file if enabled
        if self.config.enable_compression and self.config.output_compressed:
            tasks.append(self._generate_compressed(records, self.config.output_compressed))
        
        # Generate JSON file if enabled
        if self.config.enable_json and self.config.output_json:
            tasks.append(self._generate_json(records, self.config.output_json))
        
        # Run all tasks concurrently
        await asyncio.gather(*tasks)
        
        self.logger.info(f"✅ Generated outputs successfully")
    
    async def _generate_hosts_file(self, records: List[DomainRecord], output_path: Path) -> None:
        """Generate hosts file with atomic write"""
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        backup_path = output_path.with_suffix(Constants.BACKUP_SUFFIX)
        ai_count = sum(1 for r in records if r.ai_confidence > 0)
        
        async with self._write_lock:
            try:
                async with aiofiles.open(tmp_path, 'w', encoding='utf-8', buffering=Constants.BATCH_WRITE_SIZE) as f:
                    # Write header
                    await f.write(f"# DNS Security Blocklist v{VERSION}\n")
                    await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                    await f.write(f"# Total domains: {len(records):,}\n")
                    await f.write(f"# AI-detected: {ai_count:,}\n")
                    await f.write("#\n\n")
                    
                    # Write domains in batches
                    batch = []
                    for record in records:
                        batch.append(record.to_hosts_entry() + "\n")
                        if len(batch) >= 1000:
                            await f.write(''.join(batch))
                            batch = []
                    if batch:
                        await f.write(''.join(batch))
                
                # Atomic replace
                if output_path.exists():
                    shutil.copy2(output_path, backup_path)
                shutil.move(str(tmp_path), str(output_path))
                
                self.logger.info(f"   📄 {output_path}: {len(records):,} domains, {ai_count:,} AI")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {output_path}: {e}")
                if tmp_path.exists():
                    tmp_path.unlink()
                raise
    
    async def _generate_simple_file(self, records: List[DomainRecord], output_path: Path) -> None:
        """Generate simple domains file"""
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        
        async with self._write_lock:
            try:
                async with aiofiles.open(tmp_path, 'w', encoding='utf-8', buffering=Constants.BATCH_WRITE_SIZE) as f:
                    batch = []
                    for record in records:
                        batch.append(record.domain + "\n")
                        if len(batch) >= 1000:
                            await f.write(''.join(batch))
                            batch = []
                    if batch:
                        await f.write(''.join(batch))
                
                shutil.move(str(tmp_path), str(output_path))
                self.logger.info(f"   📄 {output_path}: {len(records):,} domains")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {output_path}: {e}")
                if tmp_path.exists():
                    tmp_path.unlink()
                raise
    
    async def _generate_compressed(self, records: List[DomainRecord], output_path: Path) -> None:
        """Generate compressed version"""
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        
        async with self._write_lock:
            try:
                # Use gzip compression
                with gzip.open(tmp_path, 'wt', encoding='utf-8', compresslevel=Constants.COMPRESSION_LEVEL) as f:
                    for record in records:
                        f.write(record.domain + "\n")
                
                shutil.move(str(tmp_path), str(output_path))
                size_mb = output_path.stat().st_size / (1024 * 1024)
                self.logger.info(f"   📦 {output_path}: {size_mb:.2f} MB compressed")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {output_path}: {e}")
                if tmp_path.exists():
                    tmp_path.unlink()
                raise
    
    async def _generate_json(self, records: List[DomainRecord], output_path: Path) -> None:
        """Generate JSON output for programmatic use"""
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        
        async with self._write_lock:
            try:
                data = {
                    'version': VERSION,
                    'generated': datetime.now(timezone.utc).isoformat(),
                    'total_domains': len(records),
                    'domains': [r.to_json() for r in records]
                }
                
                async with aiofiles.open(tmp_path, 'w', encoding='utf-8') as f:
                    await f.write(json.dumps(data, indent=2))
                
                shutil.move(str(tmp_path), str(output_path))
                self.logger.info(f"   📊 {output_path}: {len(records):,} domains")
                
            except Exception as e:
                self.logger.error(f"Failed to generate {output_path}: {e}")
                if tmp_path.exists():
                    tmp_path.unlink()
                raise


# ============================================================================
# MAIN BUILDER WITH HEALTH MONITORING
# ============================================================================

class BlocklistBuilder:
    """Main builder with health checks and graceful shutdown"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._shutdown = asyncio.Event()
        self._tasks: Set[asyncio.Task] = set()
        self.start_time = time.time()
        self.stats = BuildStats()
        
    def _setup_signals(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        def handler(sig: int, frame: Any) -> None:
            self.logger.info(f"Received signal {sig}, initiating graceful shutdown...")
            self._shutdown.set()
        
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    
    async def _health_monitor(self) -> None:
        """Background health monitoring"""
        while not self._shutdown.is_set():
            try:
                await asyncio.sleep(Constants.HEALTH_CHECK_INTERVAL)
                
                # Log memory usage
                import psutil
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                if memory_mb > self.config.memory_limit_mb:
                    self.logger.warning(f"High memory usage: {memory_mb:.1f} MB")
                
                # Log task count
                active_tasks = len([t for t in self._tasks if not t.done()])
                if active_tasks > 0:
                    self.logger.debug(f"Active tasks: {active_tasks}")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
    
    async def run(self) -> int:
        """Main execution with error handling"""
        self._setup_signals()
        
        # Start health monitor
        health_task = asyncio.create_task(self._health_monitor())
        self._tasks.add(health_task)
        
        try:
            print("=" * 70)
            print(f"🔒 DNS Security Blocklist Builder v{VERSION}")
            print(f"🤖 AI Detection: {'ON' if self.config.ai_enabled else 'OFF'}")
            print(f"⚙️  Threshold: {self.config.ai_confidence_threshold:.0%}")
            print(f"📁 Output: {self.config.output_dynamic} + {self.config.output_simple}")
            if self.config.enable_compression and self.config.output_compressed:
                print(f"📦 Compression: Enabled")
            if self.config.enable_json and self.config.output_json:
                print(f"📊 JSON Output: Enabled")
            print(f"💾 Memory Limit: {self.config.memory_limit_mb} MB")
            print("=" * 70)
            
            # Create connector with optimized settings
            connector = aiohttp.TCPConnector(
                limit=self.config.concurrent_downloads,
                limit_per_host=Constants.CONNECTION_LIMIT_PER_HOST,
                ttl_dns_cache=Constants.DNS_CACHE_TTL,
                ssl=True,
                enable_cleanup_closed=True
            )
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=ClientTimeout(total=self.config.timeout)
            ) as session:
                
                # Initialize components
                validator = DomainValidator()
                ai_detector = AITrackerDetector(self.config.ai_confidence_threshold) if self.config.ai_enabled else None
                
                source_manager = SourceManager(self.config, session)
                processor = DomainProcessor(self.config, validator, ai_detector)
                output_gen = OutputGenerator(self.config)
                
                # Fetch sources
                print("\n📡 Fetching sources...")
                domains_by_source = await source_manager.fetch_all()
                
                if not domains_by_source:
                    self.logger.error("No sources fetched successfully")
                    return 1
                
                # Process domains
                await processor.process_sources(domains_by_source)
                
                records = processor.get_records()
                if not records:
                    self.logger.error("No valid domains after processing")
                    return 1
                
                # Generate outputs
                await output_gen.generate(records)
                
                # Print summary
                duration = time.time() - self.start_time
                print("\n" + "=" * 70)
                print("✅ BUILD COMPLETE")
                print(f"⏱️  Duration: {duration:.2f} seconds")
                print(f"📊 Domains: {len(records):,}")
                print(f"🤖 AI Trackers: {processor.stats.ai_detected:,}")
                print(f"🔁 Duplicates: {processor.stats.duplicates_removed:,}")
                print(f"❌ Invalid: {processor.stats.invalid_domains:,}")
                print(f"📡 Sources: {source_manager.stats.sources_processed}/{len(source_manager.SOURCES)}")
                print("=" * 70)
                
                return 0
                
        except asyncio.CancelledError:
            self.logger.info("Build cancelled")
            return 130
        except Exception as e:
            self.logger.error(f"Build failed: {e}", exc_info=self.config.verbose)
            return 1
        finally:
            # Cleanup
            self._shutdown.set()
            for task in self._tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f'DNS Security Blocklist Builder v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --output-dynamic ./output/hosts.txt --output-simple ./output/domains.txt
  %(prog)s --no-ai --verbose
  %(prog)s --ai-confidence 0.7 --output-compressed ./output/domains.txt.gz
        """
    )
    
    parser.add_argument(
        '--output-dynamic', 
        type=Path, 
        default=Path('./dynamic-blocklist.txt'),
        help='Output path for hosts file (default: ./dynamic-blocklist.txt)'
    )
    parser.add_argument(
        '--output-simple', 
        type=Path, 
        default=Path('./blocklist.txt'),
        help='Output path for simple domains (default: ./blocklist.txt)'
    )
    parser.add_argument(
        '--output-compressed',
        type=Path,
        help='Output path for compressed version (.gz)'
    )
    parser.add_argument(
        '--output-json',
        type=Path,
        help='Output path for JSON version'
    )
    parser.add_argument(
        '--max-domains', 
        type=int,
        help=f'Maximum domains to process (default: {Constants.MAX_DOMAINS_DEFAULT})'
    )
    parser.add_argument(
        '--no-ai', 
        action='store_true',
        help='Disable AI tracker detection'
    )
    parser.add_argument(
        '--ai-confidence', 
        type=float, 
        default=Constants.AI_CONFIDENCE_THRESHOLD,
        help=f'AI confidence threshold (default: {Constants.AI_CONFIDENCE_THRESHOLD})'
    )
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Enable verbose logging'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress non-error output'
    )
    parser.add_argument(
        '--no-compression',
        action='store_true',
        help='Disable compression output'
    )
    parser.add_argument(
        '--memory-limit',
        type=int,
        default=Constants.MEMORY_LIMIT_MB,
        help=f'Memory limit in MB (default: {Constants.MEMORY_LIMIT_MB})'
    )
    
    return parser.parse_args()


def setup_logging(verbose: bool, quiet: bool) -> None:
    """Configure logging with appropriate level"""
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S',
        handlers=[logging.StreamHandler()]
    )
    
    # Suppress noisy libraries
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)


async def async_main() -> int:
    """Async main entry point"""
    args = parse_args()
    
    # Create configuration
    config = Config(
        output_dynamic=args.output_dynamic,
        output_simple=args.output_simple,
        output_compressed=args.output_compressed,
        output_json=args.output_json,
        max_domains=args.max_domains or Constants.MAX_DOMAINS_DEFAULT,
        ai_enabled=not args.no_ai,
        ai_confidence_threshold=args.ai_confidence,
        verbose=args.verbose,
        quiet=args.quiet,
        enable_compression=not args.no_compression,
        memory_limit_mb=args.memory_limit
    )
    
    # Setup logging
    setup_logging(config.verbose, config.quiet)
    
    # Run builder
    builder = BlocklistBuilder(config)
    return await builder.run()


def main() -> int:
    """Synchronous main entry point"""
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n❌ Fatal error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
