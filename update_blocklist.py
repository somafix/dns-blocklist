#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - Enterprise Grade Security Tool (REFACTORED v5.0)
Author: Security Research Team
Version: 5.0.0 (Complete Refactoring with Enhanced Architecture)
License: MIT

CHANGELOG v5.0.0:
- Complete architectural refactoring with modular design
- Async I/O support for concurrent downloads
- Enhanced caching with Redis support (optional)
- Improved memory management with generators
- Advanced metrics collection
- Plugin system for custom sources
- Webhook notifications support
- Container-ready configuration
"""

import asyncio
import aiohttp
import aiofiles
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
import tempfile
import shutil
import ipaddress
import resource
import gc
import threading
import queue
import argparse
import yaml
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Set, Dict, List, Optional, Tuple, Any, Union, AsyncIterator, Callable
from collections import defaultdict, deque
import statistics
import functools
import pickle
import zlib
import base64

# ============================================================================
# CONFIGURATION MODULE
# ============================================================================

@dataclass
class SecurityConfig:
    """Centralized security configuration with validation."""
    
    # Resource limits
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_decompressed_size: int = 50 * 1024 * 1024  # 50MB
    max_domains: int = 300_000
    timeout: int = 10
    retries: int = 2
    
    # Performance
    batch_size: int = 10_000
    memory_limit_mb: int = 512
    cpu_time_limit: int = 60
    max_concurrent_downloads: int = 3
    
    # Cache
    max_cache_entries: int = 200
    max_cache_size_mb: int = 10
    cache_ttl: int = 3600
    redis_url: Optional[str] = None
    
    # Security
    trusted_sources: Set[str] = field(default_factory=lambda: {
        'raw.githubusercontent.com',
        'adaway.org',
        'github.com',
        'hostsfile.mine.nu',
        'someonewhocares.org',
        'cdn.jsdelivr.net',
        'gitlab.com',
        'oisd.nl'
    })
    
    # Network
    rate_limit: int = 3
    ssl_verify: bool = True
    user_agent: str = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    
    # Logging
    log_file: str = 'security_blocklist.log'
    log_level: str = 'INFO'
    
    # Notifications
    webhook_url: Optional[str] = None
    notification_events: Set[str] = field(default_factory=lambda: {'success', 'failure', 'warning'})
    
    # Output
    output_format: str = 'hosts'  # hosts, domains, dnsmasq, unbound
    output_compression: bool = False
    
    @classmethod
    def from_file(cls, path: Path) -> 'SecurityConfig':
        """Load configuration from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
    
    def to_file(self, path: Path) -> None:
        """Save configuration to YAML file."""
        with open(path, 'w') as f:
            yaml.dump(asdict(self), f, default_flow_style=False)
    
    def validate(self) -> bool:
        """Validate configuration values."""
        if self.max_file_size < 1024:
            raise ValueError("max_file_size must be at least 1KB")
        if self.max_domains < 1000:
            raise ValueError("max_domains must be at least 1000")
        if self.timeout < 1:
            raise ValueError("timeout must be at least 1 second")
        return True


# ============================================================================
# MODELS MODULE
# ============================================================================

class DomainStatus(Enum):
    """Domain validation status."""
    VALID = auto()
    INVALID_FORMAT = auto()
    INVALID_TLD = auto()
    TOO_LONG = auto()
    RESERVED = auto()
    DUPLICATE = auto()


@dataclass
class DomainRecord:
    """Domain record with metadata."""
    domain: str
    source: str
    timestamp: datetime
    status: DomainStatus = DomainStatus.VALID
    
    def __hash__(self):
        return hash(self.domain)
    
    def to_dict(self) -> Dict:
        return {
            'domain': self.domain,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status.name
        }


@dataclass
class SourceStats:
    """Statistics for a single source."""
    name: str
    url: str
    total_domains: int = 0
    new_domains: int = 0
    invalid_domains: int = 0
    fetch_time: float = 0.0
    fetch_size: int = 0
    cached: bool = False
    last_success: Optional[datetime] = None
    error_count: int = 0
    
    @property
    def success_rate(self) -> float:
        if self.error_count == 0:
            return 1.0
        total = self.total_domains + self.error_count
        return self.total_domains / total if total > 0 else 0.0


@dataclass
class BuildMetrics:
    """Overall build metrics."""
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    total_domains: int = 0
    unique_domains: int = 0
    sources_processed: int = 0
    sources_failed: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    memory_peak_mb: float = 0.0
    
    @property
    def duration(self) -> float:
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()
    
    def to_dict(self) -> Dict:
        return {
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration,
            'total_domains': self.total_domains,
            'unique_domains': self.unique_domains,
            'sources_processed': self.sources_processed,
            'sources_failed': self.sources_failed,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'memory_peak_mb': self.memory_peak_mb
        }


# ============================================================================
# VALIDATORS MODULE
# ============================================================================

class DomainValidator:
    """RFC-compliant domain validator with high performance."""
    
    # Constants
    MAX_DOMAIN_LEN = 253
    MAX_LABEL_LEN = 63
    MIN_DOMAIN_LEN = 3
    
    # Reserved TLDs
    RESERVED_TLDS = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan', 
        'internal', 'localdomain', 'home', 'arpa'
    }
    
    # Allowed characters
    ALLOWED_CHARS = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
    
    def __init__(self):
        self._stats = defaultdict(int)
    
    def validate(self, domain: str) -> DomainStatus:
        """Validate domain according to RFC 1035/1123."""
        domain_lower = domain.lower()
        
        # Length checks
        if len(domain_lower) < self.MIN_DOMAIN_LEN:
            self._stats['too_short'] += 1
            return DomainStatus.TOO_LONG
        
        if len(domain_lower) > self.MAX_DOMAIN_LEN:
            self._stats['too_long'] += 1
            return DomainStatus.TOO_LONG
        
        # Character checks
        if not all(c in self.ALLOWED_CHARS for c in domain_lower):
            self._stats['invalid_chars'] += 1
            return DomainStatus.INVALID_FORMAT
        
        # Hyphen position checks
        if domain_lower.startswith('-') or domain_lower.endswith('-'):
            self._stats['hyphen_position'] += 1
            return DomainStatus.INVALID_FORMAT
        
        # Label validation
        labels = domain_lower.split('.')
        if len(labels) < 2:
            self._stats['no_tld'] += 1
            return DomainStatus.INVALID_FORMAT
        
        for label in labels:
            if not label or len(label) > self.MAX_LABEL_LEN:
                self._stats['label_length'] += 1
                return DomainStatus.INVALID_FORMAT
            
            if label.startswith('-') or label.endswith('-'):
                self._stats['label_hyphen'] += 1
                return DomainStatus.INVALID_FORMAT
        
        # TLD validation
        tld = labels[-1]
        if tld in self.RESERVED_TLDS:
            self._stats['reserved_tld'] += 1
            return DomainStatus.RESERVED
        
        # TLD should be at least 2 characters
        if len(tld) < 2:
            self._stats['short_tld'] += 1
            return DomainStatus.INVALID_FORMAT
        
        self._stats['valid'] += 1
        return DomainStatus.VALID
    
    def validate_url(self, url: str) -> bool:
        """Validate and sanitize URL."""
        if len(url) > 2000:
            return False
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            if parsed.scheme not in ('https',):
                return False
            
            host = parsed.hostname
            if not host:
                return False
            
            # Path traversal protection
            if any(seq in parsed.path for seq in ['..', '//', '%2e', '%2f', '%5c']):
                return False
            
            host = host.lower()
            
            # IP address check (disallow direct IPs)
            try:
                ipaddress.ip_address(host)
                return False
            except ValueError:
                pass
            
            # Label validation
            labels = host.split('.')
            for label in labels:
                if not label or len(label) > 63:
                    return False
                if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def get_stats(self) -> Dict[str, int]:
        """Get validation statistics."""
        return dict(self._stats)
    
    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats.clear()


# ============================================================================
# PARSERS MODULE
# ============================================================================

class BaseParser(ABC):
    """Abstract base class for domain parsers."""
    
    @abstractmethod
    def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        """Parse content and yield domain records."""
        pass
    
    @abstractmethod
    def supports_format(self, url: str) -> bool:
        """Check if parser supports the given URL format."""
        pass


class HostsParser(BaseParser):
    """Parser for hosts file format."""
    
    def __init__(self, validator: DomainValidator):
        self._validator = validator
        self._pattern = re.compile(
            r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9][a-z0-9.-]*[a-z0-9])',
            re.MULTILINE | re.IGNORECASE
        )
    
    async def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        """Parse hosts file format."""
        timestamp = datetime.now(timezone.utc)
        
        for match in self._pattern.finditer(content):
            domain = match.group(1).lower()
            status = self._validator.validate(domain)
            
            yield DomainRecord(
                domain=domain,
                source=source,
                timestamp=timestamp,
                status=status
            )
    
    def supports_format(self, url: str) -> bool:
        """Check if URL is likely a hosts file."""
        return any(ext in url for ext in ['hosts', '.txt'])


class DomainsParser(BaseParser):
    """Parser for plain domain list format."""
    
    def __init__(self, validator: DomainValidator):
        self._validator = validator
    
    async def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        """Parse plain domain list format."""
        timestamp = datetime.now(timezone.utc)
        
        for line in content.splitlines():
            domain = line.strip().lower()
            
            # Skip comments and empty lines
            if not domain or domain.startswith('#'):
                continue
            
            # Skip IP addresses
            if domain[0].isdigit():
                continue
            
            status = self._validator.validate(domain)
            
            yield DomainRecord(
                domain=domain,
                source=source,
                timestamp=timestamp,
                status=status
            )
    
    def supports_format(self, url: str) -> bool:
        """Check if URL is likely a domain list."""
        return 'domains' in url or 'domainswild' in url


class AdblockParser(BaseParser):
    """Parser for Adblock filter format."""
    
    def __init__(self, validator: DomainValidator):
        self._validator = validator
        self._pattern = re.compile(r'^\|\|([a-z0-9][a-z0-9.-]*[a-z0-9])\^')
    
    async def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        """Parse Adblock filter format."""
        timestamp = datetime.now(timezone.utc)
        
        for line in content.splitlines():
            # Skip comments and empty lines
            if not line or line.startswith('!'):
                continue
            
            # Extract domain from filter
            match = self._pattern.match(line)
            if match:
                domain = match.group(1).lower()
                status = self._validator.validate(domain)
                
                yield DomainRecord(
                    domain=domain,
                    source=source,
                    timestamp=timestamp,
                    status=status
                )
    
    def supports_format(self, url: str) -> bool:
        """Check if URL is likely an Adblock list."""
        return 'adblock' in url or 'adblocker' in url


class ParserFactory:
    """Factory for creating appropriate parsers."""
    
    def __init__(self, validator: DomainValidator):
        self._validator = validator
        self._parsers: List[BaseParser] = [
            HostsParser(validator),
            DomainsParser(validator),
            AdblockParser(validator)
        ]
    
    def get_parser(self, url: str) -> BaseParser:
        """Get the most appropriate parser for a URL."""
        for parser in self._parsers:
            if parser.supports_format(url):
                return parser
        
        # Default to hosts parser
        return self._parsers[0]


# ============================================================================
# CACHE MODULE
# ============================================================================

class CacheBackend(ABC):
    """Abstract cache backend interface."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete value from cache."""
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        """Clear all cache entries."""
        pass


class MemoryCache(CacheBackend):
    """In-memory cache with LRU eviction."""
    
    def __init__(self, max_entries: int = 200, max_size_mb: int = 10):
        self._cache: Dict[str, tuple[Any, float]] = {}
        self._max_entries = max_entries
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._current_size = 0
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from memory cache."""
        async with self._lock:
            if key in self._cache:
                value, expiry = self._cache[key]
                if expiry > time.time():
                    return value
                else:
                    del self._cache[key]
                    self._current_size -= sys.getsizeof(value)
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in memory cache with size management."""
        async with self._lock:
            value_size = sys.getsizeof(value)
            
            # Remove old entry if exists
            if key in self._cache:
                old_value, _ = self._cache[key]
                self._current_size -= sys.getsizeof(old_value)
            
            # Check if we need to evict
            while self._current_size + value_size > self._max_size_bytes:
                if not self._cache:
                    break
                oldest_key = next(iter(self._cache))
                oldest_value, _ = self._cache.pop(oldest_key)
                self._current_size -= sys.getsizeof(oldest_value)
            
            expiry = time.time() + (ttl or 3600)
            self._cache[key] = (value, expiry)
            self._current_size += value_size
    
    async def delete(self, key: str) -> None:
        """Delete value from cache."""
        async with self._lock:
            if key in self._cache:
                value, _ = self._cache.pop(key)
                self._current_size -= sys.getsizeof(value)
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
            self._current_size = 0


class RedisCache(CacheBackend):
    """Redis-backed cache for distributed deployments."""
    
    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._redis = None
        self._connected = False
    
    async def _get_redis(self):
        """Get Redis connection."""
        if not self._connected:
            import redis.asyncio as redis
            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            self._connected = True
        return self._redis
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis."""
        try:
            redis_client = await self._get_redis()
            data = await redis_client.get(key)
            if data:
                return pickle.loads(base64.b64decode(data))
        except Exception:
            pass
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in Redis."""
        try:
            redis_client = await self._get_redis()
            serialized = base64.b64encode(pickle.dumps(value))
            await redis_client.set(key, serialized, ex=ttl)
        except Exception:
            pass
    
    async def delete(self, key: str) -> None:
        """Delete value from Redis."""
        try:
            redis_client = await self._get_redis()
            await redis_client.delete(key)
        except Exception:
            pass
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        try:
            redis_client = await self._get_redis()
            await redis_client.flushdb()
        except Exception:
            pass


# ============================================================================
# HTTP CLIENT MODULE
# ============================================================================

class SecureHTTPClient:
    """Enterprise-grade HTTP client with async support."""
    
    def __init__(self, config: SecurityConfig, logger: logging.Logger):
        self._config = config
        self._logger = logger
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request_time: float = 0
        self._request_count: int = 0
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close_session()
    
    async def _create_session(self):
        """Create aiohttp session with security settings."""
        connector = aiohttp.TCPConnector(
            ssl=self._config.ssl_verify,
            limit=self._config.max_concurrent_downloads,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self._config.timeout,
            connect=5,
            sock_read=self._config.timeout
        )
        
        headers = {
            'User-Agent': self._config.user_agent,
            'Accept': 'text/plain,application/json,*/*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
    
    async def _close_session(self):
        """Close aiohttp session."""
        if self._session:
            await self._session.close()
    
    async def _rate_limit(self):
        """Apply rate limiting."""
        async with self._lock:
            now = time.time()
            min_interval = 1.0 / self._config.rate_limit
            
            if self._last_request_time > 0:
                elapsed = now - self._last_request_time
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
            
            self._last_request_time = time.time()
            self._request_count += 1
    
    async def fetch(self, url: str) -> Tuple[Optional[str], Optional[Dict]]:
        """Fetch URL content with retries."""
        if not DomainValidator.validate_url(url):
            self._logger.warning(f"Rejected unsafe URL: {url}")
            return None, None
        
        for attempt in range(self._config.retries + 1):
            try:
                await self._rate_limit()
                
                async with self._session.get(url) as response:
                    if response.status == 200:
                        content = await response.read()
                        
                        # Decompress if needed
                        content_encoding = response.headers.get('Content-Encoding', '')
                        if content_encoding == 'gzip':
                            import gzip
                            content = gzip.decompress(content)
                        elif content_encoding == 'deflate':
                            import zlib
                            content = zlib.decompress(content)
                        
                        # Check size limits
                        if len(content) > self._config.max_file_size:
                            self._logger.error(f"File too large: {len(content)} bytes")
                            return None, None
                        
                        text = content.decode('utf-8', errors='replace')
                        
                        # Cache metadata
                        metadata = {
                            'etag': response.headers.get('ETag'),
                            'last_modified': response.headers.get('Last-Modified'),
                            'timestamp': time.time()
                        }
                        
                        self._logger.info(f"Fetched {url}: {len(text):,} bytes")
                        return text, {k: v for k, v in metadata.items() if v}
                    
                    elif response.status == 304:
                        self._logger.info(f"Content unchanged: {url}")
                        return None, None
                    
                    else:
                        self._logger.warning(f"HTTP {response.status}: {url}")
                        
            except asyncio.TimeoutError:
                self._logger.warning(f"Timeout on attempt {attempt + 1}: {url}")
            except Exception as e:
                self._logger.error(f"Error on attempt {attempt + 1}: {e}")
            
            # Wait before retry
            if attempt < self._config.retries:
                await asyncio.sleep(2 ** attempt)
        
        return None, None


# ============================================================================
# SOURCE MANAGER MODULE
# ============================================================================

@dataclass
class Source:
    """Blocklist source definition."""
    name: str
    url: str
    fallbacks: List[str] = field(default_factory=list)
    enabled: bool = True
    parser_type: Optional[str] = None
    timeout: Optional[int] = None
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'url': self.url,
            'fallbacks': self.fallbacks,
            'enabled': self.enabled,
            'parser_type': self.parser_type
        }


class SourceManager:
    """Manages blocklist sources with fallback support."""
    
    def __init__(self, config: SecurityConfig):
        self._config = config
        self._sources: Dict[str, Source] = {}
        self._working_cache: Dict[str, str] = {}
        self._load_default_sources()
    
    def _load_default_sources(self):
        """Load default blocklist sources."""
        self._sources = {
            'stevenblack': Source(
                name='StevenBlack',
                url='https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                fallbacks=[
                    'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts',
                    'https://cdn.jsdelivr.net/gh/StevenBlack/hosts@master/hosts'
                ]
            ),
            'adaway': Source(
                name='AdAway',
                url='https://adaway.org/hosts.txt',
                fallbacks=[
                    'https://adaway.surge.sh/hosts.txt'
                ]
            ),
            'hagezi': Source(
                name='HaGeZi Ultimate',
                url='https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt',
                fallbacks=[
                    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt'
                ]
            ),
            'someonewhocares': Source(
                name='SomeoneWhoCares',
                url='https://someonewhocares.org/hosts/zero/hosts',
                fallbacks=[]
            ),
            'oisd': Source(
                name='OISD',
                url='https://big.oisd.nl/domainswild2',
                fallbacks=[
                    'https://small.oisd.nl/domainswild'
                ]
            )
        }
    
    def add_source(self, source: Source) -> None:
        """Add custom source."""
        self._sources[source.name.lower()] = source
    
    def remove_source(self, name: str) -> None:
        """Remove source."""
        key = name.lower()
        if key in self._sources:
            del self._sources[key]
    
    def get_sources(self) -> List[Source]:
        """Get all enabled sources."""
        return [s for s in self._sources.values() if s.enabled]
    
    async def get_working_url(self, source: Source) -> Tuple[str, bool]:
        """Get working URL for source with fallback."""
        # Check cache first
        if source.name in self._working_cache:
            cached_url = self._working_cache[source.name]
            if cached_url == source.url or cached_url in source.fallbacks:
                return cached_url, True
        
        # Check primary URL
        if await self._check_url(source.url):
            self._working_cache[source.name] = source.url
            return source.url, False
        
        # Check fallbacks
        for fallback in source.fallbacks:
            if await self._check_url(fallback):
                self._working_cache[source.name] = fallback
                return fallback, False
        
        return source.url, False
    
    async def _check_url(self, url: str) -> bool:
        """Quick check if URL is accessible."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=5) as response:
                    return response.status == 200
        except Exception:
            return False
    
    def mark_working(self, name: str, url: str) -> None:
        """Mark URL as working for source."""
        self._working_cache[name] = url
        self._save_working_cache()
    
    def _save_working_cache(self) -> None:
        """Save working cache to disk."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp:
                json.dump(self._working_cache, tmp)
            
            shutil.move(tmp.name, '.source_cache.json')
        except Exception:
            pass


# ============================================================================
# PROCESSOR MODULE
# ============================================================================

class DomainProcessor:
    """Process and deduplicate domains."""
    
    def __init__(self, max_domains: int = 300000):
        self._max_domains = max_domains
        self._domains: Dict[str, DomainRecord] = {}
        self._sources: Dict[str, SourceStats] = {}
        self._lock = asyncio.Lock()
    
    async def add_record(self, record: DomainRecord) -> bool:
        """Add domain record if valid and not duplicate."""
        async with self._lock:
            # Check limit
            if len(self._domains) >= self._max_domains:
                return False
            
            # Only add valid domains
            if record.status != DomainStatus.VALID:
                return False
            
            # Update source stats
            if record.source not in self._sources:
                self._sources[record.source] = SourceStats(name=record.source, url='')
            
            # Check if new
            if record.domain not in self._domains:
                self._domains[record.domain] = record
                self._sources[record.source].new_domains += 1
                self._sources[record.source].total_domains += 1
                return True
            else:
                self._sources[record.source].total_domains += 1
                return False
    
    async def add_batch(self, records: List[DomainRecord]) -> int:
        """Add batch of domain records."""
        added = 0
        for record in records:
            if await self.add_record(record):
                added += 1
        return added
    
    def get_domains(self) -> List[str]:
        """Get sorted list of all domains."""
        return sorted(self._domains.keys())
    
    def get_stats(self) -> Dict[str, SourceStats]:
        """Get source statistics."""
        return self._sources
    
    def get_count(self) -> int:
        """Get total domain count."""
        return len(self._domains)
    
    def clear(self) -> None:
        """Clear all domains."""
        self._domains.clear()
        self._sources.clear()


# ============================================================================
# NOTIFIER MODULE
# ============================================================================

class NotificationEvent(Enum):
    """Notification event types."""
    START = 'start'
    SUCCESS = 'success'
    FAILURE = 'failure'
    WARNING = 'warning'
    COMPLETE = 'complete'


class BaseNotifier(ABC):
    """Abstract notifier interface."""
    
    @abstractmethod
    async def notify(self, event: NotificationEvent, data: Dict[str, Any]) -> None:
        """Send notification."""
        pass


class WebhookNotifier(BaseNotifier):
    """Webhook-based notifier."""
    
    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url
    
    async def notify(self, event: NotificationEvent, data: Dict[str, Any]) -> None:
        """Send webhook notification."""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    'event': event.value,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'data': data
                }
                await session.post(self._webhook_url, json=payload)
        except Exception:
            pass


class LogNotifier(BaseNotifier):
    """Logging-based notifier."""
    
    def __init__(self, logger: logging.Logger):
        self._logger = logger
    
    async def notify(self, event: NotificationEvent, data: Dict[str, Any]) -> None:
        """Log notification."""
        self._logger.info(f"Notification [{event.value}]: {data}")


class NotifierManager:
    """Manage multiple notifiers."""
    
    def __init__(self):
        self._notifiers: List[BaseNotifier] = []
    
    def add_notifier(self, notifier: BaseNotifier) -> None:
        """Add notifier."""
        self._notifiers.append(notifier)
    
    async def notify_all(self, event: NotificationEvent, data: Dict[str, Any]) -> None:
        """Send notification to all notifiers."""
        for notifier in self._notifiers:
            try:
                await notifier.notify(event, data)
            except Exception:
                pass


# ============================================================================
# OUTPUT GENERATOR MODULE
# ============================================================================

class BaseOutputGenerator(ABC):
    """Abstract output generator."""
    
    @abstractmethod
    def generate_header(self, metrics: BuildMetrics) -> List[str]:
        """Generate header lines."""
        pass
    
    @abstractmethod
    def format_domain(self, domain: str) -> str:
        """Format single domain for output."""
        pass


class HostsOutputGenerator(BaseOutputGenerator):
    """Generate hosts file format."""
    
    def generate_header(self, metrics: BuildMetrics) -> List[str]:
        """Generate hosts file header."""
        return [
            "# ====================================================================",
            "# DNS SECURITY BLOCKLIST - ENTERPRISE GRADE",
            "# ====================================================================",
            f"# Generated: {metrics.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Total domains: {metrics.unique_domains:,}",
            f"# Sources processed: {metrics.sources_processed}",
            f"# Duration: {metrics.duration:.2f} seconds",
            "# ====================================================================",
            "",
            "127.0.0.1 localhost",
            "::1 localhost",
            ""
        ]
    
    def format_domain(self, domain: str) -> str:
        """Format domain for hosts file."""
        return f"0.0.0.0 {domain}"


class DomainsOutputGenerator(BaseOutputGenerator):
    """Generate plain domain list."""
    
    def generate_header(self, metrics: BuildMetrics) -> List[str]:
        """Generate domain list header."""
        return [
            f"# DNS Security Blocklist - {metrics.unique_domains:,} domains",
            f"# Generated: {metrics.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            ""
        ]
    
    def format_domain(self, domain: str) -> str:
        """Format domain for list."""
        return domain


class DnsmasqOutputGenerator(BaseOutputGenerator):
    """Generate dnsmasq format."""
    
    def generate_header(self, metrics: BuildMetrics) -> List[str]:
        """Generate dnsmasq header."""
        return [
            "# DNS Security Blocklist for dnsmasq",
            f"# Generated: {metrics.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            ""
        ]
    
    def format_domain(self, domain: str) -> str:
        """Format domain for dnsmasq."""
        return f"address=/{domain}/0.0.0.0"


class OutputGeneratorFactory:
    """Factory for output generators."""
    
    @staticmethod
    def create(format_type: str) -> BaseOutputGenerator:
        """Create output generator for format."""
        generators = {
            'hosts': HostsOutputGenerator,
            'domains': DomainsOutputGenerator,
            'dnsmasq': DnsmasqOutputGenerator
        }
        
        generator_class = generators.get(format_type, HostsOutputGenerator)
        return generator_class()


# ============================================================================
# MAIN BUILDER MODULE
# ============================================================================

class SecurityBlocklistBuilder:
    """Main orchestrator for blocklist generation."""
    
    def __init__(self, config: SecurityConfig):
        self._config = config
        self._logger = self._setup_logging()
        self._validator = DomainValidator()
        self._parser_factory = ParserFactory(self._validator)
        self._source_manager = SourceManager(config)
        self._processor = DomainProcessor(config.max_domains)
        self._notifier = NotifierManager()
        self._metrics = BuildMetrics()
        self._output_generator = OutputGeneratorFactory.create(config.output_format)
        
        # Setup notifiers
        self._notifier.add_notifier(LogNotifier(self._logger))
        if config.webhook_url:
            self._notifier.add_notifier(WebhookNotifier(config.webhook_url))
        
        # Setup cache
        if config.redis_url:
            self._cache = RedisCache(config.redis_url)
        else:
            self._cache = MemoryCache(config.max_cache_entries, config.max_cache_size_mb)
        
        # Setup signal handling
        self._shutdown = asyncio.Event()
        self._setup_signal_handlers()
        
        # Track memory usage
        self._setup_memory_tracking()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('DNSBlocklist')
        logger.setLevel(getattr(logging, self._config.log_level))
        
        # Console handler
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(console)
        
        # File handler
        file_handler = logging.FileHandler(self._config.log_file)
        file_handler.setFormatter(console.formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()
        
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(
                sig,
                lambda: asyncio.create_task(self._handle_shutdown(sig))
            )
    
    async def _handle_shutdown(self, sig: int):
        """Handle shutdown signal."""
        self._logger.warning(f"Received signal {sig}, initiating graceful shutdown...")
        self._shutdown.set()
    
    def _setup_memory_tracking(self):
        """Setup memory usage tracking."""
        def track_memory():
            try:
                import psutil
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                self._metrics.memory_peak_mb = max(self._metrics.memory_peak_mb, memory_mb)
            except ImportError:
                pass
        
        # Track memory periodically
        asyncio.get_event_loop().call_later(1, track_memory)
    
    async def process_source(self, source: Source) -> SourceStats:
        """Process a single source with fallback support."""
        stats = SourceStats(name=source.name, url=source.url)
        start_time = time.time()
        
        # Get working URL
        working_url, cached = await self._source_manager.get_working_url(source)
        stats.cached = cached
        
        self._logger.info(f"Processing {source.name}: {working_url}")
        
        async with SecureHTTPClient(self._config, self._logger) as client:
            # Check cache first
            cache_key = f"content:{working_url}"
            cached_content = await self._cache.get(cache_key)
            
            if cached_content:
                self._metrics.cache_hits += 1
                content = cached_content
                self._logger.info(f"Using cached content for {source.name}")
            else:
                self._metrics.cache_misses += 1
                content, metadata = await client.fetch(working_url)
                
                if content:
                    # Cache for future
                    await self._cache.set(cache_key, content, ttl=self._config.cache_ttl)
                    
                    # Store metadata
                    if metadata:
                        await self._cache.set(f"meta:{working_url}", metadata, ttl=self._config.cache_ttl)
            
            if not content:
                stats.error_count += 1
                self._logger.error(f"Failed to fetch {source.name}")
                return stats
            
            stats.fetch_size = len(content)
            
            # Parse content
            parser = self._parser_factory.get_parser(working_url)
            domain_count = 0
            invalid_count = 0
            
            async for record in parser.parse(content, source.name):
                if self._shutdown.is_set():
                    break
                
                if await self._processor.add_record(record):
                    domain_count += 1
                else:
                    if record.status != DomainStatus.VALID:
                        invalid_count += 1
            
            stats.total_domains = domain_count + invalid_count
            stats.new_domains = domain_count
            stats.invalid_domains = invalid_count
            stats.last_success = datetime.now(timezone.utc)
            
            self._logger.info(
                f"✓ {source.name}: {domain_count:,} valid, "
                f"{invalid_count:,} invalid [{time.time() - start_time:.2f}s]"
            )
            
            # Mark as working
            self._source_manager.mark_working(source.name, working_url)
            
            return stats
    
    async def process_all_sources(self) -> None:
        """Process all sources concurrently."""
        sources = self._source_manager.get_sources()
        self._metrics.sources_processed = len(sources)
        
        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self._config.max_concurrent_downloads)
        
        async def process_with_limit(source: Source):
            async with semaphore:
                return await self.process_source(source)
        
        # Process sources concurrently
        tasks = [process_with_limit(source) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                self._logger.error(f"Source processing failed: {result}")
                self._metrics.sources_failed += 1
            elif isinstance(result, SourceStats):
                self._processor.get_stats()[result.name] = result
    
    async def generate_output(self) -> Optional[Path]:
        """Generate final blocklist file."""
        domains = self._processor.get_domains()
        
        if not domains:
            self._logger.error("No domains to generate blocklist")
            return None
        
        self._metrics.unique_domains = len(domains)
        
        # Calculate hash
        domain_string = ''.join(domains)
        file_hash = hashlib.sha256(domain_string.encode()).hexdigest()
        
        output_path = Path('dynamic-blocklist.txt')
        
        # Generate with streaming
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as tmp:
                # Write header
                header_lines = self._output_generator.generate_header(self._metrics)
                header_lines.append(f"# SHA-256: {file_hash}\n")
                
                for line in header_lines:
                    tmp.write(line + '\n')
                
                # Write domains
                for domain in domains:
                    line = self._output_generator.format_domain(domain)
                    tmp.write(line + '\n')
                
                tmp.flush()
            
            # Atomic rename
            shutil.move(tmp.name, output_path)
            
            # Create backup
            shutil.copy2(output_path, Path('dynamic-blocklist.txt.backup'))
            
            # Compress if needed
            if self._config.output_compression:
                import gzip
                with open(output_path, 'rb') as f_in:
                    with gzip.open(f"{output_path}.gz", 'wb') as f_out:
                        f_out.writelines(f_in)
            
            self._logger.info(f"Generated blocklist: {output_path} ({len(domains):,} domains)")
            return output_path
            
        except Exception as e:
            self._logger.error(f"Failed to generate output: {e}")
            return None
    
    def print_report(self) -> None:
        """Generate and print build report."""
        print("\n" + "=" * 80)
        print("🔒 DNS SECURITY BLOCKLIST REPORT")
        print("=" * 80)
        
        # Source statistics
        print(f"\n{'SOURCE':<35} {'VALID':>12} {'INVALID':>10} {'TIME':>8} {'CACHE':>6}")
        print("-" * 80)
        
        for name, stats in self._processor.get_stats().items():
            cache_mark = "✓" if stats.cached else "✗"
            print(
                f"{name:<35} {stats.new_domains:>12,} "
                f"{stats.invalid_domains:>10,} "
                f"{stats.fetch_time:>7.2f}s "
                f"{cache_mark:>6}"
            )
        
        print("-" * 80)
        print(f"{'TOTAL':<35} {self._processor.get_count():>12,}")
        print("=" * 80)
        
        # Performance metrics
        print(f"\n📊 Performance Metrics:")
        print(f"  • Total execution time: {self._metrics.duration:.2f} seconds")
        print(f"  • Processing rate: {self._processor.get_count() / self._metrics.duration:.0f} domains/second")
        print(f"  • Sources processed: {self._metrics.sources_processed}")
        print(f"  • Sources failed: {self._metrics.sources_failed}")
        
        # Security metrics
        validator_stats = self._validator.get_stats()
        print(f"\n🛡️ Security Metrics:")
        print(f"  • Valid domains: {validator_stats.get('valid', 0):,}")
        print(f"  • Invalid domains: {sum(v for k, v in validator_stats.items() if k != 'valid'):,}")
        
        # Cache metrics
        print(f"\n💾 Cache Statistics:")
        print(f"  • Cache hits: {self._metrics.cache_hits}")
        print(f"  • Cache misses: {self._metrics.cache_misses}")
        print(f"  • Hit rate: {self._metrics.cache_hits / max(1, self._metrics.cache_hits + self._metrics.cache_misses) * 100:.1f}%")
        
        # Memory metrics
        print(f"\n💾 Memory Usage:")
        print(f"  • Peak RSS: {self._metrics.memory_peak_mb:.1f} MB")
        
        print("=" * 80)
    
    async def run(self) -> int:
        """Execute the blocklist builder."""
        print("\n" + "=" * 80)
        print("🚀 DNS SECURITY BLOCKLIST BUILDER v5.0.0")
        print("Enterprise-grade threat intelligence aggregation")
        print("=" * 80)
        
        await self._notifier.notify_all(NotificationEvent.START, {'config': asdict(self._config)})
        
        try:
            # Process all sources
            await self.process_all_sources()
            
            # Check if we have domains
            if self._processor.get_count() == 0:
                self._logger.error("No domains collected, attempting recovery...")
                await self._emergency_recovery()
            
            # Generate output
            output_path = await self.generate_output()
            
            if output_path:
                self._metrics.end_time = datetime.now(timezone.utc)
                self.print_report()
                
                await self._notifier.notify_all(NotificationEvent.SUCCESS, {
                    'domains': self._processor.get_count(),
                    'output': str(output_path),
                    'duration': self._metrics.duration
                })
                
                return 0
            else:
                self._metrics.end_time = datetime.now(timezone.utc)
                await self._notifier.notify_all(NotificationEvent.FAILURE, {
                    'error': 'Output generation failed'
                })
                return 1
                
        except Exception as e:
            self._logger.error(f"Build failed: {e}", exc_info=True)
            await self._notifier.notify_all(NotificationEvent.FAILURE, {
                'error': str(e)
            })
            return 1
    
    async def _emergency_recovery(self) -> bool:
        """Emergency recovery from backup."""
        backup_file = Path('dynamic-blocklist.txt.backup')
        
        if not backup_file.exists():
            self._logger.error("No backup file found")
            return False
        
        try:
            domains = []
            async with aiofiles.open(backup_file, 'r') as f:
                async for line in f:
                    if line.startswith('0.0.0.0'):
                        parts = line.split()
                        if len(parts) >= 2:
                            domain = parts[1].strip()
                            status = self._validator.validate(domain)
                            if status == DomainStatus.VALID:
                                domains.append(domain)
            
            for domain in domains:
                await self._processor.add_record(DomainRecord(
                    domain=domain,
                    source='emergency_recovery',
                    timestamp=datetime.now(timezone.utc),
                    status=DomainStatus.VALID
                ))
            
            self._logger.info(f"Recovered {len(domains):,} domains from backup")
            return len(domains) > 0
            
        except Exception as e:
            self._logger.error(f"Emergency recovery failed: {e}")
            return False


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

async def async_main():
    """Async main entry point."""
    parser = argparse.ArgumentParser(description='DNS Security Blocklist Builder')
    parser.add_argument('-c', '--config', type=Path, help='Configuration file path')
    parser.add_argument('-o', '--output', choices=['hosts', 'domains', 'dnsmasq'], 
                       default='hosts', help='Output format')
    parser.add_argument('--no-compress', action='store_true', help='Disable output compression')
    parser.add_argument('--max-domains', type=int, default=300000, help='Maximum domains to collect')
    parser.add_argument('--memory-limit', type=int, default=512, help='Memory limit in MB')
    
    args = parser.parse_args()
    
    # Load configuration
    if args.config and args.config.exists():
        config = SecurityConfig.from_file(args.config)
    else:
        config = SecurityConfig()
    
    # Override with CLI arguments
    config.output_format = args.output
    config.output_compression = not args.no_compress
    config.max_domains = args.max_domains
    config.memory_limit_mb = args.memory_limit
    
    # Validate configuration
    config.validate()
    
    # Set resource limits
    try:
        memory_bytes = config.memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (config.cpu_time_limit, config.cpu_time_limit))
    except Exception:
        pass
    
    # Run builder
    builder = SecurityBlocklistBuilder(config)
    return await builder.run()


def main():
    """Synchronous main entry point."""
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        return 130
    except MemoryError:
        print("❌ Fatal error: Out of memory")
        return 1
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
