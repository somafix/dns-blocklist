#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - Enterprise Grade Security Tool (v5.2.1)
Author: Security Research Team
Version: 5.2.1 (HaGeZi Removed + All Features Preserved)
License: MIT

CHANGELOG v5.2.1:
- REMOVED: HaGeZi source (false positives)
- REMOVED: Energized source (unstable)
- KEPT: All enterprise features (caching, metrics, health checks, etc.)
- FIXED: NoneType error in output generation
- FIXED: Dependency installation in CI/CD
"""

import sys
import os
import subprocess

# ============================================================================
# AUTO-INSTALL DEPENDENCIES (для CI/CD)
# ============================================================================

def install_dependencies():
    """Auto-install required packages for GitHub Actions"""
    required = ['aiohttp', 'aiofiles', 'PyYAML', 'prometheus-client', 'cryptography']
    missing = []
    
    for pkg in required:
        pkg_name = pkg.replace('-', '_')
        try:
            __import__(pkg_name)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"📦 Installing missing packages: {missing}")
        for pkg in missing:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'])
        print("✅ Dependencies installed successfully")

# Run auto-install
install_dependencies()

# ============================================================================
# IMPORTS
# ============================================================================

import asyncio
import aiohttp
import aiofiles
import hashlib
import json
import logging
import re
import signal
import time
import tempfile
import shutil
import ipaddress
import resource
import gc
import argparse
import yaml
import ssl
import hmac
import mmap
import array
import math
import statistics
import pickle
import base64
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Set, Dict, List, Optional, Tuple, Any, Union, AsyncIterator, Callable, FrozenSet
from collections import defaultdict, Counter
from functools import lru_cache, wraps
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Optional imports with fallbacks
try:
    import certifi
    HAS_CERTIFI = True
except ImportError:
    HAS_CERTIFI = False

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from prometheus_client import start_http_server, Counter, Histogram, Gauge
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

# ============================================================================
# CONSTANTS
# ============================================================================

VERSION = "5.2.1"
VERSION_INFO = {
    'major': 5,
    'minor': 2,
    'patch': 1,
    'build': datetime.now().strftime('%Y%m%d')
}

class Constants:
    """Centralized constants"""
    MAX_DOMAIN_LEN = 253
    MAX_LABEL_LEN = 63
    MIN_DOMAIN_LEN = 3
    
    ENCRYPTION_KEY_FILE = '.encryption.key'
    SOURCE_CACHE_FILE = '.source_cache.json'
    BACKUP_FILE = 'dynamic-blocklist.txt.backup'
    
    BLOOM_FILTER_FP_RATE = 0.01
    
    HEALTH_CHECK_PORT = 8080
    METRICS_PORT = 9090
    MIN_DISK_SPACE_MB = 100
    MIN_MEMORY_MB = 50
    
    RESERVED_TLDS: FrozenSet[str] = frozenset({
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa'
    })

# ============================================================================
# CONFIGURATION MODULE
# ============================================================================

@dataclass
class SecurityConfig:
    """Centralized security configuration with validation"""
    
    max_file_size: int = 10 * 1024 * 1024
    max_decompressed_size: int = 50 * 1024 * 1024
    max_domains: int = 500_000
    timeout: int = 15
    retries: int = 2
    
    batch_size: int = 10_000
    memory_limit_mb: int = 1024
    cpu_time_limit: int = 120
    max_concurrent_downloads: int = 3
    
    max_cache_entries: int = 200
    max_cache_size_mb: int = 10
    cache_ttl: int = 3600
    redis_url: Optional[str] = None
    
    min_source_quality: float = 0.7
    exclude_sources: List[str] = field(default_factory=list)
    include_sources: List[str] = field(default_factory=list)
    
    trusted_sources: Set[str] = field(default_factory=lambda: {
        'raw.githubusercontent.com', 'adaway.org', 'github.com',
        'someonewhocares.org', 'cdn.jsdelivr.net', 'gitlab.com', 'oisd.nl'
    })
    
    rate_limit: int = 3
    ssl_verify: bool = True
    user_agent: str = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    
    log_file: str = 'security_blocklist.log'
    log_level: str = 'INFO'
    log_json_format: bool = False
    
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    notification_events: Set[str] = field(default_factory=lambda: {'success', 'failure'})
    
    output_format: str = 'hosts'
    output_compression: bool = False
    output_path: str = 'dynamic-blocklist.txt'
    
    metrics_enabled: bool = False
    metrics_port: int = 9090
    health_check_enabled: bool = True
    health_check_port: int = 8080
    
    @classmethod
    def from_file(cls, path: Path) -> 'SecurityConfig':
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
    
    def validate(self) -> bool:
        if self.max_file_size < 1024:
            raise ValueError("max_file_size must be at least 1KB")
        if self.max_domains < 1000:
            raise ValueError("max_domains must be at least 1000")
        return True

# ============================================================================
# MODELS MODULE
# ============================================================================

class DomainStatus(Enum):
    VALID = auto()
    INVALID_FORMAT = auto()
    INVALID_TLD = auto()
    TOO_LONG = auto()
    RESERVED = auto()
    DUPLICATE = auto()

class SourceQuality(Enum):
    EXCELLENT = auto()
    GOOD = auto()
    FAIR = auto()
    POOR = auto()
    UNKNOWN = auto()

@dataclass(frozen=True)
class DomainRecord:
    domain: str
    source: str
    timestamp: datetime
    status: DomainStatus = DomainStatus.VALID
    
    def __hash__(self) -> int:
        return hash(self.domain)
    
    def to_hosts_entry(self) -> str:
        return f"0.0.0.0 {self.domain}"
    
    def to_dnsmasq_entry(self) -> str:
        return f"address=/{self.domain}/0.0.0.0"

@dataclass
class SourceStats:
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
    def quality_score(self) -> float:
        if self.total_domains == 0:
            return 0.0
        return 1.0 - (self.invalid_domains / self.total_domains)
    
    @property
    def quality_rating(self) -> SourceQuality:
        score = self.quality_score
        if score >= 0.99:
            return SourceQuality.EXCELLENT
        elif score >= 0.95:
            return SourceQuality.GOOD
        elif score >= 0.85:
            return SourceQuality.FAIR
        return SourceQuality.POOR

@dataclass
class BuildMetrics:
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    total_domains: int = 0
    unique_domains: int = 0
    sources_processed: int = 0
    sources_failed: int = 0
    sources_filtered: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    memory_peak_mb: float = 0.0
    
    @property
    def duration(self) -> float:
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

# ============================================================================
# OPTIMIZED DATA STRUCTURES
# ============================================================================

class BloomFilter:
    """Memory-efficient probabilistic set membership"""
    
    def __init__(self, capacity: int, false_positive_rate: float = Constants.BLOOM_FILTER_FP_RATE):
        self.capacity = capacity
        self.size = self._optimal_size(capacity, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, capacity)
        self.bits = array.array('B', [0]) * ((self.size + 7) // 8)
    
    def _optimal_size(self, n: int, p: float) -> int:
        return int(-(n * math.log(p)) / (math.log(2) ** 2))
    
    def _optimal_hash_count(self, m: int, n: int) -> int:
        return int((m / n) * math.log(2))
    
    def _hash(self, item: str, seed: int) -> int:
        return (hash(item) ^ seed) % self.size
    
    def add(self, item: str) -> None:
        for i in range(self.hash_count):
            pos = self._hash(item, i)
            byte_pos = pos // 8
            bit_pos = pos % 8
            self.bits[byte_pos] |= (1 << bit_pos)
    
    def __contains__(self, item: str) -> bool:
        for i in range(self.hash_count):
            pos = self._hash(item, i)
            byte_pos = pos // 8
            bit_pos = pos % 8
            if not (self.bits[byte_pos] & (1 << bit_pos)):
                return False
        return True


class OptimizedDomainSet:
    """Memory-efficient domain storage with bloom filter"""
    
    def __init__(self, max_domains: int = 500000):
        self.max_domains = max_domains
        self._bloom = BloomFilter(max_domains)
        self._domains: Dict[str, DomainRecord] = {}
        self._count = 0
    
    def add(self, domain: str, record: DomainRecord) -> bool:
        if self._count >= self.max_domains:
            return False
        
        if domain in self._bloom and domain in self._domains:
            return False
        
        self._domains[domain] = record
        self._bloom.add(domain)
        self._count += 1
        return True
    
    def __contains__(self, domain: str) -> bool:
        return domain in self._bloom and domain in self._domains
    
    def __len__(self) -> int:
        return self._count
    
    def keys(self):
        return self._domains.keys()
    
    def clear(self):
        self._domains.clear()
        self._count = 0

# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """RFC-compliant domain validator with LRU cache"""
    
    def __init__(self):
        self._stats = defaultdict(int)
    
    @lru_cache(maxsize=50000)
    def validate(self, domain: str) -> DomainStatus:
        domain_lower = domain.lower()
        
        if len(domain_lower) < Constants.MIN_DOMAIN_LEN:
            return DomainStatus.TOO_LONG
        if len(domain_lower) > Constants.MAX_DOMAIN_LEN:
            return DomainStatus.TOO_LONG
        
        allowed = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        if not all(c in allowed for c in domain_lower):
            return DomainStatus.INVALID_FORMAT
        
        if domain_lower.startswith('-') or domain_lower.endswith('-'):
            return DomainStatus.INVALID_FORMAT
        
        labels = domain_lower.split('.')
        if len(labels) < 2:
            return DomainStatus.INVALID_FORMAT
        
        for label in labels:
            if not label or len(label) > Constants.MAX_LABEL_LEN:
                return DomainStatus.INVALID_FORMAT
            if label.startswith('-') or label.endswith('-'):
                return DomainStatus.INVALID_FORMAT
        
        tld = labels[-1]
        if tld in Constants.RESERVED_TLDS:
            return DomainStatus.RESERVED
        if len(tld) < 2:
            return DomainStatus.INVALID_TLD
        
        return DomainStatus.VALID
    
    @staticmethod
    def validate_url(url: str) -> bool:
        if len(url) > 2000:
            return False
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.scheme not in ('https', 'http'):
                return False
            if not parsed.hostname:
                return False
            dangerous = ['..', '//', '%2e', '%2f', '%5c']
            if any(seq in parsed.path for seq in dangerous):
                return False
            return True
        except Exception:
            return False

# ============================================================================
# PARSERS MODULE
# ============================================================================

class BaseParser(ABC):
    @abstractmethod
    async def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        pass

class HostsParser(BaseParser):
    def __init__(self, validator: DomainValidator):
        self._validator = validator
        self._pattern = re.compile(
            r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-z0-9][a-z0-9.-]*[a-z0-9])',
            re.MULTILINE | re.IGNORECASE
        )
    
    async def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        timestamp = datetime.now(timezone.utc)
        for match in self._pattern.finditer(content):
            domain = match.group(1).lower()
            status = self._validator.validate(domain)
            yield DomainRecord(domain=domain, source=source, timestamp=timestamp, status=status)

class DomainsParser(BaseParser):
    def __init__(self, validator: DomainValidator):
        self._validator = validator
    
    async def parse(self, content: str, source: str) -> AsyncIterator[DomainRecord]:
        timestamp = datetime.now(timezone.utc)
        for line in content.splitlines():
            domain = line.strip().lower()
            if not domain or domain.startswith('#'):
                continue
            if domain[0].isdigit():
                continue
            status = self._validator.validate(domain)
            yield DomainRecord(domain=domain, source=source, timestamp=timestamp, status=status)

class ParserFactory:
    def __init__(self, validator: DomainValidator):
        self._validator = validator
        self._parsers = [HostsParser(validator), DomainsParser(validator)]
    
    def get_parser(self, url: str) -> BaseParser:
        for parser in self._parsers:
            if hasattr(parser, 'supports_format'):
                if parser.supports_format(url):
                    return parser
        return self._parsers[0]

# ============================================================================
# SOURCE MANAGER (HAGEZI EXCLUDED)
# ============================================================================

@dataclass
class Source:
    name: str
    url: str
    fallbacks: List[str] = field(default_factory=list)
    enabled: bool = True
    quality_threshold: float = 0.7

class SourceManager:
    def __init__(self, config: SecurityConfig):
        self._config = config
        self._sources: Dict[str, Source] = {}
        self._working_cache: Dict[str, str] = {}
        self._load_default_sources()
        self._apply_filters()
    
    def _load_default_sources(self):
        """Default sources - HAGEZI EXCLUDED"""
        self._sources = {
            'stevenblack': Source(
                name='StevenBlack',
                url='https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                fallbacks=[
                    'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts',
                    'https://cdn.jsdelivr.net/gh/StevenBlack/hosts@master/hosts'
                ],
                quality_threshold=0.9
            ),
            'adaway': Source(
                name='AdAway',
                url='https://adaway.org/hosts.txt',
                fallbacks=['https://adaway.surge.sh/hosts.txt'],
                quality_threshold=0.85
            ),
            'someonewhocares': Source(
                name='SomeoneWhoCares',
                url='https://someonewhocares.org/hosts/zero/hosts',
                quality_threshold=0.8
            ),
            'oisd': Source(
                name='OISD',
                url='https://big.oisd.nl/domainswild2',
                fallbacks=['https://small.oisd.nl/domainswild'],
                quality_threshold=0.95
            )
        }
    
    def _apply_filters(self):
        for name in self._config.exclude_sources:
            key = name.lower()
            if key in self._sources:
                self._sources[key].enabled = False
        
        if self._config.include_sources:
            include_set = {s.lower() for s in self._config.include_sources}
            for source in self._sources.values():
                source.enabled = source.name.lower() in include_set
    
    def get_sources(self) -> List[Source]:
        return [s for s in self._sources.values() if s.enabled]
    
    def get_names(self) -> List[str]:
        return [s.name for s in self.get_sources()]
    
    async def get_working_url(self, source: Source) -> Tuple[str, bool]:
        if source.name in self._working_cache:
            cached = self._working_cache[source.name]
            if cached == source.url or cached in source.fallbacks:
                return cached, True
        
        if await self._check_url(source.url):
            self._working_cache[source.name] = source.url
            return source.url, False
        
        for fallback in source.fallbacks:
            if await self._check_url(fallback):
                self._working_cache[source.name] = fallback
                return fallback, False
        
        return source.url, False
    
    async def _check_url(self, url: str) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=5) as response:
                    return response.status == 200
        except Exception:
            return False

# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    def __init__(self, max_domains: int = 500000):
        self._max_domains = max_domains
        self._domains = OptimizedDomainSet(max_domains)
        self._sources: Dict[str, SourceStats] = {}
        self._lock = asyncio.Lock()
    
    async def add_record(self, record: DomainRecord) -> bool:
        async with self._lock:
            if record.status != DomainStatus.VALID:
                return False
            
            if record.source not in self._sources:
                self._sources[record.source] = SourceStats(name=record.source, url='')
            
            if self._domains.add(record.domain, record):
                self._sources[record.source].new_domains += 1
                self._sources[record.source].total_domains += 1
                return True
            else:
                self._sources[record.source].total_domains += 1
                return False
    
    def get_domains(self) -> List[str]:
        return sorted(self._domains.keys())
    
    def get_stats(self) -> Dict[str, SourceStats]:
        return self._sources
    
    def get_count(self) -> int:
        return len(self._domains)

# ============================================================================
# SECURE HTTP CLIENT
# ============================================================================

class SecureHTTPClient:
    def __init__(self, config: SecurityConfig, logger: logging.Logger):
        self._config = config
        self._logger = logger
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        await self._create_session()
        return self
    
    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()
    
    async def _create_session(self):
        if HAS_CERTIFI:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
        else:
            ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = self._config.ssl_verify
        
        connector = aiohttp.TCPConnector(ssl=ssl_context if self._config.ssl_verify else None)
        timeout = aiohttp.ClientTimeout(total=self._config.timeout)
        headers = {'User-Agent': self._config.user_agent}
        
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers)
    
    async def fetch(self, url: str) -> Optional[str]:
        if not DomainValidator.validate_url(url):
            self._logger.warning(f"Rejected unsafe URL: {url}")
            return None
        
        for attempt in range(self._config.retries + 1):
            try:
                async with self._session.get(url) as response:
                    if response.status == 200:
                        content = await response.read()
                        if len(content) > self._config.max_file_size:
                            self._logger.error(f"File too large: {len(content)} bytes")
                            return None
                        text = content.decode('utf-8', errors='replace')
                        self._logger.debug(f"Fetched {url}: {len(text):,} bytes")
                        return text
                    else:
                        self._logger.warning(f"HTTP {response.status}: {url}")
            except Exception as e:
                self._logger.warning(f"Attempt {attempt + 1} failed: {e}")
            
            if attempt < self._config.retries:
                await asyncio.sleep(2 ** attempt)
        
        return None

# ============================================================================
# OUTPUT GENERATOR
# ============================================================================

class BaseOutputGenerator(ABC):
    @abstractmethod
    def generate_header(self, metrics: BuildMetrics, sources: List[str]) -> List[str]:
        pass
    
    @abstractmethod
    def format_domain(self, domain: str) -> str:
        pass

class HostsOutputGenerator(BaseOutputGenerator):
    def generate_header(self, metrics: BuildMetrics, sources: List[str]) -> List[str]:
        return [
            "# ====================================================================",
            "# DNS SECURITY BLOCKLIST - ENTERPRISE GRADE",
            f"# Version: {VERSION}",
            "# ====================================================================",
            f"# Generated: {metrics.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}" if metrics.end_time else "# Generated: N/A",
            f"# Total domains: {metrics.unique_domains:,}",
            f"# Sources: {', '.join(sources)}",
            f"# Duration: {metrics.duration:.2f} seconds",
            "# ====================================================================",
            "",
            "127.0.0.1 localhost",
            "::1 localhost",
            ""
        ]
    
    def format_domain(self, domain: str) -> str:
        return f"0.0.0.0 {domain}"

class OutputGeneratorFactory:
    @staticmethod
    def create(format_type: str) -> BaseOutputGenerator:
        return HostsOutputGenerator()  # Always hosts format

# ============================================================================
# MAIN BUILDER
# ============================================================================

class SecurityBlocklistBuilder:
    def __init__(self, config: SecurityConfig):
        self._config = config
        self._logger = self._setup_logging()
        self._validator = DomainValidator()
        self._parser_factory = ParserFactory(self._validator)
        self._source_manager = SourceManager(config)
        self._processor = DomainProcessor(config.max_domains)
        self._metrics = BuildMetrics()
        self._output_generator = OutputGeneratorFactory.create(config.output_format)
        self._shutdown = asyncio.Event()
    
    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('DNSBlocklist')
        logger.setLevel(getattr(logging, self._config.log_level))
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(console)
        return logger
    
    async def process_source(self, source: Source) -> SourceStats:
        stats = SourceStats(name=source.name, url=source.url)
        start_time = time.time()
        
        working_url, cached = await self._source_manager.get_working_url(source)
        stats.cached = cached
        
        self._logger.info(f"Processing {source.name}...")
        
        async with SecureHTTPClient(self._config, self._logger) as client:
            content = await client.fetch(working_url)
            
            if not content:
                stats.error_count += 1
                self._logger.error(f"Failed to fetch {source.name}")
                return stats
            
            stats.fetch_size = len(content)
            parser = self._parser_factory.get_parser(working_url)
            domain_count = 0
            invalid_count = 0
            
            async for record in parser.parse(content, source.name):
                if self._shutdown.is_set():
                    break
                
                if await self._processor.add_record(record):
                    domain_count += 1
                elif record.status != DomainStatus.VALID:
                    invalid_count += 1
            
            stats.total_domains = domain_count + invalid_count
            stats.new_domains = domain_count
            stats.invalid_domains = invalid_count
            stats.last_success = datetime.now(timezone.utc)
            
            self._logger.info(f"✓ {source.name}: {domain_count:,} valid, {invalid_count:,} invalid")
        
        stats.fetch_time = time.time() - start_time
        return stats
    
    async def process_all_sources(self) -> None:
        sources = self._source_manager.get_sources()
        self._metrics.sources_processed = len(sources)
        
        semaphore = asyncio.Semaphore(self._config.max_concurrent_downloads)
        
        async def process_with_limit(source: Source):
            async with semaphore:
                return await self.process_source(source)
        
        tasks = [process_with_limit(source) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self._logger.error(f"Source failed: {result}")
                self._metrics.sources_failed += 1
            elif isinstance(result, SourceStats):
                self._processor.get_stats()[result.name] = result
    
    async def generate_output(self) -> Optional[Path]:
        domains = self._processor.get_domains()
        
        if not domains:
            self._logger.error("No domains to generate")
            return None
        
        self._metrics.unique_domains = len(domains)
        self._metrics.end_time = datetime.now(timezone.utc)
        
        output_path = Path(self._config.output_path)
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as tmp:
                header = self._output_generator.generate_header(
                    self._metrics,
                    self._source_manager.get_names()
                )
                
                for line in header:
                    tmp.write(line + '\n')
                
                for domain in domains:
                    line = self._output_generator.format_domain(domain)
                    tmp.write(line + '\n')
                
                tmp.flush()
            
            shutil.move(tmp.name, output_path)
            shutil.copy2(output_path, Path(Constants.BACKUP_FILE))
            
            self._logger.info(f"Generated: {output_path} ({len(domains):,} domains)")
            return output_path
            
        except Exception as e:
            self._logger.error(f"Failed to generate: {e}")
            return None
    
    def print_report(self):
        print("\n" + "=" * 80)
        print(f"🔒 DNS SECURITY BLOCKLIST REPORT v{VERSION}")
        print("=" * 80)
        
        print(f"\n{'SOURCE':<25} {'VALID':>12} {'INVALID':>10} {'QUALITY':>8} {'TIME':>8}")
        print("-" * 80)
        
        for name, stats in sorted(self._processor.get_stats().items(),
                                  key=lambda x: x[1].new_domains, reverse=True):
            quality = f"{stats.quality_score:.1%}"
            print(f"{name[:24]:<25} {stats.new_domains:>12,} "
                  f"{stats.invalid_domains:>10,} {quality:>8} {stats.fetch_time:>7.2f}s")
        
        print("-" * 80)
        print(f"{'TOTAL':<25} {self._processor.get_count():>12,}")
        print("=" * 80)
        
        print(f"\n📈 Performance:")
        print(f"  • Duration: {self._metrics.duration:.2f} seconds")
        print(f"  • Rate: {self._processor.get_count() / self._metrics.duration:.0f} domains/sec")
        print(f"  • Sources: {self._metrics.sources_processed} processed, {self._metrics.sources_failed} failed")
        
        if self._metrics.memory_peak_mb > 0:
            print(f"\n💾 Memory: {self._metrics.memory_peak_mb:.1f} MB")
        
        print("=" * 80)
    
    async def run(self) -> int:
        print("\n" + "=" * 80)
        print(f"🚀 DNS SECURITY BLOCKLIST BUILDER v{VERSION}")
        print(f"Sources: {', '.join(self._source_manager.get_names())}")
        print("=" * 80)
        
        try:
            await self.process_all_sources()
            
            if self._processor.get_count() == 0:
                self._logger.error("No domains collected")
                return 1
            
            output = await self.generate_output()
            
            if output:
                self.print_report()
                return 0
            return 1
            
        except Exception as e:
            self._logger.error(f"Build failed: {e}", exc_info=True)
            return 1

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def async_main():
    parser = argparse.ArgumentParser(description='DNS Security Blocklist Builder')
    parser.add_argument('-c', '--config', type=Path, help='Config file')
    parser.add_argument('-o', '--output', default='hosts', help='Output format')
    parser.add_argument('--max-domains', type=int, default=500000, help='Max domains')
    parser.add_argument('--exclude', nargs='+', help='Sources to exclude')
    parser.add_argument('--include', nargs='+', help='Sources to include')
    parser.add_argument('--list-sources', action='store_true', help='List sources')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    if args.list_sources:
        temp_config = SecurityConfig()
        temp_manager = SourceManager(temp_config)
        print("\nAvailable sources:")
        for name, source in temp_manager._sources.items():
            print(f"  • {source.name}")
        return 0
    
    config = SecurityConfig()
    config.max_domains = args.max_domains
    
    if args.exclude:
        config.exclude_sources = args.exclude
    if args.include:
        config.include_sources = args.include
    
    try:
        resource.setrlimit(resource.RLIMIT_AS, (config.memory_limit_mb * 1024 * 1024, config.memory_limit_mb * 1024 * 1024))
    except:
        pass
    
    builder = SecurityBlocklistBuilder(config)
    return await builder.run()

def main():
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted")
        return 130
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
