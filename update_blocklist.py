#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - Enterprise Grade (v6.0.1)
Fixed: Missing include_sources/exclude_sources attributes
"""

import sys
import os
import asyncio
import hashlib
import json
import logging
import re
import signal
import time
import tempfile
import shutil
import resource
import gc
import argparse
import ssl
import gzip
import zlib
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from functools import lru_cache, wraps
from pathlib import Path
from typing import (
    Set, Dict, List, Optional, Tuple, Any, Union, 
    AsyncIterator, Callable, TypeVar, cast, NamedTuple
)
from collections import defaultdict
import asyncio
import aiohttp
import aiofiles
import yaml

# ============================================================================
# DEPENDENCY MANAGEMENT
# ============================================================================

class DependencyManager:
    """Manages optional dependencies with graceful fallbacks"""
    
    HAS_CRYPTO: bool = False
    HAS_PSUTIL: bool = False
    HAS_PROMETHEUS: bool = False
    HAS_CERTIFI: bool = False
    
    @classmethod
    def load_all(cls) -> None:
        """Load all optional dependencies safely"""
        try:
            import cryptography  # noqa
            cls.HAS_CRYPTO = True
        except ImportError:
            pass
        
        try:
            import psutil  # noqa
            cls.HAS_PSUTIL = True
        except ImportError:
            pass
        
        try:
            import prometheus_client  # noqa
            cls.HAS_PROMETHEUS = True
        except ImportError:
            pass
        
        try:
            import certifi  # noqa
            cls.HAS_CERTIFI = True
        except ImportError:
            pass

# Load dependencies
DependencyManager.load_all()

# ============================================================================
# CONSTANTS
# ============================================================================

VERSION = "6.0.1"
VERSION_INFO = {
    'major': 6,
    'minor': 0,
    'patch': 1,
    'build': datetime.now().strftime('%Y%m%d')
}

class Constants:
    """Centralized constants"""
    
    # Domain validation
    MAX_DOMAIN_LEN: int = 253
    MAX_LABEL_LEN: int = 63
    MIN_DOMAIN_LEN: int = 3
    
    # File operations
    TEMP_SUFFIX: str = '.tmp'
    BACKUP_SUFFIX: str = '.backup'
    
    # Resource limits
    MIN_DISK_SPACE_MB: int = 100
    MIN_MEMORY_MB: int = 50
    
    # Performance
    DEFAULT_BATCH_SIZE: int = 10000
    MAX_CONCURRENT_DOWNLOADS: int = 10
    DNS_CACHE_SIZE: int = 10000
    
    # Network
    DEFAULT_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    RETRY_BACKOFF: float = 1.5
    
    # Bloom filter
    BLOOM_FILTER_FP_RATE: float = 0.01
    
    # Reserved TLDs
    RESERVED_TLDS: Set[str] = frozenset({
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p'
    })
    
    USER_AGENT: str = (
        'Mozilla/5.0 (X11; Linux x86_64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        f'DNSBlocklist/{VERSION}'
    )

class SourceType(Enum):
    """Type of blocklist source"""
    HOSTS = auto()
    DOMAINS = auto()
    ADBLOCK = auto()
    DNSMASQ = auto()
    URLHAUS = auto()
    CUSTOM = auto()

class DomainStatus(Enum):
    """Domain validation status"""
    VALID = auto()
    INVALID_FORMAT = auto()
    INVALID_TLD = auto()
    TOO_LONG = auto()
    RESERVED = auto()
    DUPLICATE = auto()
    SUSPICIOUS = auto()

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass(frozen=True)
class DomainRecord:
    """Immutable domain record"""
    domain: str
    source: str
    timestamp: datetime
    status: DomainStatus = DomainStatus.VALID
    hash: str = field(init=False)
    
    def __post_init__(self) -> None:
        object.__setattr__(self, 'hash', hashlib.sha256(
            self.domain.lower().encode()
        ).hexdigest()[:16])
    
    def __hash__(self) -> int:
        return hash(self.domain.lower())
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DomainRecord):
            return False
        return self.domain.lower() == other.domain.lower()
    
    def to_hosts_entry(self) -> str:
        return f"0.0.0.0 {self.domain}"
    
    def to_dnsmasq_entry(self) -> str:
        return f"address=/{self.domain}/0.0.0.0"
    
    def to_unbound_entry(self) -> str:
        return f"local-zone: \"{self.domain}\" always_nxdomain"

@dataclass
class SourceStats:
    """Statistics for a single source"""
    name: str
    total_domains: int = 0
    valid_domains: int = 0
    invalid_domains: int = 0
    fetch_time: float = 0.0
    fetch_size: int = 0
    error: Optional[str] = None
    last_fetch: Optional[datetime] = None
    quality_score: float = 0.0

@dataclass
class BuildMetrics:
    """Build performance metrics"""
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    sources_processed: int = 0
    sources_failed: int = 0
    domains_collected: int = 0
    domains_validated: int = 0
    domains_duplicates: int = 0
    memory_peak_mb: float = 0.0
    cpu_percent: float = 0.0
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()
    
    @property
    def domains_per_second(self) -> float:
        if self.duration == 0:
            return 0.0
        return self.domains_validated / self.duration

@dataclass
class SecurityConfig:
    """Comprehensive security configuration"""
    
    # Resource limits
    max_domains: int = 500_000
    max_file_size_mb: int = 100
    memory_limit_mb: int = 1024
    cpu_time_limit: int = 300
    
    # Network
    timeout_seconds: int = 30
    max_retries: int = 3
    ssl_verify: bool = True
    allowed_domains: Set[str] = field(default_factory=set)
    blocked_domains: Set[str] = field(default_factory=set)
    
    # Source filtering - FIXED: added missing fields
    include_sources: List[str] = field(default_factory=list)
    exclude_sources: List[str] = field(default_factory=list)
    
    # Validation
    min_domain_length: int = 3
    max_domain_length: int = 253
    require_public_suffix: bool = True
    
    # Source management
    trusted_sources: Set[str] = field(default_factory=lambda: {
        'raw.githubusercontent.com', 'adaway.org', 'github.com',
        'someonewhocares.org', 'oisd.nl', 'urlhaus.abuse.ch',
        'threatfox.abuse.ch', 'cert.pl'
    })
    
    # Output
    output_path: Path = Path('dynamic-blocklist.txt')
    output_format: str = 'hosts'
    output_compression: bool = False
    
    # Logging
    log_level: str = 'INFO'
    log_file: Optional[Path] = None
    log_json: bool = False
    
    # Monitoring
    metrics_enabled: bool = False
    metrics_port: int = 9090
    health_check_enabled: bool = True
    health_check_port: int = 8080
    
    # Notifications
    webhook_url: Optional[str] = None
    notify_on_success: bool = True
    notify_on_failure: bool = True
    
    def validate(self) -> 'SecurityConfig':
        """Validate configuration"""
        if self.max_domains < 1000:
            raise ValueError("max_domains must be at least 1000")
        
        if self.max_file_size_mb < 1:
            raise ValueError("max_file_size_mb must be at least 1")
        
        if self.timeout_seconds < 1:
            raise ValueError("timeout_seconds must be at least 1")
        
        # Ensure output directory exists
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        return self
    
    def should_include_source(self, source_name: str) -> bool:
        """Check if source should be included based on filters"""
        source_lower = source_name.lower()
        
        # If include list is specified, only include those
        if self.include_sources:
            return source_lower in [s.lower() for s in self.include_sources]
        
        # If exclude list is specified, exclude those
        if self.exclude_sources:
            return source_lower not in [s.lower() for s in self.exclude_sources]
        
        # Include all by default
        return True
    
    @classmethod
    def from_file(cls, path: Path) -> 'SecurityConfig':
        """Load configuration from YAML file"""
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        with open(path) as f:
            data = yaml.safe_load(f)
        
        # Filter only valid fields
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        
        return cls(**filtered)

# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

class DomainValidator:
    """High-performance domain validation"""
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._cache: Dict[str, DomainStatus] = {}
        self._tld_cache: Set[str] = set()
        self._load_public_suffixes()
    
    def _load_public_suffixes(self) -> None:
        """Load public suffix list"""
        common_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'uk', 'de', 'jp', 'cn', 'ru', 'fr', 'br', 'au',
            'ca', 'it', 'nl', 'pl', 'es', 'in', 'kr', 'za'
        }
        self._tld_cache.update(common_tlds)
    
    @lru_cache(maxsize=Constants.DNS_CACHE_SIZE)
    def _validate_syntax(self, domain: str) -> Optional[DomainStatus]:
        """Validate domain syntax"""
        domain_lower = domain.lower().strip()
        
        if len(domain_lower) < Constants.MIN_DOMAIN_LEN:
            return DomainStatus.INVALID_FORMAT
        
        if len(domain_lower) > Constants.MAX_DOMAIN_LEN:
            return DomainStatus.TOO_LONG
        
        if domain_lower.split('.')[-1] in Constants.RESERVED_TLDS:
            return DomainStatus.RESERVED
        
        labels = domain_lower.split('.')
        for label in labels:
            if len(label) > Constants.MAX_LABEL_LEN:
                return DomainStatus.INVALID_FORMAT
            if not label or label.startswith('-') or label.endswith('-'):
                return DomainStatus.INVALID_FORMAT
            if not re.match(r'^[a-z0-9\-]+$', label):
                return DomainStatus.INVALID_FORMAT
        
        suspicious = ['xn--', '--', '.-', '-.']
        if any(pattern in domain_lower for pattern in suspicious):
            return DomainStatus.SUSPICIOUS
        
        return DomainStatus.VALID
    
    def validate(self, domain: str, source: str) -> DomainRecord:
        """Validate domain and return record"""
        if domain in self._cache:
            status = self._cache[domain]
        else:
            status = self._validate_syntax(domain)
            if status == DomainStatus.VALID:
                self._cache[domain] = status
        
        return DomainRecord(
            domain=domain,
            source=source,
            timestamp=datetime.now(timezone.utc),
            status=status or DomainStatus.INVALID_FORMAT
        )
    
    @property
    def cache_size(self) -> int:
        return len(self._cache)

# ============================================================================
# SOURCE MANAGEMENT
# ============================================================================

class SourceDefinition(NamedTuple):
    """Definition of a blocklist source"""
    name: str
    url: str
    source_type: SourceType
    enabled: bool = True
    quality: float = 0.8
    max_size_mb: int = 50

class SourceParser:
    """Parse different blocklist formats"""
    
    @staticmethod
    def parse_hosts(content: str) -> Set[str]:
        """Parse hosts file format"""
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                if domain not in ('localhost', 'localhost.localdomain', 'local'):
                    domains.add(domain)
        
        return domains
    
    @staticmethod
    def parse_domains(content: str) -> Set[str]:
        """Parse simple domain list"""
        domains = set()
        for line in content.splitlines():
            line = line.strip().lower()
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            if '#' in line:
                line = line.split('#')[0].strip()
            
            if line and not line.startswith('0.0.0.0'):
                domains.add(line)
        
        return domains
    
    @staticmethod
    def parse_adblock(content: str) -> Set[str]:
        """Parse AdBlock format"""
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('['):
                continue
            
            if line.startswith('||') and '^' in line:
                domain = line[2:].split('^')[0]
                if '/' not in domain:
                    domains.add(domain)
        
        return domains
    
    @staticmethod
    def parse_urlhaus(content: str) -> Set[str]:
        """Parse URLhaus format"""
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ',' in line:
                parts = line.split(',')
                if parts and parts[0]:
                    domains.add(parts[0].lower())
        
        return domains

class SourceManager:
    """Manages all blocklist sources"""
    
    SOURCES: List[SourceDefinition] = [
        SourceDefinition(
            name='StevenBlack',
            url='https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            source_type=SourceType.HOSTS,
            quality=0.95,
            max_size_mb=10
        ),
        SourceDefinition(
            name='OISD',
            url='https://big.oisd.nl/domains',
            source_type=SourceType.DOMAINS,
            quality=0.98,
            max_size_mb=20
        ),
        SourceDefinition(
            name='AdAway',
            url='https://adaway.org/hosts.txt',
            source_type=SourceType.HOSTS,
            quality=0.90,
            max_size_mb=5
        ),
        SourceDefinition(
            name='URLhaus',
            url='https://urlhaus.abuse.ch/downloads/hostfile/',
            source_type=SourceType.HOSTS,
            quality=0.85,
            max_size_mb=10
        ),
        SourceDefinition(
            name='ThreatFox',
            url='https://threatfox.abuse.ch/downloads/hostfile/',
            source_type=SourceType.HOSTS,
            quality=0.85,
            max_size_mb=5
        ),
        SourceDefinition(
            name='CERT.PL',
            url='https://hole.cert.pl/domains/domains_hosts.txt',
            source_type=SourceType.HOSTS,
            quality=0.80,
            max_size_mb=5
        ),
        SourceDefinition(
            name='SomeoneWhoCares',
            url='https://someonewhocares.org/hosts/hosts',
            source_type=SourceType.HOSTS,
            quality=0.75,
            max_size_mb=10
        ),
    ]
    
    def __init__(self, config: SecurityConfig, session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = session
        self._fetcher = SourceFetcher(config, session)
        self._logger = logging.getLogger(__name__)
        self._stats: Dict[str, SourceStats] = {}
    
    def _get_sources(self) -> List[SourceDefinition]:
        """Get filtered sources based on config"""
        # FIXED: use should_include_source method
        return [s for s in self.SOURCES if self._config.should_include_source(s.name)]
    
    async def fetch_all(self) -> Dict[str, Set[str]]:
        """Fetch all sources concurrently"""
        sources = self._get_sources()
        self._logger.info(f"Fetching {len(sources)} sources...")
        
        semaphore = asyncio.Semaphore(Constants.MAX_CONCURRENT_DOWNLOADS)
        
        async def fetch_with_semaphore(source: SourceDefinition) -> Tuple[str, Optional[Set[str]], Optional[str]]:
            async with semaphore:
                fetched_source, content, error = await self._fetcher.fetch(source)
                
                if error or not content:
                    self._stats[source.name] = SourceStats(
                        name=source.name,
                        error=error or "No content",
                        last_fetch=datetime.now(timezone.utc)
                    )
                    return source.name, None, error
                
                domains = self._parse_content(content, source.source_type)
                
                self._stats[source.name] = SourceStats(
                    name=source.name,
                    total_domains=len(domains),
                    valid_domains=0,
                    fetch_time=0.0,
                    fetch_size=len(content),
                    last_fetch=datetime.now(timezone.utc),
                    quality_score=source.quality
                )
                
                return source.name, domains, None
        
        tasks = [fetch_with_semaphore(source) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domains_by_source: Dict[str, Set[str]] = {}
        
        for result in results:
            if isinstance(result, Exception):
                self._logger.error(f"Failed to fetch source: {result}")
                continue
            
            name, domains, error = result
            if error:
                self._logger.warning(f"Source {name} failed: {error}")
            elif domains:
                domains_by_source[name] = domains
                self._logger.info(f"Source {name}: {len(domains):,} domains")
        
        self._logger.info(f"Successfully fetched {len(domains_by_source)}/{len(sources)} sources")
        return domains_by_source
    
    def _parse_content(self, content: str, source_type: SourceType) -> Set[str]:
        """Parse content based on source type"""
        if source_type == SourceType.HOSTS:
            return SourceParser.parse_hosts(content)
        elif source_type == SourceType.DOMAINS:
            return SourceParser.parse_domains(content)
        elif source_type == SourceType.ADBLOCK:
            return SourceParser.parse_adblock(content)
        elif source_type == SourceType.URLHAUS:
            return SourceParser.parse_urlhaus(content)
        else:
            return SourceParser.parse_domains(content)
    
    def get_stats(self) -> Dict[str, SourceStats]:
        return self._stats.copy()

class SourceFetcher:
    """Asynchronous source fetcher"""
    
    def __init__(self, config: SecurityConfig, session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = session
        self._logger = logging.getLogger(__name__)
    
    async def fetch(self, source: SourceDefinition) -> Tuple[SourceDefinition, Optional[str], Optional[str]]:
        """Fetch source content with retries"""
        start_time = time.time()
        
        for attempt in range(self._config.max_retries):
            try:
                timeout = aiohttp.ClientTimeout(total=self._config.timeout_seconds)
                headers = {
                    'User-Agent': Constants.USER_AGENT,
                    'Accept': 'text/plain,text/html,*/*'
                }
                
                async with self._session.get(
                    source.url,
                    timeout=timeout,
                    headers=headers,
                    ssl=self._config.ssl_verify
                ) as response:
                    if response.status != 200:
                        error = f"HTTP {response.status}"
                        if attempt < self._config.max_retries - 1:
                            await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
                            continue
                        return source, None, error
                    
                    content_length = response.headers.get('Content-Length')
                    if content_length and int(content_length) > source.max_size_mb * 1024 * 1024:
                        return source, None, f"Size exceeds limit ({source.max_size_mb}MB)"
                    
                    content = await response.text()
                    
                    if len(content) < 10:
                        return source, None, "Content too short"
                    
                    fetch_time = time.time() - start_time
                    self._logger.debug(f"Fetched {source.name} in {fetch_time:.2f}s")
                    return source, content, None
                    
            except asyncio.TimeoutError:
                error = "Timeout"
                if attempt < self._config.max_retries - 1:
                    await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
                    continue
                return source, None, error
                
            except aiohttp.ClientError as e:
                error = f"Client error: {e}"
                if attempt < self._config.max_retries - 1:
                    await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
                    continue
                return source, None, error
                
            except Exception as e:
                self._logger.error(f"Unexpected error fetching {source.name}: {e}")
                return source, None, str(e)
        
        return source, None, "Max retries exceeded"

# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    """Process and deduplicate domains"""
    
    def __init__(self, config: SecurityConfig, validator: DomainValidator) -> None:
        self._config = config
        self._validator = validator
        self._domains: Dict[str, DomainRecord] = {}
        self._stats: Dict[str, SourceStats] = {}
        self._logger = logging.getLogger(__name__)
    
    async def process_sources(self, domains_by_source: Dict[str, Set[str]]) -> None:
        """Process all domains from sources"""
        total_before = sum(len(domains) for domains in domains_by_source.values())
        self._logger.info(f"Processing {total_before:,} raw domains from {len(domains_by_source)} sources")
        
        for source_name, domains in domains_by_source.items():
            stats = SourceStats(name=source_name)
            stats.total_domains = len(domains)
            
            for domain in domains:
                record = self._validator.validate(domain, source_name)
                
                if record.status == DomainStatus.VALID:
                    if record.domain not in self._domains:
                        self._domains[record.domain] = record
                        stats.valid_domains += 1
                    else:
                        stats.invalid_domains += 1
                else:
                    stats.invalid_domains += 1
            
            stats.quality_score = stats.valid_domains / max(stats.total_domains, 1)
            self._stats[source_name] = stats
            
            self._logger.debug(
                f"Source {source_name}: {stats.valid_domains:,}/{stats.total_domains:,} "
                f"valid ({stats.quality_score:.1%})"
            )
        
        self._logger.info(f"Final unique domains: {len(self._domains):,}")
        
        if len(self._domains) > self._config.max_domains:
            self._logger.warning(f"Truncating to {self._config.max_domains:,} domains")
            self._domains = dict(list(self._domains.items())[:self._config.max_domains])
    
    def get_domains(self) -> List[str]:
        return sorted(self._domains.keys())
    
    def get_count(self) -> int:
        return len(self._domains)
    
    def get_stats(self) -> Dict[str, SourceStats]:
        return self._stats.copy()

# ============================================================================
# OUTPUT GENERATOR
# ============================================================================

class OutputGenerator:
    """Generate output in various formats"""
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._logger = logging.getLogger(__name__)
    
    async def generate(self, domains: List[str]) -> Path:
        """Generate output file"""
        output_path = self._config.output_path
        tmp_path = output_path.with_suffix(f'{Constants.TEMP_SUFFIX}')
        
        try:
            async with aiofiles.open(tmp_path, 'w', encoding='utf-8') as f:
                await f.write("# DNS Security Blocklist\n")
                await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                await f.write(f"# Version: {VERSION}\n")
                await f.write(f"# Total domains: {len(domains):,}\n")
                await f.write("#\n\n")
                
                batch_size = Constants.DEFAULT_BATCH_SIZE
                for i in range(0, len(domains), batch_size):
                    batch = domains[i:i + batch_size]
                    for domain in batch:
                        if self._config.output_format == 'hosts':
                            await f.write(f"0.0.0.0 {domain}\n")
                        elif self._config.output_format == 'dnsmasq':
                            await f.write(f"address=/{domain}/0.0.0.0\n")
                        elif self._config.output_format == 'unbound':
                            await f.write(f"local-zone: \"{domain}\" always_nxdomain\n")
                        else:
                            await f.write(f"{domain}\n")
                    
                    await f.flush()
            
            if self._config.output_compression:
                compressed_path = output_path.with_suffix('.gz')
                with open(tmp_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb', compresslevel=6) as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                self._logger.info(f"Compressed output: {compressed_path}")
                os.unlink(tmp_path)
                return compressed_path
            
            shutil.move(tmp_path, output_path)
            
            backup_path = output_path.with_suffix(f'{Constants.BACKUP_SUFFIX}')
            shutil.copy2(output_path, backup_path)
            
            self._logger.info(f"Generated {output_path} ({len(domains):,} domains)")
            return output_path
            
        except Exception as e:
            self._logger.error(f"Failed to generate output: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise

# ============================================================================
# METRICS COLLECTOR
# ============================================================================

class MetricsCollector:
    """Collect and expose metrics"""
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._metrics = BuildMetrics()
        self._logger = logging.getLogger(__name__)
        
        if config.metrics_enabled and DependencyManager.HAS_PROMETHEUS:
            self._setup_prometheus()
    
    def _setup_prometheus(self) -> None:
        try:
            from prometheus_client import start_http_server, Counter, Histogram, Gauge
            
            self.domains_total = Counter('blocklist_domains_total', 'Total domains processed')
            self.build_duration = Histogram('blocklist_build_duration_seconds', 'Build duration')
            self.sources_total = Counter('blocklist_sources_total', 'Total sources processed')
            
            start_http_server(self._config.metrics_port)
            self._logger.info(f"Metrics server started on port {self._config.metrics_port}")
        except Exception as e:
            self._logger.warning(f"Failed to start Prometheus metrics: {e}")
    
    def start(self) -> None:
        self._metrics.start_time = datetime.now(timezone.utc)
        
        if DependencyManager.HAS_PSUTIL:
            import psutil
            self._process = psutil.Process()
    
    def update_memory(self) -> None:
        if DependencyManager.HAS_PSUTIL and hasattr(self, '_process'):
            memory_mb = self._process.memory_info().rss / 1024 / 1024
            self._metrics.memory_peak_mb = max(self._metrics.memory_peak_mb, memory_mb)
    
    def finish(self, domains: int, sources_processed: int, sources_failed: int) -> BuildMetrics:
        self._metrics.end_time = datetime.now(timezone.utc)
        self._metrics.domains_validated = domains
        self._metrics.sources_processed = sources_processed
        self._metrics.sources_failed = sources_failed
        
        if DependencyManager.HAS_PSUTIL and hasattr(self, '_process'):
            self._metrics.cpu_percent = self._process.cpu_percent()
        
        return self._metrics

# ============================================================================
# HEALTH CHECK SERVER
# ============================================================================

class HealthCheckServer:
    """Simple health check HTTP server"""
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._logger = logging.getLogger(__name__)
        self._server: Optional[asyncio.Server] = None
    
    async def start(self) -> None:
        if not self._config.health_check_enabled:
            return
        
        try:
            self._server = await asyncio.start_server(
                self._handle_request,
                '127.0.0.1',
                self._config.health_check_port
            )
            
            self._logger.info(f"Health check server started on port {self._config.health_check_port}")
            asyncio.create_task(self._server.serve_forever())
            
        except Exception as e:
            self._logger.warning(f"Failed to start health check server: {e}")
    
    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.read(1024)
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Connection: close\r\n\r\n"
                f'{{"status":"healthy","version":"{VERSION}"}}\r\n'
            )
            writer.write(response.encode())
            await writer.drain()
            
        except Exception as e:
            self._logger.debug(f"Health check error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._logger.debug("Health check server stopped")

# ============================================================================
# MAIN BUILDER
# ============================================================================

class SecurityBlocklistBuilder:
    """Main orchestrator"""
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config.validate()
        self._logger = self._setup_logging()
        self._shutdown = asyncio.Event()
        self._metrics = MetricsCollector(config)
        self._health_server = HealthCheckServer(config)
        
        self._validator: Optional[DomainValidator] = None
        self._source_manager: Optional[SourceManager] = None
        self._processor: Optional[DomainProcessor] = None
        self._output_generator: Optional[OutputGenerator] = None
        self._session: Optional[aiohttp.ClientSession] = None
    
    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('DNSBlocklist')
        logger.setLevel(getattr(logging, self._config.log_level))
        logger.handlers.clear()
        
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(console)
        
        if self._config.log_file:
            try:
                file_handler = logging.FileHandler(self._config.log_file)
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
                ))
                logger.addHandler(file_handler)
            except Exception as e:
                logger.warning(f"Cannot create log file: {e}")
        
        return logger
    
    def _setup_signal_handlers(self) -> None:
        def signal_handler(sig: int, frame: Any) -> None:
            self._logger.info(f"Received signal {sig}, shutting down...")
            self._shutdown.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def _initialize(self) -> None:
        connector = aiohttp.TCPConnector(
            limit=Constants.MAX_CONCURRENT_DOWNLOADS,
            ttl_dns_cache=300,
            ssl=self._config.ssl_verify
        )
        
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds)
        )
        
        self._validator = DomainValidator(self._config)
        self._source_manager = SourceManager(self._config, self._session)
        self._processor = DomainProcessor(self._config, self._validator)
        self._output_generator = OutputGenerator(self._config)
        
        await self._health_server.start()
    
    async def _cleanup(self) -> None:
        await self._health_server.stop()
        if self._session:
            await self._session.close()
        gc.collect()
    
    async def run(self) -> int:
        self._setup_signal_handlers()
        self._metrics.start()
        
        try:
            self._logger.info(f"DNS Security Blocklist Builder v{VERSION}")
            await self._initialize()
            
            if self._shutdown.is_set():
                self._logger.warning("Shutdown requested before start")
                return 130
            
            self._logger.info("Fetching blocklist sources...")
            domains_by_source = await self._source_manager.fetch_all()
            
            if not domains_by_source:
                self._logger.error("No sources fetched successfully")
                return 1
            
            self._logger.info("Processing domains...")
            await self._processor.process_sources(domains_by_source)
            
            if self._processor.get_count() == 0:
                self._logger.error("No valid domains collected")
                return 1
            
            self._logger.info("Generating output...")
            domains = self._processor.get_domains()
            output_path = await self._output_generator.generate(domains)
            
            sources_processed = len(self._source_manager.get_stats())
            sources_failed = sum(1 for s in self._source_manager.get_stats().values() if s.error)
            
            metrics = self._metrics.finish(
                domains=len(domains),
                sources_processed=sources_processed,
                sources_failed=sources_failed
            )
            
            self._print_report(metrics, self._processor.get_stats())
            
            self._logger.info(f"Build completed successfully: {output_path}")
            return 0
            
        except asyncio.CancelledError:
            self._logger.warning("Build cancelled")
            return 130
            
        except Exception as e:
            self._logger.error(f"Build failed: {e}", exc_info=True)
            return 1
            
        finally:
            await self._cleanup()
    
    def _print_report(self, metrics: BuildMetrics, source_stats: Dict[str, SourceStats]) -> None:
        sep = "=" * 80
        print(f"\n{sep}")
        print(f"🔒 DNS SECURITY BLOCKLIST REPORT v{VERSION}")
        print(sep)
        
        print(f"\n{'SOURCE':<25} {'VALID':<12} {'INVALID':<10} {'QUALITY':<8} {'TIME':<8}")
        print("-" * 80)
        
        for name, stats in sorted(source_stats.items(), key=lambda x: x[1].valid_domains, reverse=True):
            quality = f"{stats.quality_score:.1%}"
            print(f"{name[:24]:<25} {stats.valid_domains:>12,} {stats.invalid_domains:>10,} {quality:>8} {stats.fetch_time:>7.2f}s")
        
        print("-" * 80)
        print(f"{'TOTAL':<25} {metrics.domains_validated:>12,}")
        print(sep)
        
        print(f"\n📈 Performance:")
        print(f"  • Duration: {metrics.duration:.2f} seconds")
        print(f"  • Rate: {metrics.domains_per_second:.0f} domains/sec")
        print(f"  • Sources: {metrics.sources_processed} processed, {metrics.sources_failed} failed")
        
        if metrics.memory_peak_mb > 0:
            print(f"\n💾 Memory: {metrics.memory_peak_mb:.1f} MB")
        
        print(sep)

# ============================================================================
# CLI & MAIN
# ============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='DNS Security Blocklist Builder - Enterprise Grade',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Run with defaults
  %(prog)s --max-domains 1000000    # Increase domain limit
  %(prog)s --exclude StevenBlack    # Exclude specific source
  %(prog)s --list-sources           # Show available sources
        """
    )
    
    parser.add_argument('-c', '--config', type=Path, help='Configuration YAML file')
    parser.add_argument('-o', '--output', type=Path, help='Output file path')
    parser.add_argument('--format', choices=['hosts', 'dnsmasq', 'unbound', 'domains'], 
                       default='hosts', help='Output format')
    parser.add_argument('--max-domains', type=int, default=500000, help='Maximum domains')
    parser.add_argument('--exclude', nargs='+', help='Source names to exclude')
    parser.add_argument('--include', nargs='+', help='Source names to include')
    parser.add_argument('--list-sources', action='store_true', help='List available sources')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    return parser.parse_args()

async def async_main() -> int:
    args = parse_args()
    
    if args.list_sources:
        print("\n📋 Available blocklist sources:\n")
        for source in SourceManager.SOURCES:
            print(f"  • {source.name}")
            print(f"    URL: {source.url}")
            print(f"    Type: {source.source_type.name}")
            print(f"    Quality: {source.quality:.0%}")
            print()
        return 0
    
    config = SecurityConfig()
    
    if args.config:
        try:
            config = SecurityConfig.from_file(args.config)
        except Exception as e:
            print(f"❌ Failed to load config: {e}", file=sys.stderr)
            return 1
    
    if args.output:
        config.output_path = args.output
    
    if args.format:
        config.output_format = args.format
    
    if args.max_domains:
        config.max_domains = args.max_domains
    
    if args.exclude:
        config.exclude_sources = args.exclude
    
    if args.include:
        config.include_sources = args.include
    
    if args.verbose:
        config.log_level = 'DEBUG'
    
    builder = SecurityBlocklistBuilder(config)
    return await builder.run()

def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Fatal error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
