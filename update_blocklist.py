#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - ENTERPRISE SECURITY HARDENED (v14.0.1)
FIXED: Import error for ClassVar
"""

import argparse
import asyncio
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import ssl
import sys
import tempfile
import time
import warnings
from collections import defaultdict
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache
from pathlib import Path
from typing import (
    Any, AsyncIterator, Dict, Final, List, Optional, 
    Set, Tuple, Union, cast, ClassVar  # <-- FIXED: ClassVar imported
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientResponse, ClientTimeout
from aiohttp.client_exceptions import ClientError, ClientConnectorError

# ============================================================================
# SECURITY IMPORTS - Enterprise Grade
# ============================================================================

try:
    import defusedxml  # For safe XML parsing if needed
    import defusedxml.lxml
except ImportError:
    pass

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ============================================================================
# VERSION & METADATA
# ============================================================================

VERSION: Final[str] = "14.0.1"
__version__ = VERSION

# ============================================================================
# SECURITY CONSTANTS - Hardened
# ============================================================================

class SecurityConstants:
    """Hardened security constants - Enterprise grade"""
    
    # Domain validation with strict limits
    MAX_DOMAIN_LEN: Final[int] = 253
    MAX_LABEL_LEN: Final[int] = 63
    MIN_DOMAIN_LEN: Final[int] = 3
    MAX_DOMAIN_INPUT_LEN: Final[int] = 1024  # ReDoS protection
    
    # Path traversal protection
    ALLOWED_OUTPUT_DIRS: Final[Set[Path]] = {
        Path.cwd(),
        Path.cwd() / "output",
        Path.cwd() / "blocklists",
    }
    
    # Network security - Hardened
    MAX_CONCURRENT_DOWNLOADS: Final[int] = 5
    DEFAULT_TIMEOUT: Final[int] = 15
    MAX_RETRIES: Final[int] = 2
    RETRY_BACKOFF: Final[float] = 1.0
    MAX_FILE_SIZE_MB: Final[int] = 50
    MAX_REDIRECTS: Final[int] = 2
    CONNECTION_LIMIT_PER_HOST: Final[int] = 2
    RATE_LIMIT_REQUESTS: Final[int] = 5
    RATE_LIMIT_WINDOW: Final[int] = 1
    
    # DNS security - Anti-rebinding
    DNS_RESOLVE_TIMEOUT: Final[int] = 5
    DNS_REBINDING_CHECKS: Final[int] = 2
    DNS_REBINDING_DELAY: Final[float] = 0.5
    
    # Cache settings
    DNS_CACHE_SIZE: Final[int] = 10000
    DNS_CACHE_TTL: Final[int] = 300
    AI_CACHE_SIZE: Final[int] = 10000
    AI_CACHE_TTL: Final[int] = 3600
    
    # Security - IP ranges (blocked)
    BLOCKED_IP_RANGES: Final[Tuple[str, ...]] = (
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96',
        '100.64.0.0/10', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'
    )
    
    # Allowed domains - Whitelist
    ALLOWED_DOMAINS: Final[Set[str]] = {
        'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
        'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
        'hole.cert.pl', 'github.com', 'gitlab.com', 'bitbucket.org'
    }
    
    # Reserved TLDs
    RESERVED_TLDS: Final[Set[str]] = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p'
    }
    
    # Performance limits
    MAX_DOMAINS_DEFAULT: Final[int] = 1000000
    MEMORY_LIMIT_MB: Final[int] = 512
    GC_THRESHOLD: Final[int] = 10000
    
    # AI Detection
    AI_CONFIDENCE_THRESHOLD: Final[float] = 0.65
    
    @classmethod
    def validate(cls) -> None:
        """Validate constants"""
        assert cls.MAX_CONCURRENT_DOWNLOADS > 0
        assert cls.DEFAULT_TIMEOUT > 0
        assert 0 <= cls.AI_CONFIDENCE_THRESHOLD <= 1


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
# DATA MODELS
# ============================================================================

@dataclass(frozen=True, slots=True)
class DomainRecord:
    """Immutable domain record"""
    domain: str
    source: str
    status: DomainStatus
    ai_confidence: float = 0.0
    ai_reasons: Tuple[str, ...] = field(default_factory=tuple)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self) -> None:
        if not self.domain or not isinstance(self.domain, str):
            raise ValueError(f"Invalid domain: {self.domain}")
        if not 0 <= self.ai_confidence <= 1:
            raise ValueError(f"Invalid confidence: {self.ai_confidence}")
    
    def to_hosts_entry(self) -> str:
        safe_domain = self._sanitize_domain()
        
        if self.ai_confidence > SecurityConstants.AI_CONFIDENCE_THRESHOLD:
            safe_reasons = []
            for r in self.ai_reasons[:2]:
                clean = re.sub(r'[^\w\-]', '_', r)
                safe_reasons.append(clean)
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{','.join(safe_reasons)}]"
        
        return f"0.0.0.0 {safe_domain}"
    
    def _sanitize_domain(self) -> str:
        cleaned = re.sub(r'[\x00-\x1f\x7f]', '', self.domain)
        cleaned = re.sub(r'[\s\t]', '', cleaned)
        cleaned = cleaned.replace('#', '').replace('|', '').replace('&', '')
        return cleaned[:SecurityConstants.MAX_DOMAIN_LEN]


# ============================================================================
# SAFE CACHE
# ============================================================================

class SafeCache:
    """Thread-safe cache with TTL"""
    
    def __init__(self, maxsize: int, ttl_seconds: int) -> None:
        self.maxsize = maxsize
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._lock = asyncio.Lock()
        self._hits = 0
        self._misses = 0
    
    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            value, timestamp = self._cache[key]
            if time.monotonic() - timestamp > self.ttl:
                del self._cache[key]
                self._misses += 1
                return None
            
            self._hits += 1
            return value
    
    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            if len(self._cache) >= self.maxsize:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = (value, time.monotonic())
    
    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0


# ============================================================================
# SECURE PATH VALIDATOR
# ============================================================================

class SecurePathValidator:
    """Prevent path traversal attacks"""
    
    @staticmethod
    def validate_output_path(path: Path, working_dir: Optional[Path] = None) -> Path:
        if working_dir is None:
            working_dir = Path.cwd()
        
        try:
            resolved = path.resolve()
            working_resolved = working_dir.resolve()
        except (OSError, RuntimeError):
            raise ValueError(f"Invalid path: {path}")
        
        try:
            resolved.relative_to(working_resolved)
        except ValueError:
            allowed = False
            for allowed_dir in SecurityConstants.ALLOWED_OUTPUT_DIRS:
                try:
                    resolved.relative_to(allowed_dir.resolve())
                    allowed = True
                    break
                except (ValueError, OSError):
                    continue
            
            if not allowed:
                raise ValueError(
                    f"Path {path} escapes working directory. "
                    f"Only {SecurityConstants.ALLOWED_OUTPUT_DIRS} are allowed"
                )
        
        resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        return resolved


# ============================================================================
# SSRF PROTECTOR - With DNS rebinding protection
# ============================================================================

class SSRFProtector:
    """Hardened SSRF protection with DNS rebinding defense"""
    
    def __init__(self, session: aiohttp.ClientSession) -> None:
        self.session = session
        self._blocked_networks = [
            ipaddress.ip_network(net) for net in SecurityConstants.BLOCKED_IP_RANGES
        ]
        self._checked_urls: SafeCache = SafeCache(maxsize=10000, ttl_seconds=3600)
        self._dns_cache: SafeCache = SafeCache(
            maxsize=SecurityConstants.DNS_CACHE_SIZE,
            ttl_seconds=SecurityConstants.DNS_CACHE_TTL
        )
        self._rate_limiter = asyncio.Semaphore(SecurityConstants.RATE_LIMIT_REQUESTS)
    
    async def validate_url(self, url: str) -> None:
        normalized = self._normalize_url(url)
        
        cached = await self._checked_urls.get(normalized)
        if cached is not None:
            return
        
        async with self._rate_limiter:
            await self._validate_url_impl(normalized)
        
        await self._checked_urls.set(normalized, True)
    
    async def _validate_url_impl(self, url: str) -> None:
        parsed = urlparse(url)
        
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        if not parsed.hostname:
            raise ValueError(f"No hostname in URL: {url}")
        
        if parsed.hostname not in SecurityConstants.ALLOWED_DOMAINS:
            await self._validate_ip_with_rebinding_protection(parsed.hostname)
    
    async def _validate_ip_with_rebinding_protection(self, hostname: str) -> None:
        results = []
        
        for attempt in range(SecurityConstants.DNS_REBINDING_CHECKS):
            ips = await self._resolve_hostname(hostname)
            results.append(set(ips))
            
            if attempt < SecurityConstants.DNS_REBINDING_CHECKS - 1:
                await asyncio.sleep(SecurityConstants.DNS_REBINDING_DELAY)
        
        if len(results) > 1 and results[0] != results[-1]:
            raise ValueError(f"DNS rebinding detected for {hostname}")
        
        for ip_str in results[-1]:
            ip = ipaddress.ip_address(ip_str)
            for blocked_net in self._blocked_networks:
                if ip in blocked_net:
                    raise ValueError(f"IP {ip} is in blocked range {blocked_net}")
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        cached = await self._dns_cache.get(hostname)
        if cached is not None:
            return cast(List[str], cached)
        
        loop = asyncio.get_event_loop()
        try:
            ips = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, family=0, type=0, proto=0),
                timeout=SecurityConstants.DNS_RESOLVE_TIMEOUT
            )
            result = list(set(ip[4][0] for ip in ips))
            await self._dns_cache.set(hostname, result)
            return result
        except asyncio.TimeoutError:
            raise ValueError(f"DNS resolution timeout for {hostname}")
        except Exception as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
    
    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        normalized = parsed._replace(
            netloc=parsed.hostname or '',
            fragment='',
            query=''
        )
        return normalized.geturl()


# ============================================================================
# DOMAIN VALIDATOR - ReDoS safe
# ============================================================================

class DomainValidator:
    """ReDoS-safe domain validator"""
    
    DOMAIN_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$',
        re.IGNORECASE
    )
    
    def __init__(self) -> None:
        self._cache: SafeCache = SafeCache(
            maxsize=SecurityConstants.DNS_CACHE_SIZE,
            ttl_seconds=SecurityConstants.DNS_CACHE_TTL
        )
    
    async def is_valid(self, domain: str) -> bool:
        if len(domain) > SecurityConstants.MAX_DOMAIN_INPUT_LEN:
            return False
        
        domain_lower = domain.lower().strip()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        valid = self._validate_syntax(domain_lower)
        await self._cache.set(domain_lower, valid)
        
        return valid
    
    def _validate_syntax(self, domain: str) -> bool:
        if len(domain) < SecurityConstants.MIN_DOMAIN_LEN:
            return False
        if len(domain) > SecurityConstants.MAX_DOMAIN_LEN:
            return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        if parts[-1] in SecurityConstants.RESERVED_TLDS:
            return False
        
        for label in parts:
            if not label or len(label) > SecurityConstants.MAX_LABEL_LEN:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
            if not label.isascii():
                try:
                    label.encode('idna').decode('ascii')
                except (UnicodeError, ValueError):
                    return False
        
        try:
            return bool(self.DOMAIN_PATTERN.match(domain))
        except re.error:
            return False
    
    async def cleanup(self) -> None:
        await self._cache.clear()


# ============================================================================
# AI DETECTOR - Safe patterns
# ============================================================================

class AITrackerDetector:
    """Safe tracker detection"""
    
    TRACKER_PATTERNS: ClassVar[Tuple[Tuple[str, str, float], ...]] = (
        (r'analytics', 'analytics', 0.82),
        (r'google-analytics', 'google_analytics', 0.95),
        (r'googletagmanager', 'google_tag_manager', 0.92),
        (r'firebase', 'firebase_analytics', 0.92),
        (r'amplitude', 'amplitude', 0.90),
        (r'mixpanel', 'mixpanel', 0.90),
        (r'segment', 'segment', 0.90),
        (r'tracking', 'tracking', 0.80),
        (r'pixel', 'tracking_pixel', 0.85),
        (r'beacon', 'tracking_beacon', 0.85),
        (r'collector', 'data_collector', 0.80),
        (r'doubleclick', 'doubleclick', 0.95),
        (r'adservice', 'ad_service', 0.85),
        (r'criteo', 'criteo', 0.85),
        (r'facebook', 'facebook_pixel', 0.95),
        (r'twitter', 'twitter_tracker', 0.82),
        (r'sentry', 'error_tracking', 0.75),
        (r'hotjar', 'user_behavior', 0.85),
        (r'clarity', 'microsoft_analytics', 0.85),
        (r'appsflyer', 'appsflyer', 0.90),
    )
    
    def __init__(self, threshold: float = SecurityConstants.AI_CONFIDENCE_THRESHOLD) -> None:
        self.threshold = threshold
        self._cache: SafeCache = SafeCache(
            maxsize=SecurityConstants.AI_CACHE_SIZE,
            ttl_seconds=SecurityConstants.AI_CACHE_TTL
        )
        self._patterns = [(re.compile(p, re.IGNORECASE), r, c) 
                         for p, r, c in self.TRACKER_PATTERNS]
    
    async def analyze(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        if len(domain) > SecurityConstants.MAX_DOMAIN_INPUT_LEN:
            return (0.0, ())
        
        domain_lower = domain.lower()
        
        cached = await self._cache.get(domain_lower)
        if cached is not None:
            return cached
        
        confidence, reasons = self._analyze_patterns(domain_lower)
        
        result = (confidence, reasons)
        await self._cache.set(domain_lower, result)
        
        return result
    
    def _analyze_patterns(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        confidence = 0.0
        reasons = []
        
        for pattern, reason, base_conf in self._patterns:
            try:
                if pattern.search(domain):
                    if base_conf > confidence:
                        confidence = base_conf
                    if reason not in reasons:
                        reasons.append(reason)
            except re.error:
                continue
        
        confidence = min(1.0, confidence)
        return (confidence, tuple(reasons))
    
    async def cleanup(self) -> None:
        await self._cache.clear()


# ============================================================================
# SECURE TEMP FILE MANAGER
# ============================================================================

class SecureTempFile:
    """Secure temporary file creation"""
    
    @staticmethod
    async def create_temp_file(content: str, suffix: str = '.txt') -> str:
        fd = -1
        path = None
        
        try:
            fd, path = tempfile.mkstemp(suffix=suffix, prefix='dns_blocklist_', text=True)
            
            with os.fdopen(fd, 'w') as f:
                f.write(content)
                f.flush()
                os.fsync(fd)
            
            os.chmod(path, 0o600)
            return path
            
        except Exception as e:
            if fd >= 0:
                os.close(fd)
            if path and os.path.exists(path):
                os.unlink(path)
            raise RuntimeError(f"Failed to create secure temp file: {e}")
    
    @staticmethod
    async def secure_delete(path: str) -> None:
        try:
            if os.path.exists(path):
                with open(path, 'wb') as f:
                    f.write(b'\x00' * os.path.getsize(path))
                    f.flush()
                    os.fsync(f.fileno())
                os.unlink(path)
        except Exception:
            pass


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
    max_size_mb: int = SecurityConstants.MAX_FILE_SIZE_MB
    
    def __post_init__(self) -> None:
        if not self.name or not self.url:
            raise ValueError(f"Invalid source: {self.name}")
        parsed = urlparse(self.url)
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"Invalid scheme: {parsed.scheme}")


# ============================================================================
# BUILD STATS
# ============================================================================

@dataclass
class BuildStats:
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
    
    @property
    def duration(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time


# ============================================================================
# SOURCE PROCESSOR
# ============================================================================

class SourceProcessor:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        validator: DomainValidator,
        detector: Optional[AITrackerDetector],
        stats: BuildStats
    ) -> None:
        self.session = session
        self.validator = validator
        self.detector = detector
        self.stats = stats
        self.ssrf_protector = SSRFProtector(session)
        self.ai_results: Dict[str, Tuple[float, Tuple[str, ...]]] = {}
    
    async def process_source(self, source: SourceDefinition) -> Set[str]:
        if not source.enabled:
            return set()
        
        try:
            await self.ssrf_protector.validate_url(source.url)
            
            content = await self._download_safe(source)
            
            if content is None:
                self.stats.sources_unchanged += 1
                return set()
            
            domains = self._extract_domains_safe(content, source)
            valid_domains = await self._validate_domains(domains, source)
            
            if self.detector:
                await self._process_ai_detection(valid_domains)
            
            self.stats.sources_processed += 1
            return valid_domains
            
        except Exception as e:
            self.stats.sources_failed += 1
            error_msg = f"Failed to process {source.name}: {e}"
            self.stats.errors.append(error_msg)
            logging.error(error_msg)
            return set()
    
    async def _download_safe(self, source: SourceDefinition) -> Optional[str]:
        for attempt in range(SecurityConstants.MAX_RETRIES):
            try:
                timeout = ClientTimeout(total=SecurityConstants.DEFAULT_TIMEOUT)
                async with self.session.get(
                    source.url,
                    timeout=timeout,
                    max_redirects=SecurityConstants.MAX_REDIRECTS
                ) as response:
                    if response.status != 200:
                        raise ValueError(f"HTTP {response.status}")
                    
                    content_length = response.headers.get('Content-Length')
                    if content_length:
                        size_mb = int(content_length) / (1024 * 1024)
                        if size_mb > source.max_size_mb:
                            raise ValueError(f"File too large: {size_mb:.1f} MB")
                    
                    raw_content = await response.read()
                    if len(raw_content) > source.max_size_mb * 1024 * 1024:
                        raise ValueError(f"File too large: {len(raw_content)} bytes")
                    
                    return raw_content.decode('utf-8', errors='replace')
                    
            except (asyncio.TimeoutError, ClientError) as e:
                if attempt == SecurityConstants.MAX_RETRIES - 1:
                    raise
                await asyncio.sleep(SecurityConstants.RETRY_BACKOFF ** attempt)
        
        return None
    
    def _extract_domains_safe(self, content: str, source: SourceDefinition) -> Set[str]:
        domains = set()
        
        for line in content.splitlines():
            if len(domains) >= SecurityConstants.MAX_DOMAINS_DEFAULT:
                break
            
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            domain = self._parse_line_safe(line, source.source_type)
            if domain:
                domains.add(domain)
        
        self.stats.total_raw_domains += len(domains)
        return domains
    
    def _parse_line_safe(self, line: str, source_type: SourceType) -> Optional[str]:
        if source_type == SourceType.HOSTS:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                domain = parts[1].split('#')[0].strip()
                if domain and len(domain) <= SecurityConstants.MAX_DOMAIN_LEN:
                    return domain
        elif source_type == SourceType.DOMAINS:
            domain = line.split('#')[0].strip()
            if domain and len(domain) <= SecurityConstants.MAX_DOMAIN_LEN:
                return domain
        
        return None
    
    async def _validate_domains(self, domains: Set[str], source: SourceDefinition) -> Set[str]:
        valid_domains = set()
        
        for domain in domains:
            if len(valid_domains) >= SecurityConstants.MAX_DOMAINS_DEFAULT:
                break
            
            if await self.validator.is_valid(domain):
                valid_domains.add(domain)
            else:
                self.stats.invalid_domains += 1
        
        self.stats.valid_domains += len(valid_domains)
        return valid_domains
    
    async def _process_ai_detection(self, domains: Set[str]) -> None:
        if not self.detector:
            return
        
        for domain in domains:
            confidence, reasons = await self.detector.analyze(domain)
            if confidence >= SecurityConstants.AI_CONFIDENCE_THRESHOLD:
                self.stats.ai_detected += 1
                self.ai_results[domain] = (confidence, reasons)


# ============================================================================
# BLOCKLIST BUILDER
# ============================================================================

class BlocklistBuilder:
    def __init__(self, output_path: Path) -> None:
        self.output_path = SecurePathValidator.validate_output_path(output_path)
        self.stats = BuildStats()
        self.validator = DomainValidator()
        self.detector = AITrackerDetector()
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stderr)]
        )
    
    async def build(self, sources: List[SourceDefinition]) -> bool:
        logging.info(f"Starting DNS Blocklist Builder v{VERSION}")
        
        try:
            async with self._create_session() as session:
                all_domains = await self._process_sources(session, sources)
                await self._write_blocklist(all_domains)
                
                self.stats.end_time = time.time()
                self._print_summary()
                
                return True
                
        except Exception as e:
            logging.critical(f"Build failed: {e}", exc_info=True)
            return False
        finally:
            await self.cleanup()
    
    @asynccontextmanager
    async def _create_session(self) -> AsyncIterator[aiohttp.ClientSession]:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        connector = aiohttp.TCPConnector(
            limit=SecurityConstants.MAX_CONCURRENT_DOWNLOADS,
            limit_per_host=SecurityConstants.CONNECTION_LIMIT_PER_HOST,
            ttl_dns_cache=300,
            ssl=ssl_context,
            enable_cleanup_closed=True
        )
        
        timeout = ClientTimeout(total=SecurityConstants.DEFAULT_TIMEOUT)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': f'DNS-Blocklist-Builder/{VERSION}'}
        ) as session:
            yield session
    
    async def _process_sources(
        self,
        session: aiohttp.ClientSession,
        sources: List[SourceDefinition]
    ) -> Set[str]:
        processor = SourceProcessor(session, self.validator, self.detector, self.stats)
        
        tasks = [processor.process_source(source) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_domains = set()
        
        for i, result in enumerate(results):
            if isinstance(result, set):
                all_domains.update(result)
            elif isinstance(result, Exception):
                logging.error(f"Source {sources[i].name} failed: {result}")
        
        self.stats.duplicates_removed = self.stats.valid_domains - len(all_domains)
        return all_domains
    
    async def _write_blocklist(self, domains: Set[str]) -> None:
        sorted_domains = sorted(domains)
        
        header = f"# DNS Security Blocklist v{VERSION}\n"
        header += f"# Generated: {datetime.now(timezone.utc).isoformat()}\n"
        header += f"# Total domains: {len(sorted_domains)}\n\n"
        
        content = header
        for domain in sorted_domains:
            record = DomainRecord(
                domain=domain,
                source="builder",
                status=DomainStatus.BLOCKED
            )
            content += record.to_hosts_entry() + "\n"
        
        temp_path = None
        try:
            temp_path = await SecureTempFile.create_temp_file(content, suffix='.txt')
            os.rename(temp_path, self.output_path)
            logging.info(f"Blocklist written to {self.output_path}")
        finally:
            if temp_path and os.path.exists(temp_path):
                await SecureTempFile.secure_delete(temp_path)
    
    def _print_summary(self) -> None:
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
        print(f"AI Detected: {self.stats.ai_detected:,}")
        print(f"Output: {self.output_path}")
        
        if self.stats.errors:
            print(f"\n⚠️  Errors ({len(self.stats.errors)}):")
            for error in self.stats.errors[:5]:
                print(f"  - {error[:100]}")
        
        print("=" * 70)
    
    async def cleanup(self) -> None:
        await self.validator.cleanup()
        await self.detector.cleanup()


# ============================================================================
# SOURCE MANAGER
# ============================================================================

class SourceManager:
    @staticmethod
    def get_default_sources() -> List[SourceDefinition]:
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
# MAIN
# ============================================================================

async def main_async() -> int:
    parser = argparse.ArgumentParser(
        description=f"DNS Security Blocklist Builder v{VERSION} - Enterprise Hardened"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("./blocklist.txt"),
        help="Output file path"
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=SecurityConstants.MAX_DOMAINS_DEFAULT,
        help=f"Maximum domains to process"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=SecurityConstants.DEFAULT_TIMEOUT,
        help=f"Download timeout in seconds"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    
    args = parser.parse_args()
    
    SecurityConstants.validate()
    
    try:
        output_path = SecurePathValidator.validate_output_path(args.output)
    except ValueError as e:
        logging.error(f"Invalid output path: {e}")
        return 1
    
    builder = BlocklistBuilder(output_path)
    
    try:
        sources = SourceManager.get_default_sources()
        success = await builder.build(sources)
        return 0 if success else 1
        
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        return 130
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=args.verbose)
        return 1
    finally:
        await builder.cleanup()


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
