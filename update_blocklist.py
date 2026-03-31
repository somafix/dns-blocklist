#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION EDITION (v17.0.1)
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
import socket  # Добавлено: необходим для резолвинга DNS
from collections import deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, AsyncIterator, Callable, Deque, Dict, Final, List, Optional, 
    Set, Tuple, TypeVar, Union, cast, AsyncGenerator, Awaitable, Generic # Добавлено: Generic
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientTimeout, ClientError
from aiohttp.client_exceptions import ServerTimeoutError, ClientResponseError
from pydantic import BaseModel, Field, ValidationError, HttpUrl, conint, confloat, field_validator, ConfigDict
from pydantic_settings import BaseSettings
import tenacity

# Определение типа для Generic
T = TypeVar('T')

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
# CONFIGURATION MODELS (Pydantic V2)
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
        }
    )
    
    blocked_ip_ranges: List[str] = Field(
        default=[
            '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
            '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96',
            '100.64.0.0/10', '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'
        ]
    )
    
    max_redirects: int = Field(3, ge=0, le=10)
    user_agent: str = Field("DNS-Blocklist-Builder/17.0.1")
    
    @field_validator('blocked_ip_ranges')
    @classmethod
    def validate_ip_ranges(cls, v: List[str]) -> List[str]:
        for net in v:
            try:
                ipaddress.ip_network(net, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid IP network: {net}") from e
        return v


class PerformanceConfig(BaseModel):
    """Performance tuning configuration."""
    
    max_concurrent_downloads: int = Field(10, ge=1, le=50)
    connection_limit_per_host: int = Field(5, ge=1, le=20)
    http_timeout: int = Field(30, ge=1, le=300)
    dns_timeout: int = Field(10, ge=1, le=60)
    max_domains_total: int = Field(2000000, ge=1000, le=10000000)
    max_file_size_mb: int = Field(100, ge=1, le=1024)
    stream_buffer_size: int = Field(16384, ge=1024, le=1048576)
    flush_interval: int = Field(50000, ge=1000, le=100000)
    bloom_filter_error_rate: float = Field(0.001, ge=0.0001, le=0.1)
    bloom_filter_capacity: int = Field(2000000, ge=10000, le=10000000)
    dns_cache_size: int = Field(50000, ge=1000, le=500000)
    dns_cache_ttl: int = Field(600, ge=60, le=3600)
    use_bloom_filter: bool = Field(True)

    @field_validator('use_bloom_filter')
    @classmethod
    def validate_bloom_availability(cls, v: bool) -> bool:
        if v and not BLOOM_AVAILABLE:
            logging.warning("Bloom filter requested but pybloom-live not installed. Falling back to set.")
            return False
        return v


class SourceConfig(BaseModel):
    """Source configuration."""
    name: str = Field(..., min_length=1, max_length=100)
    url: HttpUrl = Field(...)
    source_type: str = Field(..., pattern='^(hosts|domains|adblock)$')
    enabled: bool = Field(True)
    priority: int = Field(0, ge=0, le=100)
    max_size_mb: int = Field(100, ge=1, le=1024)
    verify_ssl: bool = Field(True)


class AppSettings(BaseSettings):
    """Application settings."""
    model_config = ConfigDict(
        env_prefix="DNSBL_",
        env_nested_delimiter="__",
        case_sensitive=False
    )
    
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    log_level: str = Field("INFO", pattern='^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$')
    log_json: bool = Field(True)
    log_file: Optional[Path] = Field(None)
    output_path: Path = Field(Path("./blocklist.txt"))
    output_compression: bool = Field(False)


# ============================================================================
# DOMAIN MODELS
# ============================================================================

class DomainStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    DUPLICATE = "duplicate"
    AI_DETECTED = "ai_detected"
    BLOCKED = "blocked"


class DomainRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    domain: str = Field(..., min_length=3, max_length=253)
    source: str = Field(..., min_length=1, max_length=100)
    status: DomainStatus
    ai_confidence: float = Field(0.0, ge=0.0, le=1.0)
    ai_reasons: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @field_validator('domain')
    @classmethod
    def validate_domain_logic(cls, v: str) -> str:
        v = v.lower().strip()
        if len(v) < 3 or len(v) > 253:
            raise ValueError("Domain length outside valid range")
        labels = v.split('.')
        if len(labels) < 2:
            raise ValueError("Domain must have at least two labels")
        for label in labels:
            if not label or len(label) > 63:
                raise ValueError("Invalid label length")
            if not re.match(r'^[a-z0-9-]+$', label) or label.startswith('-') or label.endswith('-'):
                raise ValueError("Invalid characters or hyphens in label")
        return v
    
    def to_hosts_entry(self) -> str:
        safe_domain = re.sub(r'[\x00-\x1f\x7f\s#|&]', '', self.domain)[:253]
        if self.ai_confidence >= 0.65:
            reasons = ",".join([re.sub(r'[^\w\-]', '_', r)[:50] for r in self.ai_reasons[:2]])
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{reasons}]"
        return f"0.0.0.0 {safe_domain}"

# ============================================================================
# CACHE & CORE LOGIC
# ============================================================================

class AsyncTTLCache(Generic[T]):
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
            val, ts = self._cache[key]
            if time.monotonic() - ts > self.ttl:
                del self._cache[key]
                with suppress(ValueError): self._access_order.remove(key)
                self._misses += 1
                return None
            self._access_order.remove(key)
            self._access_order.append(key)
            self._hits += 1
            return val

    async def set(self, key: str, value: T) -> None:
        async with self._lock:
            if key in self._cache:
                self._access_order.remove(key)
            elif len(self._cache) >= self.maxsize:
                oldest = self._access_order.popleft()
                self._cache.pop(oldest, None)
            self._cache[key] = (value, time.monotonic())
            self._access_order.append(key)

    async def clear(self) -> None:
        async with self._lock:
            self._cache.clear()
            self._access_order.clear()

class DeduplicationManager:
    def __init__(self, expected_elements: int, error_rate: float, use_bloom: bool):
        self._use_bloom = use_bloom and BLOOM_AVAILABLE
        self._false_positives = 0
        if self._use_bloom:
            self._bloom = ScalableBloomFilter(initial_capacity=expected_elements, error_rate=error_rate)
            self._confirmed: Set[str] = set()
        else:
            self._domains: Set[str] = set()

    def add(self, domain: str) -> bool:
        if not self._use_bloom:
            if domain in self._domains: return True
            self._domains.add(domain)
            return False
        if domain in self._confirmed: return True
        if domain in self._bloom:
            self._confirmed.add(domain)
            self._false_positives += 1
            return True
        self._bloom.add(domain)
        return False

    @property
    def unique_count(self) -> int:
        return len(self._bloom) if self._use_bloom else len(self._domains)

    @property
    def stats(self) -> Dict:
        return {"use_bloom": self._use_bloom, "unique": self.unique_count, "false_positives": self._false_positives if self._use_bloom else 0}

# ============================================================================
# PROCESSORS
# ============================================================================

class SSRFProtector:
    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._logger = logging.getLogger(__name__)
        self._blocked_nets = [ipaddress.ip_network(n, strict=False) for n in settings.security.blocked_ip_ranges]
        self._checked_urls: AsyncTTLCache[bool] = AsyncTTLCache(10000, 3600)
        self._dns_cache: AsyncTTLCache[List[str]] = AsyncTTLCache(settings.performance.dns_cache_size, settings.performance.dns_cache_ttl)

    async def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'): raise ValueError("Invalid scheme")
        if not parsed.hostname: raise ValueError("No hostname")
        if parsed.hostname in self._settings.security.allowed_domains: return
        
        # Резолвинг и проверка IP
        ips = await self._resolve(parsed.hostname)
        for ip_str in ips:
            ip = ipaddress.ip_address(ip_str)
            if any(ip in net for net in self._blocked_nets):
                raise ValueError(f"Blocked IP: {ip}")

    async def _resolve(self, hostname: str) -> List[str]:
        cached = await self._dns_cache.get(hostname)
        if cached: return cached
        loop = asyncio.get_running_loop()
        try:
            addr_info = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, hostname, None, 0, socket.SOCK_STREAM),
                timeout=self._settings.performance.dns_timeout
            )
            ips = list(set(info[4][0] for info in addr_info))
            await self._dns_cache.set(hostname, ips)
            return ips
        except Exception as e:
            raise ValueError(f"DNS failed: {hostname}") from e

    async def cleanup(self):
        await self._checked_urls.clear()
        await self._dns_cache.clear()

class AITrackerDetector:
    TRACKER_PATTERNS = [
        (re.compile(r'\banalytics|google[-_]analytics|googletagmanager|gtm|firebase|amplitude|mixpanel|segment|tracking|pixel|beacon|doubleclick|adservice|criteo|facebook|twitter|sentry|hotjar|clarity|appsflyer\b', re.I), "tracker", 0.85)
    ]
    def __init__(self, settings: AppSettings):
        self._cache = AsyncTTLCache(settings.performance.dns_cache_size, 7200)

    async def analyze(self, domain: str) -> Tuple[float, List[str]]:
        cached = await self._cache.get(domain)
        if cached: return cached
        conf, reasons = 0.0, []
        for pat, name, val in self.TRACKER_PATTERNS:
            if pat.search(domain):
                conf, reasons = val, [name]
                break
        await self._cache.set(domain, (conf, reasons))
        return conf, reasons

    async def cleanup(self): await self._cache.clear()

class SourceProcessor:
    def __init__(self, session: aiohttp.ClientSession, settings: AppSettings):
        self._session, self._settings = session, settings
        self._ssrf, self._detector = SSRFProtector(settings), AITrackerDetector(settings)
        self._count = 0

    async def process_source(self, source: SourceConfig) -> AsyncGenerator[DomainRecord, None]:
        if not source.enabled: return
        try:
            await self._ssrf.validate_url(str(source.url))
            timeout = ClientTimeout(total=self._settings.performance.http_timeout)
            async with self._session.get(str(source.url), timeout=timeout, ssl=source.verify_ssl) as resp:
                async for line in resp.content:
                    if self._count >= self._settings.performance.max_domains_total: break
                    domain = self._parse(line.decode('utf-8', 'ignore'), source.source_type)
                    if not domain: continue
                    try:
                        conf, reasons = await self._detector.analyze(domain)
                        rec = DomainRecord(domain=domain, source=source.name, status=DomainStatus.VALID, ai_confidence=conf, ai_reasons=reasons)
                        self._count += 1
                        yield rec
                    except ValidationError: continue
        except Exception as e:
            logging.error(f"Error {source.name}: {e}")

    def _parse(self, line: str, stype: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith('#'): return None
        if stype == 'hosts':
            p = line.split()
            return p[1].split('#')[0].strip() if len(p) >= 2 and p[0] in ('0.0.0.0', '127.0.0.1') else None
        return line.split('#')[0].strip()

    async def cleanup(self):
        await self._ssrf.cleanup()
        await self._detector.cleanup()

# ============================================================================
# BUILDER
# ============================================================================

class BlocklistBuilder:
    def __init__(self, settings: AppSettings):
        self._settings = settings
        self._dedup = DeduplicationManager(settings.performance.max_domains_total, settings.performance.bloom_filter_error_rate, settings.performance.use_bloom_filter)
        self._total, self._dupes, self._ai = 0, 0, 0

    async def build(self, sources: List[SourceConfig]) -> bool:
        start = time.time()
        self._settings.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiohttp.ClientSession(headers={'User-Agent': self._settings.security.user_agent}) as session:
            proc = SourceProcessor(session, self._settings)
            async with aiofiles.open(self._settings.output_path, 'w') as f:
                await f.write(f"# DNS Blocklist v17.0.1 | Generated: {datetime.now(timezone.utc)}\n\n")
                
                buffer = []
                for src in sorted(sources, key=lambda x: x.priority):
                    async for rec in proc.process_source(src):
                        if self._dedup.add(rec.domain):
                            self._dupes += 1
                            continue
                        self._total += 1
                        if rec.ai_confidence >= 0.65: self._ai += 1
                        buffer.append(rec.to_hosts_entry() + "\n")
                        if len(buffer) >= self._settings.performance.flush_interval:
                            await f.writelines(buffer)
                            buffer.clear()
                if buffer: await f.writelines(buffer)
                await f.write(f"\n# Total unique: {self._total} | AI Detected: {self._ai} | Build: {time.time()-start:.2f}s\n")
            await proc.cleanup()
        return True

async def main_async() -> int:
    settings = AppSettings()
    sources = [
        SourceConfig(name="OISD Big", url="https://big.oisd.nl/domains", source_type="domains", priority=1),
        SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=2),
        SourceConfig(name="URLhaus", url="https://urlhaus.abuse.ch/downloads/hostfile/", source_type="hosts", priority=3)
    ]
    builder = BlocklistBuilder(settings)
    return 0 if await builder.build(sources) else 1

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(asyncio.run(main_async()))
