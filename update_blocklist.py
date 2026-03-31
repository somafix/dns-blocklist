#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION EDITION (v17.0.2)
Исправлены импорты Generic и обновлены валидаторы Pydantic V2.
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
import socket  # Необходим для работы резолвера
from collections import deque
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any, AsyncIterator, Callable, Deque, Dict, Final, List, Optional, 
    Set, Tuple, TypeVar, Union, cast, AsyncGenerator, Awaitable, Generic
)
from urllib.parse import urlparse

import aiofiles
import aiohttp
from aiohttp import ClientTimeout, ClientError
from pydantic import BaseModel, Field, ValidationError, HttpUrl, field_validator, ConfigDict
from pydantic_settings import BaseSettings
import tenacity

# Определение типа для Generic
T = TypeVar('T')

# Проверка наличия опциональных зависимостей
try:
    from pybloom_live import ScalableBloomFilter
    BLOOM_AVAILABLE = True
except ImportError:
    BLOOM_AVAILABLE = False

# ============================================================================
# КОНФИГУРАЦИЯ (Pydantic V2 Style)
# ============================================================================

class SecurityConfig(BaseModel):
    allowed_domains: Set[str] = Field(default_factory=lambda: {
        'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
        'raw.github.com', 'github.com', 'gist.github.com', 'gitlab.com',
        'bitbucket.org', 'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch',
        'threatfox.abuse.ch', 'hole.cert.pl', 'someonewhocares.org',
        'pgl.yoyo.org', 's3.amazonaws.com', 'hosts-file.net'
    })
    blocked_ip_ranges: List[str] = Field(default=[
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10', '::ffff:0:0/96'
    ])
    max_redirects: int = Field(3, ge=0, le=10)
    user_agent: str = Field("DNS-Blocklist-Builder/17.0.2")

    @field_validator('blocked_ip_ranges')
    @classmethod
    def validate_ips(cls, v):
        for ip in v:
            ipaddress.ip_network(ip, strict=False)
        return v

class PerformanceConfig(BaseModel):
    max_concurrent_downloads: int = Field(10, ge=1, le=50)
    connection_limit_per_host: int = Field(5, ge=1, le=20)
    http_timeout: int = Field(30, ge=1)
    dns_timeout: int = Field(10, ge=1)
    max_domains_total: int = Field(2000000)
    flush_interval: int = Field(50000)
    bloom_filter_error_rate: float = Field(0.001)
    use_bloom_filter: bool = Field(True)

    @field_validator('use_bloom_filter')
    @classmethod
    def check_bloom(cls, v):
        if v and not BLOOM_AVAILABLE:
            logging.warning("pybloom-live не установлен. Откат к Set.")
            return False
        return v

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str = Field(pattern='^(hosts|domains|adblock)$')
    enabled: bool = Field(True)
    priority: int = Field(0)
    max_size_mb: int = Field(100)
    verify_ssl: bool = Field(True)

class AppSettings(BaseSettings):
    model_config = ConfigDict(env_prefix="DNSBL_", case_sensitive=False)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    output_path: Path = Field(Path("./blocklist.txt"))

# ============================================================================
# МОДЕЛИ ДАННЫХ
# ============================================================================

class DomainStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"

class DomainRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    domain: str
    source: str
    status: DomainStatus
    ai_confidence: float = 0.0
    ai_reasons: List[str] = Field(default_factory=list)

    @field_validator('domain')
    @classmethod
    def clean_domain(cls, v):
        v = v.lower().strip()
        if not re.match(r'^[a-z0-9.-]+$', v) or len(v) > 253:
            raise ValueError("Неверный формат домена")
        return v

    def to_hosts_entry(self) -> str:
        return f"0.0.0.0 {self.domain}"

# ============================================================================
# ЛОГИКА КЭША И ОБРАБОТКИ
# ============================================================================

class AsyncTTLCache(Generic[T]):
    def __init__(self, maxsize: int, ttl: int):
        self.maxsize = maxsize
        self.ttl = ttl
        self._cache = {}
        self._order = deque()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[T]:
        async with self._lock:
            if key in self._cache:
                val, ts = self._cache[key]
                if time.monotonic() - ts < self.ttl:
                    return val
                del self._cache[key]
            return None

    async def set(self, key: str, value: T):
        async with self._lock:
            if len(self._cache) >= self.maxsize:
                old = self._order.popleft()
                self._cache.pop(old, None)
            self._cache[key] = (value, time.monotonic())
            self._order.append(key)

class SourceProcessor:
    def __init__(self, session: aiohttp.ClientSession, settings: AppSettings):
        self.session = session
        self.settings = settings

    async def process(self, source: SourceConfig) -> AsyncGenerator[DomainRecord, None]:
        if not source.enabled: return
        try:
            timeout = ClientTimeout(total=self.settings.performance.http_timeout)
            async with self.session.get(str(source.url), timeout=timeout, ssl=source.verify_ssl) as resp:
                resp.raise_for_status()
                async for line in resp.content:
                    d_str = self._parse(line.decode('utf-8', 'ignore'), source.source_type)
                    if d_str:
                        try:
                            yield DomainRecord(domain=d_str, source=source.name, status=DomainStatus.VALID)
                        except ValidationError: continue
        except Exception as e:
            logging.error(f"Ошибка в источнике {source.name}: {e}")

    def _parse(self, line: str, stype: str) -> Optional[str]:
        line = line.strip()
        if not line or line.startswith(('#', '!')): return None
        if stype == 'hosts':
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
                return parts[1].split('#')[0].strip()
            return None
        return line.split('#')[0].strip()

# ============================================================================
# MAIN
# ============================================================================

async def main_async():
    settings = AppSettings()
    sources = [
        SourceConfig(name="OISD", url="https://big.oisd.nl/domains", source_type="domains"),
        SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts")
    ]
    
    seen = set()
    total = 0
    start = time.time()
    
    async with aiohttp.ClientSession() as session:
        proc = SourceProcessor(session, settings)
        async with aiofiles.open(settings.output_path, 'w') as f:
            await f.write(f"# DNS Blocklist | {datetime.now(timezone.utc)}\n")
            
            for src in sources:
                async for rec in proc.process(src):
                    if rec.domain not in seen:
                        seen.add(rec.domain)
                        total += 1
                        await f.write(rec.to_hosts_entry() + "\n")
                        
                        if total % 10000 == 0:
                            logging.info(f"Обработано {total} доменов...")

    logging.info(f"Завершено! Доменов: {total}. Время: {time.time()-start:.1f}s")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        pass
