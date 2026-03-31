#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - v17.1.1 (Compatible with Pydantic V1 and V2)
"""

import asyncio
import ipaddress
import logging
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any, Dict, List, Optional, Set, Tuple, TypeVar, Generic, AsyncGenerator
)

import aiofiles
import aiohttp
from aiohttp import ClientTimeout
import tenacity

# Pydantic compatibility layer
try:
    # Try Pydantic V2 imports
    from pydantic import BaseModel, Field, ValidationError, HttpUrl, ConfigDict
    from pydantic import field_validator as pydantic_field_validator
    PYDANTIC_V2 = True
except ImportError:
    # Fall back to Pydantic V1
    from pydantic import BaseModel, Field, ValidationError, HttpUrl, validator as pydantic_validator
    PYDANTIC_V2 = False
    
    # Create compatibility decorator
    def field_validator(field_name, *args, **kwargs):
        if callable(field_name):
            return pydantic_validator('*', allow_reuse=True)(field_name)
        return pydantic_validator(field_name, allow_reuse=True)

try:
    from pydantic_settings import BaseSettings
    PYDANTIC_SETTINGS_AVAILABLE = True
except ImportError:
    from pydantic import BaseSettings
    PYDANTIC_SETTINGS_AVAILABLE = False

# Try to import tqdm for progress bars
try:
    from tqdm.asyncio import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    tqdm = None

T = TypeVar('T')

# ============================================================================
# CONFIGURATION MODELS
# ============================================================================

class SecurityConfig(BaseModel):
    allowed_domains: Set[str] = Field(default_factory=lambda: {
        'raw.githubusercontent.com', 'raw.githubusercontentusercontent.com',
        'github.com', 'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch'
    })
    blocked_ip_ranges: List[str] = Field(default=[
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '::1/128'
    ])
    
    if PYDANTIC_V2:
        @field_validator('blocked_ip_ranges')
        @classmethod
        def validate_networks(cls, v: List[str]) -> List[str]:
            for net in v:
                try:
                    ipaddress.ip_network(net, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid network {net}: {e}")
            return v
    else:
        @pydantic_validator('blocked_ip_ranges')
        def validate_networks(cls, v: List[str]) -> List[str]:
            for net in v:
                try:
                    ipaddress.ip_network(net, strict=False)
                except ValueError as e:
                    raise ValueError(f"Invalid network {net}: {e}")
            return v

class PerformanceConfig(BaseModel):
    max_concurrent_downloads: int = Field(10, ge=1, le=50)
    http_timeout: int = Field(30, ge=1)
    max_domains_total: int = Field(2000000)
    flush_interval: int = Field(50000)
    dns_timeout: int = Field(10)

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str
    enabled: bool = Field(True)
    priority: int = Field(0)
    verify_ssl: bool = Field(True)
    
    if PYDANTIC_V2:
        @field_validator('source_type')
        @classmethod
        def validate_source_type(cls, v: str) -> str:
            if v not in ('hosts', 'domains', 'adblock'):
                raise ValueError(f"source_type must be hosts, domains, or adblock, got {v}")
            return v
    else:
        @pydantic_validator('source_type')
        def validate_source_type(cls, v: str) -> str:
            if v not in ('hosts', 'domains', 'adblock'):
                raise ValueError(f"source_type must be hosts, domains, or adblock, got {v}")
            return v

if PYDANTIC_SETTINGS_AVAILABLE:
    class AppSettings(BaseSettings):
        model_config = ConfigDict(env_prefix="DNSBL_", case_sensitive=False)
        
        security: SecurityConfig = Field(default_factory=SecurityConfig)
        performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
        output_path: Path = Field(default=Path("./blocklist.txt"))
else:
    class AppSettings(BaseSettings):
        security: SecurityConfig = Field(default_factory=SecurityConfig)
        performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
        output_path: Path = Field(default=Path("./blocklist.txt"))
        
        class Config:
            env_prefix = "DNSBL_"
            case_sensitive = False

# ============================================================================
# DOMAIN MANAGEMENT
# ============================================================================

class DomainRecord(BaseModel):
    domain: str
    source: str
    
    if PYDANTIC_V2:
        model_config = ConfigDict(frozen=True)
        
        @field_validator('domain')
        @classmethod
        def clean_domain(cls, v: str) -> str:
            v = v.lower().strip()
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', v):
                raise ValueError(f"Invalid domain: {v}")
            if len(v) > 253:
                raise ValueError("Domain too long")
            return v
    else:
        @pydantic_validator('domain')
        def clean_domain(cls, v: str) -> str:
            v = v.lower().strip()
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', v):
                raise ValueError(f"Invalid domain: {v}")
            if len(v) > 253:
                raise ValueError("Domain too long")
            return v

    def to_hosts_entry(self) -> str:
        return f"0.0.0.0 {self.domain}"

class DomainSet:
    """Efficient domain deduplication with statistics tracking"""
    
    def __init__(self, max_size: int):
        self._set: Set[str] = set()
        self._duplicates: Dict[str, int] = {}
        self.max_size = max_size
    
    def add(self, domain: str, source: str) -> bool:
        if domain in self._set:
            self._duplicates[domain] = self._duplicates.get(domain, 0) + 1
            return False
        
        if len(self._set) >= self.max_size:
            return False
            
        self._set.add(domain)
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'unique': len(self._set),
            'duplicates': sum(self._duplicates.values()),
            'duplicate_domains': len(self._duplicates)
        }

# ============================================================================
# CACHE SYSTEM
# ============================================================================

class AsyncTTLCache(Generic[T]):
    def __init__(self, maxsize: int, ttl: int):
        self.maxsize = maxsize
        self.ttl = ttl
        self._cache: Dict[str, Tuple[T, float]] = {}
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
                if self._order:
                    old = self._order.popleft()
                    self._cache.pop(old, None)
            self._cache[key] = (value, time.monotonic())
            self._order.append(key)

# ============================================================================
# SOURCE PROCESSOR
# ============================================================================

class SourceProcessor:
    def __init__(self, session: aiohttp.ClientSession, settings: AppSettings):
        self.session = session
        self.settings = settings

    async def process(self, source: SourceConfig) -> AsyncGenerator[DomainRecord, None]:
        if not source.enabled:
            return
            
        try:
            timeout = ClientTimeout(total=self.settings.performance.http_timeout)
            async with self.session.get(str(source.url), timeout=timeout, ssl=source.verify_ssl) as resp:
                resp.raise_for_status()
                
                line_count = 0
                async for line in resp.content:
                    try:
                        decoded = line.decode('utf-8', 'ignore').strip()
                        domain = self._extract_domain(decoded, source.source_type)
                        if domain:
                            yield DomainRecord(domain=domain, source=source.name)
                            line_count += 1
                    except Exception:
                        continue
                
                logging.debug(f"  {source.name}: total {line_count} domains extracted")
                    
        except Exception as e:
            logging.error(f"Error processing source {source.name}: {e}")

    def _extract_domain(self, line: str, stype: str) -> Optional[str]:
        """Extract domain from different source formats"""
        # Remove comments
        line = line.split('#')[0].strip()
        
        # Skip empty lines and comments
        if not line or line.startswith(('!', '#')):
            return None
        
        if stype == 'hosts':
            # Hosts file format: 0.0.0.0 example.com
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1'):
                return parts[1]
            return None
            
        elif stype == 'adblock':
            # AdBlock format: ||example.com^
            match = re.match(r'^\|\|([a-z0-9.-]+)\^', line)
            if match:
                return match.group(1)
            return None
            
        else:  # domains
            # Simple domain list format: one domain per line
            return line

# ============================================================================
# MAIN BUILDER
# ============================================================================

async def main_async():
    """Main async entry point"""
    settings = AppSettings()
    
    sources = [
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
    ]
    
    domain_set = DomainSet(max_size=settings.performance.max_domains_total)
    total_processed = 0
    unique_count = 0
    
    logging.info("🚀 Starting DNS blocklist build...")
    logging.info(f"📊 Max domains: {settings.performance.max_domains_total:,}")
    
    async with aiohttp.ClientSession() as session:
        processor = SourceProcessor(session, settings)
        
        async with aiofiles.open(settings.output_path, 'w', encoding='utf-8') as outfile:
            # Write header
            await outfile.write(f"# DNS Security Blocklist\n")
            await outfile.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            await outfile.write(f"# Version: 17.1.1\n\n")
            
            # Process sources in priority order
            for src in sorted(sources, key=lambda x: x.priority):
                if not src.enabled:
                    continue
                    
                logging.info(f"📥 Processing {src.name}...")
                
                try:
                    async for record in processor.process(src):
                        total_processed += 1
                        
                        if domain_set.add(record.domain, src.name):
                            await outfile.write(record.to_hosts_entry() + "\n")
                            unique_count += 1
                            
                            if unique_count % 100000 == 0:
                                logging.info(f"  📈 Progress: {unique_count:,} unique domains...")
                                
                            if unique_count >= settings.performance.max_domains_total:
                                logging.warning(f"⚠️ Domain limit reached")
                                break
                                
                except Exception as e:
                    logging.error(f"❌ Failed to process {src.name}: {e}")
                
                if unique_count >= settings.performance.max_domains_total:
                    break
    
    # Print summary
    logging.info(f"\n{'='*50}")
    logging.info(f"✅ Build completed!")
    logging.info(f"📊 Unique domains: {unique_count:,}")
    logging.info(f"📊 Total processed: {total_processed:,}")
    logging.info(f"💾 Output file: {settings.output_path}")
    
    # Show file size
    if settings.output_path.exists():
        size = settings.output_path.stat().st_size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.2f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.2f} MB"
        logging.info(f"💾 File size: {size_str}")
    logging.info(f"{'='*50}")

def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logging.info("\n⚠️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
