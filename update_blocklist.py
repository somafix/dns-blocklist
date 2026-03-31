#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - v17.2.0 (All-in-One Production Version)
Вся мощь в одном файле: blocklist.txt
"""

import asyncio
import ipaddress
import logging
import re
import sys
import time
import hashlib
import json
import gzip
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import (
    Any, Dict, List, Optional, Set, Tuple, TypeVar, Generic, AsyncGenerator
)
import aiofiles
import aiohttp
from aiohttp import ClientTimeout, ClientError
import tenacity

# Pydantic compatibility layer
try:
    from pydantic import BaseModel, Field, ValidationError, HttpUrl, ConfigDict
    from pydantic import field_validator, model_validator
    PYDANTIC_V2 = True
except ImportError:
    from pydantic import BaseModel, Field, ValidationError, HttpUrl, validator as pydantic_validator
    PYDANTIC_V2 = False
    
    def field_validator(field_name, *args, **kwargs):
        if callable(field_name):
            return pydantic_validator('*', allow_reuse=True)(field_name)
        def decorator(func):
            return pydantic_validator(field_name, allow_reuse=True)(func)
        return decorator

try:
    from pydantic_settings import BaseSettings
    PYDANTIC_SETTINGS = True
except ImportError:
    from pydantic import BaseSettings
    PYDANTIC_SETTINGS = False

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
    cache_ttl: int = Field(86400)
    cache_maxsize: int = Field(10000)

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str
    enabled: bool = Field(True)
    priority: int = Field(0)
    verify_ssl: bool = Field(True)
    update_interval: int = Field(86400)
    last_update: Optional[datetime] = Field(default=None)
    etag: Optional[str] = Field(default=None)
    
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

class AIConfig(BaseModel):
    """AI/ML detection configuration"""
    enabled: bool = Field(True)
    patterns: List[str] = Field(default=[
        r'chatgpt|openai|gpt-\d',
        r'claude|anthropic',
        r'gemini|bard',
        r'copilot|github[-_]?copilot',
        r'midjourney|stable[-_]?diffusion',
        r'deep[-_]?learning|neural[-_]?network',
        r'tensorflow|pytorch|keras',
        r'computer[-_]?vision|nlp|llm',
        r'ai|artificial[-_]?intelligence',
        r'machine[-_]?learning|ml[-_]?',
        r'huggingface|replicate',
        r'character\.ai|perplexity',
        r'elevenlabs|voice[-_]?ai'
    ])

class OutputConfig(BaseModel):
    main_blocklist: Path = Field(default=Path("./blocklist.txt"))  # ТОЛЬКО ОДИН ФАЙЛ
    compressed: bool = Field(default=True)
    format_hosts: bool = Field(default=True)
    include_metadata: bool = Field(default=True)
    include_categories: bool = Field(default=True)  # Добавлять категории в комментариях

if PYDANTIC_SETTINGS:
    class AppSettings(BaseSettings):
        model_config = ConfigDict(env_prefix="DNSBL_", case_sensitive=False)
        
        security: SecurityConfig = Field(default_factory=SecurityConfig)
        performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
        ai: AIConfig = Field(default_factory=AIConfig)
        output: OutputConfig = Field(default_factory=OutputConfig)
        cache_dir: Path = Field(default=Path("./cache"))
else:
    class AppSettings(BaseSettings):
        security: SecurityConfig = Field(default_factory=SecurityConfig)
        performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
        ai: AIConfig = Field(default_factory=AIConfig)
        output: OutputConfig = Field(default_factory=OutputConfig)
        cache_dir: Path = Field(default=Path("./cache"))
        
        class Config:
            env_prefix = "DNSBL_"
            case_sensitive = False

# ============================================================================
# DOMAIN MANAGEMENT
# ============================================================================

class DomainRecord(BaseModel):
    domain: str
    source: str
    category: Optional[str] = Field(default=None)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
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

    def to_hosts_entry(self, include_category: bool = False) -> str:
        if include_category and self.category:
            return f"0.0.0.0 {self.domain} # {self.category}"
        return f"0.0.0.0 {self.domain}"

class DomainSet:
    """Efficient domain deduplication with statistics and categorization"""
    
    def __init__(self, max_size: int, ai_patterns: Optional[List[str]] = None):
        self._set: Set[str] = set()
        self._metadata: Dict[str, DomainRecord] = {}
        self._duplicates: Dict[str, int] = {}
        self._categories: Dict[str, Set[str]] = {
            'ai_ml': set(),
            'ads': set(),
            'tracking': set(),
            'malware': set(),
            'other': set()
        }
        self.max_size = max_size
        self.ai_patterns = ai_patterns or []
        self._ai_regex = re.compile('|'.join(ai_patterns), re.IGNORECASE) if ai_patterns else None
    
    def _categorize(self, domain: str) -> str:
        """Categorize domain based on patterns"""
        if self._ai_regex and self._ai_regex.search(domain):
            return 'ai_ml'
        
        # Ad patterns
        if any(x in domain for x in ['ad', 'ads', 'banner', 'doubleclick', 'adserver']):
            return 'ads'
        
        # Tracking patterns
        if any(x in domain for x in ['track', 'analytics', 'stat', 'pixel', 'beacon', 'metrics']):
            return 'tracking'
        
        # Malware patterns
        if any(x in domain for x in ['malware', 'phish', 'ransom', 'exploit', 'virus']):
            return 'malware'
        
        return 'other'
    
    def add(self, domain: str, source: str) -> bool:
        if domain in self._set:
            self._duplicates[domain] = self._duplicates.get(domain, 0) + 1
            return False
        
        if len(self._set) >= self.max_size:
            return False
            
        self._set.add(domain)
        category = self._categorize(domain)
        self._categories[category].add(domain)
        self._metadata[domain] = DomainRecord(domain=domain, source=source, category=category)
        return True
    
    def get_by_category(self, category: str) -> Set[str]:
        return self._categories.get(category, set())
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'unique': len(self._set),
            'duplicates': sum(self._duplicates.values()),
            'duplicate_domains': len(self._duplicates),
            'categories': {cat: len(domains) for cat, domains in self._categories.items()}
        }
    
    def get_all_with_metadata(self) -> List[DomainRecord]:
        return list(self._metadata.values())

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

class SourceCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def get_cache_path(self, source_name: str) -> Path:
        safe_name = re.sub(r'[^\w\-_\.]', '_', source_name)
        return self.cache_dir / f"{safe_name}.json.gz"
    
    async def save(self, source_name: str, data: Dict[str, Any]):
        path = self.get_cache_path(source_name)
        async with aiofiles.open(path, 'wb') as f:
            await f.write(gzip.compress(json.dumps(data).encode()))
    
    async def load(self, source_name: str) -> Optional[Dict[str, Any]]:
        path = self.get_cache_path(source_name)
        if path.exists():
            try:
                async with aiofiles.open(path, 'rb') as f:
                    content = await f.read()
                    return json.loads(gzip.decompress(content).decode())
            except Exception:
                pass
        return None

# ============================================================================
# SOURCE PROCESSOR WITH RETRY
# ============================================================================

class SourceProcessor:
    def __init__(self, session: aiohttp.ClientSession, settings: AppSettings, cache: SourceCache):
        self.session = session
        self.settings = settings
        self.cache = cache
    
    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=4, max=10),
        retry=tenacity.retry_if_exception_type((ClientError, asyncio.TimeoutError, aiohttp.ClientError))
    )
    async def fetch_source(self, source: SourceConfig) -> Tuple[str, Dict[str, Any]]:
        """Fetch source with retry logic and caching"""
        headers = {}
        
        if source.etag:
            headers['If-None-Match'] = source.etag
        if source.last_update:
            headers['If-Modified-Since'] = source.last_update.strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        timeout = ClientTimeout(total=self.settings.performance.http_timeout)
        
        async with self.session.get(
            str(source.url), 
            timeout=timeout, 
            ssl=source.verify_ssl,
            headers=headers
        ) as resp:
            if resp.status == 304:
                cached = await self.cache.load(source.name)
                if cached:
                    return cached['content'], {'etag': cached.get('etag'), 'cached': True}
                return "", {'cached': False}
            
            resp.raise_for_status()
            content = await resp.text()
            
            metadata = {
                'etag': resp.headers.get('ETag'),
                'last_modified': resp.headers.get('Last-Modified'),
                'cached': False
            }
            
            await self.cache.save(source.name, {
                'content': content,
                'etag': metadata['etag'],
                'last_modified': metadata['last_modified']
            })
            
            return content, metadata

    async def process(self, source: SourceConfig) -> AsyncGenerator[DomainRecord, None]:
        if not source.enabled:
            return
            
        try:
            content, metadata = await self.fetch_source(source)
            
            if not content and metadata.get('cached'):
                logging.debug(f"  {source.name}: using cached version")
                return
            
            line_count = 0
            for line in content.split('\n'):
                try:
                    domain = self._extract_domain(line, source.source_type)
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
        line = line.split('#')[0].strip()
        
        if not line or line.startswith(('!', '#')):
            return None
        
        if stype == 'hosts':
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1'):
                domain = parts[1]
                if domain in ('localhost', 'localhost.localdomain', 'local'):
                    return None
                if ' ' in domain or not domain:
                    return None
                return domain
            return None
            
        elif stype == 'adblock':
            match = re.match(r'^\|\|([a-z0-9.-]+)\^', line)
            if match:
                return match.group(1)
            return None
            
        else:  # domains
            if '.' in line and not line.startswith('.'):
                return line
            return None

# ============================================================================
# MAIN BUILDER - ONE FILE ONLY
# ============================================================================

async def main_async():
    """Main async entry point - creates ONLY blocklist.txt"""
    settings = AppSettings()
    
    # Initialize sources
    sources = [
        SourceConfig(
            name="OISD Big",
            url="https://big.oisd.nl/domains",
            source_type="domains",
            priority=1,
            update_interval=43200
        ),
        SourceConfig(
            name="AdAway",
            url="https://adaway.org/hosts.txt",
            source_type="hosts",
            priority=2,
            update_interval=86400
        ),
        SourceConfig(
            name="URLhaus",
            url="https://urlhaus.abuse.ch/downloads/hostfile/",
            source_type="hosts",
            priority=3,
            update_interval=3600
        ),
        SourceConfig(
            name="StevenBlack",
            url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            source_type="hosts",
            priority=4,
            update_interval=86400
        ),
    ]
    
    # Create domain set with AI patterns
    domain_set = DomainSet(
        max_size=settings.performance.max_domains_total,
        ai_patterns=settings.ai.patterns
    )
    
    total_processed = 0
    unique_count = 0
    
    logging.info("=" * 70)
    logging.info("🚀 DNS Security Blocklist Builder v17.2.0 (All-in-One)")
    logging.info("=" * 70)
    logging.info(f"📊 Max domains: {settings.performance.max_domains_total:,}")
    logging.info(f"🤖 AI detection: {'enabled' if settings.ai.enabled else 'disabled'}")
    logging.info(f"🗜️  Compression: {'enabled' if settings.output.compressed else 'disabled'}")
    logging.info(f"📁 Output: {settings.output.main_blocklist}")
    logging.info("=" * 70)
    
    source_cache = SourceCache(settings.cache_dir)
    
    async with aiohttp.ClientSession() as session:
        processor = SourceProcessor(session, settings, source_cache)
        
        settings.output.main_blocklist.parent.mkdir(parents=True, exist_ok=True)
        
        for src in sorted(sources, key=lambda x: x.priority):
            if not src.enabled:
                logging.info(f"⏭️  Skipping {src.name} (disabled)")
                continue
                
            logging.info(f"📥 Processing {src.name}...")
            
            try:
                src_count = 0
                async for record in processor.process(src):
                    total_processed += 1
                    src_count += 1
                    
                    if domain_set.add(record.domain, src.name):
                        unique_count += 1
                        
                        if unique_count % 100000 == 0:
                            logging.info(f"  📈 Progress: {unique_count:,} unique domains...")
                            
                        if unique_count >= settings.performance.max_domains_total:
                            logging.warning(f"⚠️ Domain limit reached")
                            break
                
                logging.info(f"  ✅ {src.name}: added {src_count:,} domains")
                                
            except Exception as e:
                logging.error(f"❌ Failed to process {src.name}: {e}")
            
            if unique_count >= settings.performance.max_domains_total:
                break
        
        # Save ONE blocklist file with categories in comments
        logging.info("\n💾 Saving blocklist...")
        
        stats = domain_set.get_stats()
        all_records = domain_set.get_all_with_metadata()
        
        async with aiofiles.open(settings.output.main_blocklist, 'w', encoding='utf-8') as f:
            # Header
            await f.write(f"# DNS Security Blocklist - All-in-One\n")
            await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            await f.write(f"# Version: 17.2.0\n")
            await f.write(f"# Total domains: {unique_count:,}\n")
            await f.write(f"# Active sources: {len([s for s in sources if s.enabled])}\n\n")
            
            # Category statistics in header
            await f.write(f"# Category breakdown:\n")
            for cat, count in stats['categories'].items():
                if count > 0:
                    emoji = {'ai_ml': '🤖', 'ads': '📢', 'tracking': '👁️', 'malware': '💀', 'other': '📄'}.get(cat, '📄')
                    await f.write(f"#   {emoji} {cat.upper()}: {count:,}\n")
            await f.write(f"#\n")
            await f.write(f"# Format: 0.0.0.0 domain.com # category\n")
            await f.write(f"#\n\n")
            
            # Write all domains with categories
            for record in sorted(all_records, key=lambda x: x.domain):
                category_emoji = {
                    'ai_ml': '🤖', 'ads': '📢', 'tracking': '👁️', 'malware': '💀', 'other': '📄'
                }.get(record.category, '📄')
                await f.write(f"0.0.0.0 {record.domain} # {category_emoji} {record.category.upper()}\n")
        
        # Create compressed version
        if settings.output.compressed:
            with open(settings.output.main_blocklist, 'rb') as f_in:
                with gzip.open(f"{settings.output.main_blocklist}.gz", 'wb') as f_out:
                    f_out.writelines(f_in)
    
    # Print summary
    stats = domain_set.get_stats()
    logging.info(f"\n{'='*70}")
    logging.info(f"✅ BUILD COMPLETED SUCCESSFULLY!")
    logging.info(f"{'='*70}")
    logging.info(f"📊 Statistics:")
    logging.info(f"   • Unique domains: {unique_count:,}")
    logging.info(f"   • Total processed: {total_processed:,}")
    logging.info(f"   • Duplicates avoided: {stats['duplicates']:,}")
    logging.info(f"\n📁 Category breakdown:")
    for cat, count in stats['categories'].items():
        if count > 0:
            emoji = {'ai_ml': '🤖', 'ads': '📢', 'tracking': '👁️', 'malware': '💀', 'other': '📄'}.get(cat, '📄')
            logging.info(f"   {emoji} {cat.upper()}: {count:,}")
    
    # File size
    if settings.output.main_blocklist.exists():
        size = settings.output.main_blocklist.stat().st_size
        if size < 1024:
            size_str = f"{size} B"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.2f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.2f} MB"
        
        logging.info(f"\n💾 Output:")
        logging.info(f"   📄 {settings.output.main_blocklist.name}: {size_str}")
        
        if settings.output.compressed:
            gz_file = Path(f"{settings.output.main_blocklist}.gz")
            if gz_file.exists():
                gz_size = gz_file.stat().st_size
                if gz_size < 1024:
                    gz_str = f"{gz_size} B"
                elif gz_size < 1024 * 1024:
                    gz_str = f"{gz_size / 1024:.2f} KB"
                else:
                    gz_str = f"{gz_size / (1024 * 1024):.2f} MB"
                savings = (1 - gz_size/size) * 100
                logging.info(f"   🗜️  {gz_file.name}: {gz_str} (saved {savings:.1f}%)")
    
    logging.info(f"{'='*70}")

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
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
