#!/usr/bin/env python3
"""
DNS SECURITY BLOCKLIST BUILDER - FULL AUTONOMOUS VERSION
"""

import subprocess
import sys
import importlib
import os
from pathlib import Path

# ============================================================================
# АВТОМАТИЧЕСКАЯ УСТАНОВКА ЗАВИСИМОСТЕЙ
# ============================================================================

REQUIRED_PACKAGES = [
    'aiohttp',
    'aiofiles', 
    'tenacity',
    'pydantic',
    'pydantic-settings',
]

def install_package(package):
    print(f"📦 Устанавливаю {package}...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--quiet"])

def ensure_dependencies():
    for package in REQUIRED_PACKAGES:
        try:
            importlib.import_module(package.replace('-', '_'))
        except ImportError:
            print(f"⚠️ {package} не найден, устанавливаю...")
            install_package(package)

print("=" * 70)
print("🔧 ПРОВЕРКА ЗАВИСИМОСТЕЙ")
print("=" * 70)
ensure_dependencies()
print("✅ Зависимости проверены")
print("=" * 70)
print()

# ============================================================================
# ОСНОВНОЙ СКРИПТ
# ============================================================================

import asyncio
import ipaddress
import loggingimport re
import time
import json
import gzip
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, AsyncGenerator
import aiofiles
import aiohttp
from aiohttp import ClientTimeout, ClientError
import tenacity

from pydantic import BaseModel, Field, HttpUrl, ConfigDict, field_validator
from pydantic_settings import BaseSettings

# ============================================================================
# CONFIGURATION MODELS
# ============================================================================

class SecurityConfig(BaseModel):
    allowed_domains: Set[str] = Field(default_factory=lambda: {
        'raw.githubusercontent.com', 'githubusercontent.com',
        'github.com', 'oisd.nl', 'adaway.org', 'urlhaus.abuse.ch'
    })
    blocked_ip_ranges: List[str] = Field(default=[
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '::1/128'
    ])
    
    @field_validator('blocked_ip_ranges')
    @classmethod
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
    url: HttpUrl    source_type: str
    enabled: bool = Field(True)
    priority: int = Field(0)
    verify_ssl: bool = Field(True)
    update_interval: int = Field(86400)
    last_update: Optional[datetime] = Field(default=None)
    etag: Optional[str] = Field(default=None)
    
    @field_validator('source_type')
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        if v not in ('hosts', 'domains', 'adblock'):
            raise ValueError(f"source_type must be hosts, domains, or adblock, got {v}")
        return v

class AIConfig(BaseModel):
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
    main_blocklist: Path = Field(default=Path("./blocklist.txt"))
    compressed: bool = Field(default=True)
    format_hosts: bool = Field(default=True)
    include_meta: bool = Field(default=True)
    include_categories: bool = Field(default=True)

class AppSettings(BaseSettings):
    model_config = ConfigDict(env_prefix="DNSBL_", case_sensitive=False)
    
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    cache_dir: Path = Field(default=Path("./cache"))

# ============================================================================# DOMAIN MANAGEMENT
# ============================================================================

class DomainRecord(BaseModel):
    domain: str
    source: str
    category: Optional[str] = Field(default=None)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    model_config = ConfigDict(frozen=True)
        
    @field_validator('domain')
    @classmethod
    def clean_domain(cls, v: str) -> str:
        v = v.lower().strip()
        if not v or len(v) < 3:
            raise ValueError(f"Invalid domain (too short): {v}")
        if v.count('.') == 0:
            raise ValueError(f"Invalid domain (no dot): {v}")
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', v):
            raise ValueError(f"Domain cannot be IP: {v}")
        if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', v):
            raise ValueError(f"Invalid domain format: {v}")
        if len(v) > 253:
            raise ValueError("Domain too long")
        return v

class DomainSet:
    def __init__(self, max_size: int, ai_patterns: Optional[List[str]] = None):
        self._set: Set[str] = set()
        self._metadata: Dict[str, DomainRecord] = {}
        self._duplicates: Dict[str, int] = {}
        self._categories: Dict[str, Set[str]] = {
            'ai_ml': set(), 'ads': set(), 'tracking': set(),
            'malware': set(), 'scam': set(), 'other': set()
        }
        self.max_size = max_size
        self.ai_patterns = ai_patterns or []
        self._ai_regex = re.compile('|'.join(ai_patterns), re.IGNORECASE) if ai_patterns else None
    
    def _categorize(self, domain: str) -> str:
        if self._ai_regex and self._ai_regex.search(domain):
            return 'ai_ml'
        if any(x in domain for x in ['scam', 'fraud', 'fake', 'phishing', 'lottery', 'prize', 'casino']):
            return 'scam'
        if any(x in domain for x in ['ad', 'ads', 'banner', 'doubleclick', 'adserver', 'promo']):
            return 'ads'
        if any(x in domain for x in ['track', 'analytics', 'stat', 'pixel', 'beacon', 'metrics', 'telemetry']):
            return 'tracking'
        if any(x in domain for x in ['malware', 'phish', 'ransom', 'exploit', 'virus', 'trojan']):            return 'malware'
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

class SourceCache:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def get_cache_path(self, source_name: str) -> Path:
        safe_name = re.sub(r'[^\w\-_\.]', '_', source_name)
        return self.cache_dir / f"{safe_name}.json.gz"
    
    async def save(self, source_name: str, data: Dict[str, Any]):
        path = self.get_cache_path(source_name)
        try:
            async with aiofiles.open(path, 'wb') as f:
                await f.write(gzip.compress(json.dumps(data).encode()))
        except Exception as e:
            logging.warning(f"Failed to save cache for {source_name}: {e}")
    
    async def load(self, source_name: str) -> Optional[Dict[str, Any]]:
        path = self.get_cache_path(source_name)
        if path.exists():            try:
                async with aiofiles.open(path, 'rb') as f:
                    content = await f.read()
                    return json.loads(gzip.decompress(content).decode())
            except Exception:
                pass
        return None

# ============================================================================
# SOURCE PROCESSOR
# ============================================================================

class SourceProcessor:
    def __init__(self, session: aiohttp.ClientSession, settings: AppSettings, cache: SourceCache):
        self.session = session
        self.settings = settings
        self.cache = cache
    
    @tenacity.retry(
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_exponential(multiplier=1, min=2, max=10),
        retry=tenacity.retry_if_exception_type((ClientError, asyncio.TimeoutError))
    )
    async def fetch_source(self, source: SourceConfig) -> Tuple[str, Dict[str, Any]]:
        headers = {}
        if source.etag:
            headers['If-None-Match'] = source.etag
        if source.last_update:
            headers['If-Modified-Since'] = source.last_update.strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        timeout = ClientTimeout(total=self.settings.performance.http_timeout)
        
        try:
            async with self.session.get(str(source.url), timeout=timeout, ssl=source.verify_ssl, headers=headers) as resp:
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
                    'etag': metadata['etag'],                     'last_modified': metadata['last_modified']
                })
                return content, metadata
        except Exception as e:
            logging.error(f"Fetch failed for {source.name}: {e}")
            raise

    async def process(self, source: SourceConfig) -> AsyncGenerator[DomainRecord, None]:
        if not source.enabled:
            return
        
        try:
            content, metadata = await self.fetch_source(source)
            if not content and metadata.get('cached'):
                if not content:
                    return
            
            for line in content.split('\n'):
                try:
                    domain = self._extract_domain(line, source.source_type)
                    if domain:
                        yield DomainRecord(domain=domain, source=source.name)
                except Exception:
                    continue
        except Exception as e:
            logging.error(f"Error processing source {source.name}: {e}")

    def _extract_domain(self, line: str, stype: str) -> Optional[str]:
        line = line.split('#')[0].strip()
        if not line or len(line) < 3:
            return None
        
        if line.startswith(('!', '[', '(', '/*', '*', '@@', '###', '--')):
            return None
            
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
            return None
            
        if line.lower() in ('localhost', 'localhost.localdomain', 'local', 'broadcasthost'):
            return None
        
        domain = None
        if stype == 'hosts':
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1'):
                candidate = parts[1]
                if candidate and '.' in candidate and not re.match(r'^\d+\.\d+\.\d+\.\d+$', candidate):
                    domain = candidate.lower()
        elif stype == 'domains':
            if '.' in line and not line.startswith('.'):                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    domain = line.lower()
        elif stype == 'adblock':
            match = re.match(r'^\|\|([a-z0-9.-]+)\^', line)
            if match:
                candidate = match.group(1)
                if candidate and '.' in candidate and not re.match(r'^\d+\.\d+\.\d+\.\d+$', candidate):
                    domain = candidate.lower()
        
        if domain:
            if domain.startswith('.') or domain.endswith('.'):
                return None
            if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', domain):
                return None
            return domain
        return None

# ============================================================================
# MAIN BUILDER
# ============================================================================

async def main_async():
    settings = AppSettings()
    
    sources = [
        SourceConfig(name="OISD Big", url="https://big.oisd.nl/domains", source_type="domains", priority=1),
        SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=2),
        SourceConfig(name="URLhaus", url="https://urlhaus.abuse.ch/downloads/hostfile/", source_type="hosts", priority=3),
        SourceConfig(name="StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", source_type="hosts", priority=4),
        SourceConfig(name="GoodbyeAds", url="https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt", source_type="hosts", priority=5),
        SourceConfig(name="GoodbyeAds Ultimate", url="https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds_Ultimate.txt", source_type="hosts", priority=6),
    ]
    
    domain_set = DomainSet(
        max_size=settings.performance.max_domains_total, 
        ai_patterns=settings.ai.patterns if settings.ai.enabled else None
    )
    total_processed = 0
    unique_count = 0
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    print("=" * 70)
    print("🚀 DNS SECURITY BLOCKLIST BUILDER v17.2.4")
    print("=" * 70)
    print(f"📊 Max domains: {settings.performance.max_domains_total:,}")
    print(f"🤖 AI detection: {'enabled' if settings.ai.enabled else 'disabled'}")
    print(f"📁 Output: {settings.output.main_blocklist}")
    print("=" * 70)
        source_cache = SourceCache(settings.cache_dir)
    settings.output.main_blocklist.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiohttp.ClientSession() as session:
        processor = SourceProcessor(session, settings, source_cache)
        
        for src in sorted(sources, key=lambda x: x.priority):
            if not src.enabled:
                continue
            
            print(f"📥 Processing {src.name}...")
            src_count = 0
            
            try:
                async for record in processor.process(src):
                    total_processed += 1
                    src_count += 1
                    if domain_set.add(record.domain, src.name):
                        unique_count += 1
                        if unique_count >= settings.performance.max_domains_total:
                            break
                print(f"  ✅ {src.name}: processed {src_count:,} lines")
            except Exception as e:
                print(f"  ❌ Failed: {e}")
            
            if unique_count >= settings.performance.max_domains_total:
                print("⚠️ Max domain limit reached. Stopping.")
                break
        
        print("\n💾 Saving blocklist...")
        stats = domain_set.get_stats()
        all_records = domain_set.get_all_with_metadata()
        sorted_records = sorted(all_records, key=lambda x: x.domain)
        
        async with aiofiles.open(settings.output.main_blocklist, 'w', encoding='utf-8') as f:
            await f.write(f"# DNS Security Blocklist\n")
            await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
            await f.write(f"# Total domains: {unique_count:,}\n\n")
            
            await f.write(f"# Category breakdown:\n")
            for cat, count in stats['categories'].items():
                if count > 0:
                    await f.write(f"#   {cat.upper()}: {count:,}\n")
            await f.write(f"#\n\n")
            
            for record in sorted_records:
                await f.write(f"0.0.0.0 {record.domain} # {record.category.upper()}\n")
        
        if settings.output.compressed:
            print("🗜️ Compressing...")            with open(settings.output.main_blocklist, 'rb') as f_in:
                with gzip.open(f"{settings.output.main_blocklist}.gz", 'wb') as f_out:
                    f_out.writelines(f_in)
    
    print("\n" + "=" * 70)
    print("✅ BUILD COMPLETED!")
    print("=" * 70)
    print(f"📊 Unique domains: {unique_count:,}")
    print(f"📊 Total processed: {total_processed:,}")
    print(f"📊 Duplicates avoided: {stats['duplicates']:,}")
    print(f"📂 Output file: {settings.output.main_blocklist}")
    if settings.output.compressed:
        print(f"📂 Compressed: {settings.output.main_blocklist}.gz")
    print("=" * 70)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.exception("Fatal error occurred")
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
