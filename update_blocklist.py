#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - v17.1.0
Enhanced version with health checks, progress bars, and statistics
"""

import asyncio
import ipaddress
import logging
import re
import socket
import sys
import time
import uuid
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any, AsyncIterator, Dict, List, Optional, 
    Set, Tuple, TypeVar, Generic, AsyncGenerator
)

import aiofiles
import aiohttp
from aiohttp import ClientTimeout
from pydantic import BaseModel, Field, ValidationError, HttpUrl, field_validator, ConfigDict
from pydantic_settings import BaseSettings
import tenacity

# Try to import tqdm for progress bars, fallback to simple logging if not available
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

    @field_validator('blocked_ip_ranges')
    @classmethod
    def validate_networks(cls, v: List[str]) -> List[str]:
        for net in v:
            ipaddress.ip_network(net, strict=False)
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
    source_type: str = Field(pattern='^(hosts|domains|adblock)$')
    enabled: bool = Field(True)
    priority: int = Field(0)
    verify_ssl: bool = Field(True)

class AppSettings(BaseSettings):
    model_config = ConfigDict(env_prefix="DNSBL_", case_sensitive=False)
    
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    output_path: Path = Field(default=Path("./blocklist.txt"))

# ============================================================================
# DOMAIN MANAGEMENT
# ============================================================================

class DomainRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    domain: str
    source: str

    @field_validator('domain')
    @classmethod
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
    
    def get_domains(self) -> Set[str]:
        return self._set

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
# SOURCE HEALTH CHECKER
# ============================================================================

class SourceHealthChecker:
    """Check source availability before processing"""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self._stats: Dict[str, Dict] = {}
    
    async def check_source(self, source: SourceConfig) -> bool:
        try:
            start_time = time.time()
            async with self.session.head(str(source.url), timeout=10, ssl=source.verify_ssl) as resp:
                response_time = time.time() - start_time
                self._stats[source.name] = {
                    'status': resp.status,
                    'response_time': response_time,
                    'last_check': datetime.now(timezone.utc).isoformat(),
                    'healthy': resp.status == 200
                }
                return resp.status == 200
        except Exception as e:
            self._stats[source.name] = {
                'healthy': False,
                'error': str(e),
                'last_check': datetime.now(timezone.utc).isoformat()
            }
            return False
    
    async def filter_healthy_sources(self, sources: List[SourceConfig]) -> List[SourceConfig]:
        healthy_sources = []
        for source in sources:
            if not source.enabled:
                logging.info(f"Source {source.name} is disabled, skipping")
                continue
                
            logging.info(f"Checking health of {source.name}...")
            if await self.check_source(source):
                healthy_sources.append(source)
                logging.info(f"✓ {source.name} is healthy")
            else:
                status = self._stats[source.name]
                error = status.get('error', f"HTTP {status.get('status')}")
                logging.warning(f"✗ {source.name} is unhealthy: {error}")
        
        return healthy_sources
    
    def get_stats(self) -> Dict[str, Any]:
        return self._stats

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
                
                # Get content length for progress bar
                content_length = int(resp.headers.get('Content-Length', 0))
                
                # Setup progress bar if tqdm is available
                if TQDM_AVAILABLE and content_length > 0:
                    pbar = tqdm(
                        total=content_length,
                        unit='B',
                        unit_scale=True,
                        desc=f"Downloading {source.name}"
                    )
                else:
                    pbar = None
                
                line_count = 0
                async for line in resp.content:
                    if pbar:
                        pbar.update(len(line))
                    
                    try:
                        decoded = line.decode('utf-8', 'ignore').strip()
                        domain = self._extract_domain(decoded, source.source_type)
                        if domain:
                            yield DomainRecord(domain=domain, source=source.name)
                            line_count += 1
                            
                            if line_count % 10000 == 0 and not pbar:
                                logging.debug(f"  {source.name}: processed {line_count} lines")
                                
                    except (ValidationError, ValueError):
                        continue
                
                if pbar:
                    pbar.close()
                
                logging.debug(f"  {source.name}: total {line_count} domains extracted")
                    
        except Exception as e:
            logging.error(f"Error processing source {source.name}: {e}")
            raise

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
# STATISTICS
# ============================================================================

class BuildStats(BaseModel):
    """Build statistics tracking"""
    total_domains: int = 0
    unique_domains: int = 0
    sources_processed: int = 0
    sources_failed: int = 0
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    errors: List[str] = Field(default_factory=list)
    source_stats: Dict[str, Dict] = Field(default_factory=dict)
    
    def finish(self) -> 'BuildStats':
        self.end_time = datetime.now(timezone.utc)
        return self
    
    def duration(self) -> float:
        if not self.end_time:
            return 0
        return (self.end_time - self.start_time).total_seconds()
    
    def to_markdown(self) -> str:
        return f"""## Build Statistics
- **Unique domains:** {self.unique_domains:,}
- **Total processed:** {self.total_domains:,}
- **Sources processed:** {self.sources_processed}
- **Sources failed:** {self.sources_failed}
- **Duration:** {self.duration():.2f} seconds
- **Errors:** {len(self.errors)}
- **Rate:** {self.unique_domains / self.duration():.0f} domains/second
"""
    
    def to_json(self) -> str:
        return json.dumps(self.model_dump(), indent=2, default=str)
    
    def log_summary(self):
        logging.info(f"\n{'='*50}")
        logging.info(f"Build completed in {self.duration():.2f} seconds")
        logging.info(f"Unique domains: {self.unique_domains:,}")
        logging.info(f"Total processed: {self.total_domains:,}")
        logging.info(f"Sources: {self.sources_processed} successful, {self.sources_failed} failed")
        if self.errors:
            logging.info(f"Errors: {len(self.errors)}")
        logging.info(f"{'='*50}")

# ============================================================================
# MAIN BUILDER
# ============================================================================

class DNSBlocklistBuilder:
    """Main builder class orchestrating the blocklist generation"""
    
    def __init__(self, settings: AppSettings):
        self.settings = settings
        self.stats = BuildStats()
        
    async def build(self, sources: List[SourceConfig]) -> Path:
        """Build the blocklist from sources"""
        
        logging.info("🚀 Starting DNS blocklist build...")
        logging.info(f"📊 Configuration: max domains = {self.settings.performance.max_domains_total:,}")
        
        domain_set = DomainSet(max_size=self.settings.performance.max_domains_total)
        
        async with aiohttp.ClientSession() as session:
            # Check source health
            health_checker = SourceHealthChecker(session)
            healthy_sources = await health_checker.filter_healthy_sources(sources)
            
            # Update stats
            self.stats.sources_processed = len(healthy_sources)
            self.stats.sources_failed = len(sources) - len(healthy_sources)
            self.stats.source_stats = health_checker.get_stats()
            
            if not healthy_sources:
                raise Exception("No healthy sources available")
            
            logging.info(f"📡 Processing {len(healthy_sources)} sources...")
            
            processor = SourceProcessor(session, self.settings)
            
            # Write output file
            async with aiofiles.open(self.settings.output_path, 'w', encoding='utf-8') as outfile:
                # Write header with metadata
                await outfile.write(f"# DNS Security Blocklist\n")
                await outfile.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                await outfile.write(f"# Version: 17.1.0\n")
                await outfile.write(f"# Sources: {len(healthy_sources)}\n")
                for src in healthy_sources:
                    await outfile.write(f"#   - {src.name}: {src.url}\n")
                await outfile.write(f"#\n")
                await outfile.write(f"# This blocklist contains domains known for ads, trackers, and malware\n")
                await outfile.write(f"# Format: 0.0.0.0 domain.com\n")
                await outfile.write(f"#\n\n")
                
                # Process each source in priority order
                for src in sorted(healthy_sources, key=lambda x: x.priority):
                    logging.info(f"📥 Processing {src.name} (priority {src.priority})...")
                    
                    try:
                        async for record in processor.process(src):
                            self.stats.total_domains += 1
                            
                            if domain_set.add(record.domain, src.name):
                                await outfile.write(record.to_hosts_entry() + "\n")
                                self.stats.unique_domains += 1
                                
                                # Progress logging
                                if self.stats.unique_domains % 100000 == 0:
                                    logging.info(f"  📈 Progress: {self.stats.unique_domains:,} unique domains...")
                                    
                                # Check limit
                                if self.stats.unique_domains >= self.settings.performance.max_domains_total:
                                    logging.warning(f"⚠️  Domain limit reached ({self.settings.performance.max_domains_total:,})")
                                    break
                                    
                    except Exception as e:
                        error_msg = f"Failed to process {src.name}: {str(e)}"
                        logging.error(f"❌ {error_msg}")
                        self.stats.errors.append(error_msg)
                        self.stats.sources_failed += 1
                    
                    # Break if limit reached
                    if self.stats.unique_domains >= self.settings.performance.max_domains_total:
                        break
        
        # Finalize stats
        self.stats.finish()
        
        # Save statistics
        stats_path = self.settings.output_path.parent / f"{self.settings.output_path.stem}_stats.json"
        async with aiofiles.open(stats_path, 'w', encoding='utf-8') as f:
            await f.write(self.stats.to_json())
        
        return self.settings.output_path

# ============================================================================
# SOURCES DEFINITION
# ============================================================================

def get_default_sources() -> List[SourceConfig]:
    """Get default list of blocklist sources"""
    return [
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
        SourceConfig(
            name="StevenBlack Unified",
            url="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
            source_type="hosts",
            priority=4,
            enabled=True
        ),
        SourceConfig(
            name="EasyList",
            url="https://easylist.to/easylist/easylist.txt",
            source_type="adblock",
            priority=5,
            enabled=False  # Disabled by default due to size
        ),
    ]

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main_async():
    """Main async entry point"""
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="DNS Security Blocklist Builder")
    parser.add_argument("--config", type=Path, help="Path to JSON config file")
    parser.add_argument("--output", type=Path, help="Output file path")
    parser.add_argument("--max-domains", type=int, help="Maximum domains to include")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Load settings
    settings = AppSettings()
    if args.output:
        settings.output_path = args.output
    if args.max_domains:
        settings.performance.max_domains_total = args.max_domains
    
    # Load custom sources if config provided
    sources = get_default_sources()
    if args.config and args.config.exists():
        try:
            async with aiofiles.open(args.config, 'r') as f:
                content = await f.read()
                custom_sources = json.loads(content)
                sources = [SourceConfig(**s) for s in custom_sources]
                logging.info(f"Loaded {len(sources)} sources from {args.config}")
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
    
    # Create builder and run
    builder = DNSBlocklistBuilder(settings)
    
    try:
        output_path = await builder.build(sources)
        
        # Print final summary
        builder.stats.log_summary()
        
        # Print file size
        if output_path.exists():
            size = output_path.stat().st_size
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.2f} KB"
            else:
                size_str = f"{size / (1024 * 1024):.2f} MB"
            logging.info(f"💾 Output file: {output_path} ({size_str})")
        
        logging.info("✅ Build completed successfully!")
        
    except Exception as e:
        logging.error(f"❌ Build failed: {e}")
        sys.exit(1)

def main():
    """Main entry point with error handling"""
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logging.info("\n⚠️  Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
