#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - Production Ready with AI Detection (v7.1.0)
Fully working version with rule-based AI tracker detection
"""

import sys
import os
import asyncio
import hashlib
import json
import logging
import logging.handlers
import re
import signal
import time
import shutil
import gc
import argparse
import gzip
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from functools import lru_cache
from pathlib import Path
from typing import Set, Dict, List, Optional, Tuple, Any, ClassVar, Final
from collections import defaultdict
from types import FrameType
import aiohttp
import aiofiles
import yaml

# Suppress warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=ResourceWarning)

# ============================================================================
# VERSION AND CONSTANTS
# ============================================================================

VERSION: Final[str] = "7.1.0"

class Constants:
    MAX_DOMAIN_LEN: ClassVar[int] = 253
    MAX_LABEL_LEN: ClassVar[int] = 63
    MIN_DOMAIN_LEN: ClassVar[int] = 3
    TEMP_SUFFIX: ClassVar[str] = '.tmp'
    BACKUP_SUFFIX: ClassVar[str] = '.backup'
    DEFAULT_BATCH_SIZE: ClassVar[int] = 10000
    MAX_CONCURRENT_DOWNLOADS: ClassVar[int] = 20
    DNS_CACHE_SIZE: ClassVar[int] = 50000
    DEFAULT_TIMEOUT: ClassVar[int] = 30
    MAX_RETRIES: ClassVar[int] = 3
    RETRY_BACKOFF: ClassVar[float] = 1.5
    AI_CACHE_SIZE: ClassVar[int] = 50000
    RESERVED_TLDS: ClassVar[Set[str]] = frozenset({
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p'
    })
    USER_AGENT: ClassVar[str] = f'Mozilla/5.0 (compatible; DNS-Blocklist-Builder/{VERSION})'

# ============================================================================
# EXCEPTIONS
# ============================================================================

class BlocklistError(Exception):
    pass

class ConfigurationError(BlocklistError):
    pass

# ============================================================================
# ENUMS
# ============================================================================

class SourceType(Enum):
    HOSTS = auto()
    DOMAINS = auto()
    ADBLOCK = auto()
    URLHAUS = auto()
    CUSTOM = auto()

class DomainStatus(Enum):
    VALID = auto()
    INVALID_FORMAT = auto()
    INVALID_TLD = auto()
    TOO_LONG = auto()
    RESERVED = auto()
    DUPLICATE = auto()
    SUSPICIOUS = auto()
    AI_DETECTED = auto()

@dataclass
class ProcessingStats:
    total_domains: int = 0
    valid_domains: int = 0
    invalid_domains: int = 0
    duplicate_domains: int = 0
    ai_detected: int = 0
    processing_time: float = 0.0

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass(frozen=True, slots=True)
class DomainRecord:
    domain: str
    source: str
    timestamp: datetime
    status: DomainStatus = DomainStatus.VALID
    ai_confidence: float = 0.0
    ai_reasons: Tuple[str, ...] = field(default_factory=tuple)
    _hash: str = field(init=False, repr=False)
    
    def __post_init__(self) -> None:
        object.__setattr__(self, '_hash', hashlib.blake2b(
            self.domain.lower().encode(), digest_size=16
        ).hexdigest())
    
    def __hash__(self) -> int:
        return hash(self.domain.lower())
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DomainRecord):
            return NotImplemented
        return self.domain.lower() == other.domain.lower()
    
    def to_hosts_entry(self) -> str:
        if self.ai_confidence > 0:
            reasons = ','.join(self.ai_reasons[:2])
            return f"0.0.0.0 {self.domain} # AI:{self.ai_confidence:.0%} [{reasons}]"
        return f"0.0.0.0 {self.domain}"

@dataclass
class SourceDefinition:
    name: str
    url: str
    source_type: SourceType
    enabled: bool = True
    quality: float = 0.8
    max_size_mb: int = 50

@dataclass
class SecurityConfig:
    max_domains: int = 500_000
    timeout_seconds: int = Constants.DEFAULT_TIMEOUT
    max_retries: int = Constants.MAX_RETRIES
    ssl_verify: bool = True
    include_sources: List[str] = field(default_factory=list)
    exclude_sources: List[str] = field(default_factory=list)
    output_path: Path = Path('./blocklist.txt')
    output_format: str = 'hosts'
    output_compression: bool = False
    ai_enabled: bool = True
    ai_confidence_threshold: float = 0.65
    ai_auto_add: bool = True
    log_level: str = 'INFO'
    batch_size: int = Constants.DEFAULT_BATCH_SIZE
    concurrent_downloads: int = Constants.MAX_CONCURRENT_DOWNLOADS
    
    def should_include_source(self, source_name: str) -> bool:
        source_lower = source_name.lower()
        if self.include_sources:
            return source_lower in [s.lower() for s in self.include_sources]
        if self.exclude_sources:
            return source_lower not in [s.lower() for s in self.exclude_sources]
        return True

# ============================================================================
# LOGGING
# ============================================================================

class LoggerManager:
    _initialized: bool = False
    
    @classmethod
    def setup(cls, config: SecurityConfig) -> None:
        if cls._initialized:
            return
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, config.log_level.upper()))
        root_logger.handlers.clear()
        
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        root_logger.addHandler(console)
        cls._initialized = True
    
    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

class DomainValidator:
    DOMAIN_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*$'
    )
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._cache: Dict[str, DomainStatus] = {}
    
    @lru_cache(maxsize=Constants.DNS_CACHE_SIZE)
    def validate(self, domain: str, source: str) -> DomainRecord:
        domain_lower = domain.lower().strip()
        if domain_lower in self._cache:
            status = self._cache[domain_lower]
        else:
            status = self._validate_syntax(domain_lower)
            if len(self._cache) < Constants.DNS_CACHE_SIZE:
                self._cache[domain_lower] = status
        
        return DomainRecord(
            domain=domain,
            source=source,
            timestamp=datetime.now(timezone.utc),
            status=status
        )
    
    def _validate_syntax(self, domain: str) -> DomainStatus:
        if len(domain) < Constants.MIN_DOMAIN_LEN:
            return DomainStatus.INVALID_FORMAT
        if len(domain) > Constants.MAX_DOMAIN_LEN:
            return DomainStatus.TOO_LONG
        
        tld = domain.split('.')[-1]
        if tld in Constants.RESERVED_TLDS:
            return DomainStatus.RESERVED
        
        if not self.DOMAIN_PATTERN.match(domain):
            return DomainStatus.INVALID_FORMAT
        
        return DomainStatus.VALID
    
    def clear_cache(self) -> None:
        self._cache.clear()
        self.validate.cache_clear()

# ============================================================================
# SOURCE PARSERS
# ============================================================================

class SourceParser:
    @staticmethod
    def parse_hosts(content: str) -> Set[str]:
        domains = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line[0] == '#':
                continue
            parts = line.split(maxsplit=2)
            if len(parts) >= 2:
                domain = parts[1].lower()
                if domain not in ('localhost', 'localhost.localdomain', 'local'):
                    domains.add(domain)
        return domains
    
    @staticmethod
    def parse_domains(content: str) -> Set[str]:
        domains = set()
        for line in content.splitlines():
            line = line.strip().lower()
            if not line or line[0] in ('#', '!'):
                continue
            if '#' in line:
                line = line.split('#', 1)[0].strip()
            if line and not line.startswith('0.0.0.0'):
                domains.add(line)
        return domains

# ============================================================================
# SOURCE FETCHER
# ============================================================================

class SourceFetcher:
    def __init__(self, config: SecurityConfig, session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = session
        self._logger = LoggerManager.get_logger(__name__)
    
    async def fetch(self, source: SourceDefinition) -> Tuple[SourceDefinition, Optional[str], Optional[str]]:
        for attempt in range(self._config.max_retries):
            try:
                async with self._session.get(
                    source.url,
                    timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds),
                    headers={'User-Agent': Constants.USER_AGENT},
                    ssl=self._config.ssl_verify
                ) as response:
                    if response.status != 200:
                        error = f"HTTP {response.status}"
                        if attempt < self._config.max_retries - 1:
                            await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
                            continue
                        return source, None, error
                    
                    content = await response.text()
                    if len(content) < 10:
                        return source, None, "Content too short"
                    return source, content, None
                    
            except asyncio.TimeoutError:
                error = "Timeout"
                if attempt < self._config.max_retries - 1:
                    await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
                    continue
                return source, None, error
            except Exception as e:
                return source, None, str(e)
        
        return source, None, "Max retries exceeded"

# ============================================================================
# SOURCE MANAGER
# ============================================================================

class SourceManager:
    SOURCES: ClassVar[List[SourceDefinition]] = [
        SourceDefinition('StevenBlack', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', SourceType.HOSTS, quality=0.95),
        SourceDefinition('OISD', 'https://big.oisd.nl/domains', SourceType.DOMAINS, quality=0.98),
        SourceDefinition('AdAway', 'https://adaway.org/hosts.txt', SourceType.HOSTS, quality=0.90),
        SourceDefinition('URLhaus', 'https://urlhaus.abuse.ch/downloads/hostfile/', SourceType.HOSTS, quality=0.85),
        SourceDefinition('ThreatFox', 'https://threatfox.abuse.ch/downloads/hostfile/', SourceType.HOSTS, quality=0.85),
        SourceDefinition('CERT.PL', 'https://hole.cert.pl/domains/domains_hosts.txt', SourceType.HOSTS, quality=0.80),
    ]
    
    def __init__(self, config: SecurityConfig, session: aiohttp.ClientSession) -> None:
        self._config = config
        self._session = session
        self._fetcher = SourceFetcher(config, session)
        self._logger = LoggerManager.get_logger(__name__)
    
    def _get_sources(self) -> List[SourceDefinition]:
        return [s for s in self.SOURCES if self._config.should_include_source(s.name)]
    
    async def fetch_all(self) -> Dict[str, Set[str]]:
        sources = self._get_sources()
        self._logger.info(f"Fetching {len(sources)} sources...")
        
        semaphore = asyncio.Semaphore(self._config.concurrent_downloads)
        
        async def fetch_with_semaphore(source: SourceDefinition):
            async with semaphore:
                _, content, error = await self._fetcher.fetch(source)
                if error or not content:
                    return source.name, None, error
                
                if source.source_type == SourceType.HOSTS:
                    domains = SourceParser.parse_hosts(content)
                else:
                    domains = SourceParser.parse_domains(content)
                
                return source.name, domains, None
        
        tasks = [fetch_with_semaphore(s) for s in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domains_by_source = {}
        for result in results:
            if isinstance(result, Exception):
                continue
            name, domains, error = result
            if error:
                self._logger.warning(f"{name}: {error}")
            elif domains:
                domains_by_source[name] = domains
                self._logger.info(f"  ✅ {name}: {len(domains):,} domains")
        
        return domains_by_source

# ============================================================================
# AI TRACKER DETECTOR - WORKING VERSION
# ============================================================================

class AITrackerDetector:
    """Rule-based AI tracker detector - no ML dependencies required"""
    
    TRACKER_PATTERNS = [
        # Analytics
        (r'analytics?', 'analytics', 0.82),
        (r'google-analytics', 'google_analytics', 0.95),
        (r'googletagmanager|gtm', 'google_tag_manager', 0.92),
        
        # Tracking
        (r'track(?:ing)?', 'tracking', 0.80),
        (r'pixel', 'tracking_pixel', 0.85),
        (r'beacon', 'tracking_beacon', 0.85),
        (r'collect', 'data_collector', 0.80),
        (r'telemetry', 'telemetry', 0.85),
        (r'metrics', 'metrics', 0.78),
        (r'stat(?:s|istic)?', 'statistics', 0.75),
        
        # Advertising
        (r'doubleclick', 'doubleclick', 0.95),
        (r'adservice', 'ad_service', 0.85),
        (r'ads?\.', 'ad_domain', 0.75),
        
        # Product analytics
        (r'amplitude', 'amplitude', 0.90),
        (r'mixpanel', 'mixpanel', 0.90),
        (r'segment\.com', 'segment', 0.90),
        (r'appsflyer', 'appsflyer', 0.90),
        
        # Social
        (r'facebook\.com/tr', 'facebook_pixel', 0.95),
        (r'twitter\.com/i', 'twitter_tracker', 0.82),
        
        # Suspicious patterns
        (r'[\w-]+\.(?:click|track|metrics|data|stats|insights)\.[a-z]+', 'suspicious_domain', 0.75),
        (r'[\da-f]{16,}', 'hex_domain', 0.70),
    ]
    
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._logger = LoggerManager.get_logger(__name__)
        self._enabled = config.ai_enabled
        self._analysis_cache: Dict[str, Dict] = {}
        self._compiled_patterns = []
        
        for pattern, reason, confidence in self.TRACKER_PATTERNS:
            self._compiled_patterns.append((re.compile(pattern, re.I), reason, confidence))
        
        self._logger.info(f"AI Tracker Detector ready ({len(self._compiled_patterns)} patterns)")
    
    def analyze(self, domain: str) -> Dict:
        """Analyze domain for tracking behavior"""
        if domain in self._analysis_cache:
            return self._analysis_cache[domain]
        
        result = {
            'is_tracker': False,
            'confidence': 0.0,
            'reasons': [],
            'detection_method': 'none'
        }
        
        domain_lower = domain.lower()
        
        # Pattern matching
        for pattern, reason, confidence in self._compiled_patterns:
            if pattern.search(domain_lower):
                result['is_tracker'] = True
                result['confidence'] = max(result['confidence'], confidence)
                result['reasons'].append(reason)
                result['detection_method'] = 'pattern'
        
        # Heuristic: high subdomain count
        if not result['is_tracker']:
            parts = domain_lower.split('.')
            if len(parts) > 5:
                result['is_tracker'] = True
                result['confidence'] = 0.60
                result['reasons'].append('many_subdomains')
                result['detection_method'] = 'heuristic'
        
        # Cache
        if len(self._analysis_cache) < Constants.AI_CACHE_SIZE:
            self._analysis_cache[domain] = result
        
        return result
    
    @property
    def is_enabled(self) -> bool:
        return self._enabled

# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    def __init__(self, config: SecurityConfig, validator: DomainValidator, ai_detector: Optional[AITrackerDetector] = None) -> None:
        self._config = config
        self._validator = validator
        self._ai_detector = ai_detector
        self._logger = LoggerManager.get_logger(__name__)
        self._domains: Dict[str, DomainRecord] = {}
        self._ai_added = 0
        self._stats = ProcessingStats()
    
    async def process_sources(self, domains_by_source: Dict[str, Set[str]]) -> None:
        self._stats.total_domains = sum(len(d) for d in domains_by_source.values())
        self._logger.info(f"Processing {self._stats.total_domains:,} raw domains...")
        
        start_time = time.time()
        
        for source_name, domains in domains_by_source.items():
            for domain in domains:
                record = self._validator.validate(domain, source_name)
                if record.status == DomainStatus.VALID:
                    if record.domain not in self._domains:
                        self._domains[record.domain] = record
                        self._stats.valid_domains += 1
                    else:
                        self._stats.duplicate_domains += 1
                else:
                    self._stats.invalid_domains += 1
        
        # AI analysis
        if self._ai_detector and self._ai_detector.is_enabled and self._config.ai_auto_add:
            await self._ai_analysis_pass()
        
        self._stats.processing_time = time.time() - start_time
        
        # Apply limit
        if len(self._domains) > self._config.max_domains:
            self._logger.warning(f"Truncating to {self._config.max_domains:,} domains")
            self._domains = dict(list(self._domains.items())[:self._config.max_domains])
        
        self._logger.info(f"✅ Final: {len(self._domains):,} unique domains (AI: {self._ai_added:,})")
    
    async def _ai_analysis_pass(self) -> None:
        """Run AI analysis on collected domains"""
        self._logger.info("🤖 Running AI analysis for unknown trackers...")
        
        total = len(self._domains)
        processed = 0
        last_log = 0
        
        for domain in list(self._domains.keys()):
            analysis = self._ai_detector.analyze(domain)
            processed += 1
            
            if processed - last_log >= 10000:
                self._logger.info(f"   AI progress: {processed}/{total} ({processed*100//total}%)")
                last_log = processed
            
            if analysis['is_tracker'] and analysis['confidence'] >= self._config.ai_confidence_threshold:
                record = self._domains[domain]
                new_record = DomainRecord(
                    domain=record.domain,
                    source=f"{record.source}+ai",
                    timestamp=record.timestamp,
                    status=DomainStatus.AI_DETECTED,
                    ai_confidence=analysis['confidence'],
                    ai_reasons=tuple(analysis['reasons'])
                )
                self._domains[domain] = new_record
                self._ai_added += 1
        
        self._stats.ai_detected = self._ai_added
        self._logger.info(f"✅ AI analysis complete: {self._ai_added:,} threats detected")
    
    def get_records(self) -> List[DomainRecord]:
        return list(self._domains.values())
    
    def get_stats(self) -> ProcessingStats:
        return self._stats

# ============================================================================
# OUTPUT GENERATOR
# ============================================================================

class OutputGenerator:
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._logger = LoggerManager.get_logger(__name__)
    
    async def generate(self, records: List[DomainRecord]) -> Path:
        output_path = self._config.output_path
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        ai_count = sum(1 for r in records if r.ai_confidence > 0)
        
        try:
            async with aiofiles.open(tmp_path, 'w', encoding='utf-8') as f:
                await f.write(f"# DNS Security Blocklist v{VERSION}\n")
                await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                await f.write(f"# Total domains: {len(records):,}\n")
                await f.write(f"# AI-detected: {ai_count:,}\n")
                await f.write("#\n\n")
                
                for i in range(0, len(records), self._config.batch_size):
                    batch = records[i:i + self._config.batch_size]
                    for record in batch:
                        if self._config.output_format == 'hosts':
                            await f.write(record.to_hosts_entry() + "\n")
                        else:
                            await f.write(record.domain + "\n")
                    await f.flush()
            
            shutil.move(tmp_path, output_path)
            self._logger.info(f"✅ Generated {output_path} ({len(records):,} domains, {ai_count:,} AI-detected)")
            return output_path
            
        except Exception as e:
            self._logger.error(f"Failed to generate output: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise

# ============================================================================
# MAIN BUILDER
# ============================================================================

class SecurityBlocklistBuilder:
    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._logger = LoggerManager.get_logger(__name__)
        self._shutdown = asyncio.Event()
        
        self._validator: Optional[DomainValidator] = None
        self._ai_detector: Optional[AITrackerDetector] = None
        self._source_manager: Optional[SourceManager] = None
        self._processor: Optional[DomainProcessor] = None
        self._output_generator: Optional[OutputGenerator] = None
        self._session: Optional[aiohttp.ClientSession] = None
    
    def _setup_signal_handlers(self) -> None:
        def signal_handler(sig: int, frame: Optional[FrameType]) -> None:
            self._logger.info("Shutting down...")
            self._shutdown.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def _initialize(self) -> None:
        connector = aiohttp.TCPConnector(limit=self._config.concurrent_downloads, ssl=self._config.ssl_verify)
        self._session = aiohttp.ClientSession(connector=connector, headers={'User-Agent': Constants.USER_AGENT})
        
        self._validator = DomainValidator(self._config)
        
        if self._config.ai_enabled:
            self._ai_detector = AITrackerDetector(self._config)
        
        self._source_manager = SourceManager(self._config, self._session)
        self._processor = DomainProcessor(self._config, self._validator, self._ai_detector)
        self._output_generator = OutputGenerator(self._config)
    
    async def _cleanup(self) -> None:
        if self._session:
            await self._session.close()
        if self._validator:
            self._validator.clear_cache()
        gc.collect()
    
    async def run(self) -> int:
        self._setup_signal_handlers()
        
        try:
            print("=" * 60)
            print(f"🔒 DNS Security Blocklist Builder v{VERSION}")
            print(f"🤖 AI detection: {'ENABLED' if self._config.ai_enabled else 'DISABLED'}")
            print(f"📁 Output: {self._config.output_path}")
            print("=" * 60)
            
            await self._initialize()
            
            if self._shutdown.is_set():
                return 130
            
            domains_by_source = await self._source_manager.fetch_all()
            
            if not domains_by_source:
                self._logger.error("No sources fetched")
                return 1
            
            await self._processor.process_sources(domains_by_source)
            
            if not self._processor.get_records():
                self._logger.error("No valid domains")
                return 1
            
            records = self._processor.get_records()
            await self._output_generator.generate(records)
            
            self._print_report()
            return 0
            
        except asyncio.CancelledError:
            return 130
        except Exception as e:
            self._logger.error(f"Build failed: {e}")
            return 1
        finally:
            await self._cleanup()
    
    def _print_report(self) -> None:
        stats = self._processor.get_stats()
        sep = "=" * 60
        
        print(f"\n{sep}")
        print(f"📊 BUILD REPORT")
        print(sep)
        print(f"  • Total processed: {stats.total_domains:,}")
        print(f"  • Valid domains: {stats.valid_domains:,}")
        print(f"  • Duplicates: {stats.duplicate_domains:,}")
        
        if stats.ai_detected > 0:
            print(f"\n🤖 AI DETECTION:")
            print(f"  • Threats found: {stats.ai_detected:,}")
            print(f"  • Detection rate: {stats.ai_detected / max(stats.valid_domains, 1):.2%}")
        
        print(f"\n⚡ PERFORMANCE:")
        print(f"  • Time: {stats.processing_time:.2f}s")
        print(f"  • Rate: {stats.valid_domains / max(stats.processing_time, 1):.0f} domains/sec")
        print(sep)

# ============================================================================
# MAIN
# ============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='DNS Security Blocklist Builder')
    parser.add_argument('-o', '--output', type=Path, help='Output file path')
    parser.add_argument('--format', choices=['hosts', 'domains'], default='hosts')
    parser.add_argument('--max-domains', type=int, help='Maximum domains')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI detection')
    parser.add_argument('--ai-confidence', type=float, default=0.65, help='AI confidence threshold')
    parser.add_argument('--list-sources', action='store_true', help='List sources')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    return parser.parse_args()

async def async_main() -> int:
    args = parse_args()
    
    if args.list_sources:
        print("\n📋 Available sources:")
        for s in SourceManager.SOURCES:
            print(f"  • {s.name}")
        return 0
    
    config = SecurityConfig()
    
    if args.output:
        config.output_path = args.output
    if args.format:
        config.output_format = args.format
    if args.max_domains:
        config.max_domains = args.max_domains
    if args.no_ai:
        config.ai_enabled = False
    if args.ai_confidence:
        config.ai_confidence_threshold = args.ai_confidence
    if args.verbose:
        config.log_level = 'DEBUG'
    
    LoggerManager.setup(config)
    
    builder = SecurityBlocklistBuilder(config)
    return await builder.run()

def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted")
        return 130

if __name__ == "__main__":
    sys.exit(main())
