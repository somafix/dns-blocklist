#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - GOLDEN EDITION (v9.0.0)
Balance: Working AI detection + Critical security fixes + Clean code
"""

import sys
import os
import asyncio
import hashlib
import logging
import re
import signal
import time
import shutil
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Set, Dict, List, Optional, Tuple, ClassVar, Final
from urllib.parse import urlparse
import ipaddress

import aiohttp

VERSION: Final[str] = "9.0.0"

# ============================================================================
# CONSTANTS
# ============================================================================

class Constants:
    MAX_DOMAIN_LEN: int = 253
    MAX_LABEL_LEN: int = 63
    MIN_DOMAIN_LEN: int = 3
    TEMP_SUFFIX: str = '.tmp'
    BACKUP_SUFFIX: str = '.backup'
    MAX_CONCURRENT_DOWNLOADS: int = 10
    DNS_CACHE_SIZE: int = 50000
    AI_CACHE_SIZE: int = 50000
    DEFAULT_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    RETRY_BACKOFF: float = 1.5
    MAX_FILE_SIZE_MB: int = 50
    MAX_DECOMPRESSED_MB: int = 200  # Zip-bomb protection
    
    # SSRF Protection
    ALLOWED_SCHEMES: Set[str] = {'http', 'https'}
    BLOCKED_IP_RANGES: List[str] = [
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10'
    ]
    ALLOWED_DOMAINS: Set[str] = {
        'raw.githubusercontent.com',
        'oisd.nl',
        'adaway.org',
        'urlhaus.abuse.ch',
        'threatfox.abuse.ch',
        'hole.cert.pl',
    }
    
    RESERVED_TLDS: Set[str] = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p'
    }
    
    USER_AGENT: str = f'Mozilla/5.0 (compatible; DNS-Blocklist-Builder/{VERSION})'

# ============================================================================
# ENUMS
# ============================================================================

class SourceType(Enum):
    HOSTS = auto()
    DOMAINS = auto()

class DomainStatus(Enum):
    VALID = auto()
    INVALID = auto()
    DUPLICATE = auto()
    AI_DETECTED = auto()


@dataclass(frozen=True)
class DomainRecord:
    domain: str
    source: str
    status: DomainStatus
    ai_confidence: float = 0.0
    ai_reasons: Tuple[str, ...] = field(default_factory=tuple)
    
    def to_hosts_entry(self) -> str:
        """Safe hosts entry with injection protection"""
        # CRITICAL FIX: Escape dangerous characters
        safe_domain = re.sub(r'[\n\r\t\v\f]', '', self.domain)
        if self.ai_confidence > 0:
            reasons = ','.join(self.ai_reasons[:2])
            return f"0.0.0.0 {safe_domain} # AI:{self.ai_confidence:.0%} [{reasons}]"
        return f"0.0.0.0 {safe_domain}"


@dataclass
class SourceDefinition:
    name: str
    url: str
    source_type: SourceType
    enabled: bool = True


@dataclass
class Config:
    output_path: Path = Path('./dynamic-blocklist.txt')
    output_format: str = 'hosts'
    max_domains: int = 500_000
    timeout: int = Constants.DEFAULT_TIMEOUT
    max_retries: int = Constants.MAX_RETRIES
    concurrent_downloads: int = Constants.MAX_CONCURRENT_DOWNLOADS
    ai_enabled: bool = True
    ai_confidence_threshold: float = 0.65
    verbose: bool = False


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )


# ============================================================================
# SSRF PROTECTION
# ============================================================================

class SSRFP protector:
    """Prevent Server-Side Request Forgery attacks"""
    
    def __init__(self):
        self._blocked_networks = [ipaddress.ip_network(net) for net in Constants.BLOCKED_IP_RANGES]
    
    async def validate_url(self, url: str, session: aiohttp.ClientSession) -> bool:
        """Validate URL is safe to fetch"""
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in Constants.ALLOWED_SCHEMES:
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        # Check domain whitelist
        if parsed.hostname not in Constants.ALLOWED_DOMAINS:
            # Resolve DNS and check IP
            ips = await self._resolve_hostname(parsed.hostname)
            for ip in ips:
                self._check_ip_allowed(ip)
        
        return True
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IPs"""
        loop = asyncio.get_event_loop()
        try:
            ips = await loop.getaddrinfo(hostname, None, family=0, type=0, proto=0)
            return list(set(ip[4][0] for ip in ips))
        except Exception as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
    
    def _check_ip_allowed(self, ip_str: str) -> None:
        """Check if IP is in blocked range"""
        ip = ipaddress.ip_address(ip_str)
        for blocked in self._blocked_networks:
            if ip in blocked:
                raise ValueError(f"IP {ip} is in blocked range {blocked}")


# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

class DomainValidator:
    """Validate domain names with caching"""
    
    DOMAIN_PATTERN = re.compile(
        r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$',
        re.IGNORECASE
    )
    
    def __init__(self):
        self._cache: Dict[str, bool] = {}
    
    def is_valid(self, domain: str) -> bool:
        """Check if domain is valid"""
        domain_lower = domain.lower().strip()
        
        if domain_lower in self._cache:
            return self._cache[domain_lower]
        
        valid = self._validate(domain_lower)
        if len(self._cache) < Constants.DNS_CACHE_SIZE:
            self._cache[domain_lower] = valid
        
        return valid
    
    def _validate(self, domain: str) -> bool:
        if len(domain) < Constants.MIN_DOMAIN_LEN:
            return False
        if len(domain) > Constants.MAX_DOMAIN_LEN:
            return False
        
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        tld = parts[-1]
        if tld in Constants.RESERVED_TLDS:
            return False
        
        for label in parts:
            if len(label) > Constants.MAX_LABEL_LEN:
                return False
        
        return bool(self.DOMAIN_PATTERN.match(domain))


# ============================================================================
# AI TRACKER DETECTOR (WORKING - FROM V7.1.0)
# ============================================================================

class AITrackerDetector:
    """Rule-based tracker detection - no ML needed"""
    
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
    ]
    
    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold
        self._cache: Dict[str, Tuple[float, List[str]]] = {}
        self._patterns = [(re.compile(p, re.I), r, c) for p, r, c in self.TRACKER_PATTERNS]
    
    def analyze(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze domain, returns (confidence, reasons)"""
        domain_lower = domain.lower()
        
        if domain_lower in self._cache:
            return self._cache[domain_lower]
        
        confidence = 0.0
        reasons = []
        
        for pattern, reason, base_conf in self._patterns:
            if pattern.search(domain_lower):
                confidence = max(confidence, base_conf)
                reasons.append(reason)
        
        # Heuristic: many subdomains = suspicious
        if not reasons and domain_lower.count('.') > 4:
            confidence = 0.60
            reasons.append('many_subdomains')
        
        result = (min(confidence, 1.0), reasons)
        
        if len(self._cache) < Constants.AI_CACHE_SIZE:
            self._cache[domain_lower] = result
        
        return result


# ============================================================================
# SOURCE PARSERS
# ============================================================================

def parse_hosts(content: str) -> Set[str]:
    """Parse hosts file format"""
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


def parse_domains(content: str) -> Set[str]:
    """Parse plain domains list"""
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
# SOURCE MANAGER
# ============================================================================

class SourceManager:
    SOURCES: List[SourceDefinition] = [
        SourceDefinition('StevenBlack', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', SourceType.HOSTS),
        SourceDefinition('OISD', 'https://big.oisd.nl/domains', SourceType.DOMAINS),
        SourceDefinition('AdAway', 'https://adaway.org/hosts.txt', SourceType.HOSTS),
        SourceDefinition('URLhaus', 'https://urlhaus.abuse.ch/downloads/hostfile/', SourceType.HOSTS),
        SourceDefinition('ThreatFox', 'https://threatfox.abuse.ch/downloads/hostfile/', SourceType.HOSTS),
        SourceDefinition('CERT.PL', 'https://hole.cert.pl/domains/domains_hosts.txt', SourceType.HOSTS),
    ]
    
    def __init__(self, config: Config, session: aiohttp.ClientSession):
        self.config = config
        self.session = session
        self.logger = logging.getLogger(__name__)
        self.ssrf = SSRFProtector()
    
    async def fetch_all(self) -> Dict[str, Set[str]]:
        """Fetch all enabled sources"""
        tasks = []
        for source in self.SOURCES:
            if source.enabled:
                tasks.append(self._fetch_with_retry(source))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domains_by_source = {}
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Source failed: {result}")
            elif result:
                name, domains = result
                domains_by_source[name] = domains
        
        return domains_by_source
    
    async def _fetch_with_retry(self, source: SourceDefinition) -> Tuple[str, Set[str]]:
        """Fetch source with retries and security checks"""
        for attempt in range(self.config.max_retries):
            try:
                # SSRF validation
                await self.ssrf.validate_url(source.url, self.session)
                
                # Download with size limits
                content = await self._download_safe(source.url)
                
                # Parse
                if source.source_type == SourceType.HOSTS:
                    domains = parse_hosts(content)
                else:
                    domains = parse_domains(content)
                
                self.logger.info(f"✅ {source.name}: {len(domains):,} domains")
                return source.name, domains
                
            except Exception as e:
                self.logger.warning(f"⚠️ {source.name} attempt {attempt+1}: {e}")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
        
        raise Exception(f"Failed after {self.config.max_retries} attempts")
    
    async def _download_safe(self, url: str) -> str:
        """Download with size limits (zip-bomb protection)"""
        async with self.session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            headers={'User-Agent': Constants.USER_AGENT}
        ) as resp:
            if resp.status != 200:
                raise Exception(f"HTTP {resp.status}")
            
            # Check content length
            content_length = resp.headers.get('Content-Length')
            if content_length and int(content_length) > Constants.MAX_FILE_SIZE_MB * 1024 * 1024:
                raise Exception(f"File too large: {int(content_length) / 1024 / 1024:.1f}MB")
            
            # Stream with limit
            data = bytearray()
            async for chunk in resp.content.iter_chunked(8192):
                data.extend(chunk)
                if len(data) > Constants.MAX_DECOMPRESSED_MB * 1024 * 1024:
                    raise Exception("Decompressed size limit exceeded (zip-bomb protection)")
            
            return data.decode('utf-8', errors='ignore')


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    def __init__(self, config: Config, validator: DomainValidator, ai: Optional[AITrackerDetector] = None):
        self.config = config
        self.validator = validator
        self.ai = ai
        self.logger = logging.getLogger(__name__)
        self.domains: Dict[str, DomainRecord] = {}
        self.ai_added = 0
        self.stats = {'total': 0, 'valid': 0, 'invalid': 0, 'duplicate': 0}
    
    async def process_sources(self, domains_by_source: Dict[str, Set[str]]) -> None:
        """Process all fetched domains"""
        self.stats['total'] = sum(len(d) for d in domains_by_source.values())
        self.logger.info(f"Processing {self.stats['total']:,} raw domains...")
        
        start = time.time()
        
        # First pass: validation and dedup
        for source_name, domains in domains_by_source.items():
            for domain in domains:
                if not self.validator.is_valid(domain):
                    self.stats['invalid'] += 1
                    continue
                
                if domain in self.domains:
                    self.stats['duplicate'] += 1
                    continue
                
                self.domains[domain] = DomainRecord(
                    domain=domain,
                    source=source_name,
                    status=DomainStatus.VALID
                )
                self.stats['valid'] += 1
        
        # Second pass: AI detection (if enabled)
        if self.ai and self.config.ai_enabled:
            await self._ai_analysis()
        
        # Apply max domains limit
        if len(self.domains) > self.config.max_domains:
            self.logger.warning(f"Truncating to {self.config.max_domains:,} domains")
            self.domains = dict(list(self.domains.items())[:self.config.max_domains])
        
        self.logger.info(f"✅ Final: {len(self.domains):,} unique domains (AI: {self.ai_added:,})")
        self.logger.info(f"⏱️ Processing time: {time.time() - start:.2f}s")
    
    async def _ai_analysis(self) -> None:
        """Run AI detection on all domains"""
        self.logger.info("🤖 Running AI tracker detection...")
        
        total = len(self.domains)
        processed = 0
        
        for domain, record in list(self.domains.items()):
            confidence, reasons = self.ai.analyze(domain)
            processed += 1
            
            if processed % 10000 == 0:
                self.logger.info(f"   AI progress: {processed}/{total} ({processed*100//total}%)")
            
            if confidence >= self.config.ai_confidence_threshold:
                new_record = DomainRecord(
                    domain=record.domain,
                    source=f"{record.source}+ai",
                    status=DomainStatus.AI_DETECTED,
                    ai_confidence=confidence,
                    ai_reasons=tuple(reasons[:2])
                )
                self.domains[domain] = new_record
                self.ai_added += 1
        
        self.logger.info(f"✅ AI complete: {self.ai_added:,} trackers detected")
    
    def get_records(self) -> List[DomainRecord]:
        return list(self.domains.values())


# ============================================================================
# OUTPUT GENERATOR
# ============================================================================

class OutputGenerator:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def generate(self, records: List[DomainRecord]) -> Path:
        """Generate output file atomically"""
        output_path = self.config.output_path
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        backup_path = output_path.with_suffix(Constants.BACKUP_SUFFIX)
        
        ai_count = sum(1 for r in records if r.ai_confidence > 0)
        
        try:
            # Write to temp file
            with open(tmp_path, 'w', encoding='utf-8') as f:
                f.write(f"# DNS Security Blocklist v{VERSION}\n")
                f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"# Total domains: {len(records):,}\n")
                f.write(f"# AI-detected: {ai_count:,}\n")
                f.write("#\n\n")
                
                for record in records:
                    if self.config.output_format == 'hosts':
                        f.write(record.to_hosts_entry() + "\n")
                    else:
                        f.write(record.domain + "\n")
                
                f.flush()
                os.fsync(f.fileno())
            
            # Create backup
            if output_path.exists():
                shutil.copy2(output_path, backup_path)
            
            # Atomic move
            shutil.move(str(tmp_path), str(output_path))
            
            self.logger.info(f"✅ Generated: {output_path} ({len(records):,} domains, {ai_count:,} AI)")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Failed: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise


# ============================================================================
# MAIN BUILDER
# ============================================================================

class BlocklistBuilder:
    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._shutdown = asyncio.Event()
    
    def _setup_signals(self):
        def handler(sig, frame):
            self.logger.info("Shutting down...")
            self._shutdown.set()
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    
    async def run(self) -> int:
        self._setup_signals()
        
        try:
            print("=" * 60)
            print(f"🔒 DNS Security Blocklist Builder v{VERSION}")
            print(f"🤖 AI: {'ON' if self.config.ai_enabled else 'OFF'}")
            print(f"📁 Output: {self.config.output_path}")
            print("=" * 60)
            
            # Setup components
            connector = aiohttp.TCPConnector(limit=self.config.concurrent_downloads)
            async with aiohttp.ClientSession(connector=connector) as session:
                validator = DomainValidator()
                ai = AITrackerDetector(self.config.ai_confidence_threshold) if self.config.ai_enabled else None
                source_manager = SourceManager(self.config, session)
                processor = DomainProcessor(self.config, validator, ai)
                output_gen = OutputGenerator(self.config)
                
                # Fetch sources
                print("\n📡 Fetching sources...")
                domains_by_source = await source_manager.fetch_all()
                
                if not domains_by_source:
                    self.logger.error("No sources fetched")
                    return 1
                
                # Process domains
                await processor.process_sources(domains_by_source)
                
                records = processor.get_records()
                if not records:
                    self.logger.error("No valid domains")
                    return 1
                
                # Generate output
                await output_gen.generate(records)
                
                print("\n" + "=" * 60)
                print("✅ BUILD COMPLETE")
                print("=" * 60)
                return 0
                
        except asyncio.CancelledError:
            return 130
        except Exception as e:
            self.logger.error(f"Build failed: {e}", exc_info=self.config.verbose)
            return 1


# ============================================================================
# MAIN
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description=f'DNS Security Blocklist Builder v{VERSION}')
    parser.add_argument('-o', '--output', type=Path, help='Output file path')
    parser.add_argument('--format', choices=['hosts', 'domains'], default='hosts')
    parser.add_argument('--max-domains', type=int, help='Maximum domains')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI detection')
    parser.add_argument('--ai-confidence', type=float, default=0.65, help='AI threshold (0-1)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    return parser.parse_args()


async def async_main():
    args = parse_args()
    
    config = Config()
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
        config.verbose = True
    
    setup_logging(config.verbose)
    
    builder = BlocklistBuilder(config)
    return await builder.run()


def main():
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
