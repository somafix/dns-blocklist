#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - PRODUCTION READY (v9.2.1)
FIXED: ClientResponse.session compatibility
"""

import sys
import asyncio
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
from typing import Set, Dict, List, Optional, Tuple, ClassVar, Final, Any
from urllib.parse import urlparse
import ipaddress
from collections import deque

import aiohttp
from aiohttp import ClientTimeout, ClientResponse
import aiofiles

VERSION: Final[str] = "9.2.1"

# ============================================================================
# CONSTANTS
# ============================================================================

class Constants:
    MAX_DOMAIN_LEN: int = 253
    MAX_LABEL_LEN: int = 63
    MIN_DOMAIN_LEN: int = 3
    
    TEMP_SUFFIX: str = '.tmp'
    BACKUP_SUFFIX: str = '.backup'
    BATCH_WRITE_SIZE: int = 65536
    
    MAX_CONCURRENT_DOWNLOADS: int = 5
    DEFAULT_TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    RETRY_BACKOFF: float = 1.5
    MAX_FILE_SIZE_MB: int = 50
    
    DNS_CACHE_SIZE: int = 100000
    AI_CACHE_SIZE: int = 100000
    AI_BATCH_SIZE: int = 1000
    
    ALLOWED_SCHEMES: Set[str] = {'http', 'https'}
    BLOCKED_IP_RANGES: Tuple[str, ...] = (
        '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
        '::1/128', 'fc00::/7', 'fe80::/10'
    )
    ALLOWED_DOMAINS: Set[str] = {
        'raw.githubusercontent.com', 'oisd.nl', 'adaway.org',
        'urlhaus.abuse.ch', 'threatfox.abuse.ch', 'hole.cert.pl'
    }
    
    RESERVED_TLDS: Set[str] = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa', 'onion', 'i2p'
    }
    
    USER_AGENT: str = f'Mozilla/5.0 (compatible; DNS-Blocklist-Builder/{VERSION})'
    AI_CONFIDENCE_THRESHOLD: float = 0.65
    SUSPICIOUS_SUBDOMAIN_DEPTH: int = 4


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
        safe_domain = re.sub(r'[\n\r\t\v\f]', '', self.domain)
        safe_reasons = tuple(r.replace(',', '\\,') for r in self.ai_reasons[:2])
        
        if self.ai_confidence > 0:
            reasons = ','.join(safe_reasons)
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
    output_dynamic: Path = Path('./dynamic-blocklist.txt')
    output_simple: Path = Path('./blocklist.txt')
    output_format: str = 'hosts'
    max_domains: int = 500000
    timeout: int = Constants.DEFAULT_TIMEOUT
    max_retries: int = Constants.MAX_RETRIES
    concurrent_downloads: int = Constants.MAX_CONCURRENT_DOWNLOADS
    ai_enabled: bool = True
    ai_confidence_threshold: float = 0.65
    verbose: bool = False


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )


# ============================================================================
# SSRF PROTECTION (FIXED)
# ============================================================================

class SSRFProtector:
    def __init__(self, session: aiohttp.ClientSession) -> None:
        self.session = session
        self._blocked_networks = [ipaddress.ip_network(net) for net in Constants.BLOCKED_IP_RANGES]
        self._checked_urls: Set[str] = set()
    
    async def validate_url(self, url: str) -> None:
        normalized = self._normalize_url(url)
        if normalized in self._checked_urls:
            return
        
        parsed = urlparse(normalized)
        
        if parsed.scheme not in Constants.ALLOWED_SCHEMES:
            raise ValueError(f"Scheme not allowed: {parsed.scheme}")
        
        if parsed.hostname not in Constants.ALLOWED_DOMAINS:
            ips = await self._resolve_hostname(parsed.hostname)
            for ip in ips:
                self._check_ip_allowed(ip)
        
        self._checked_urls.add(normalized)
    
    async def validate_response(self, response: ClientResponse, final_url: str) -> None:
        await self.validate_url(final_url)
    
    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        normalized = parsed._replace(netloc=parsed.hostname or '', fragment='')
        return normalized.geturl()
    
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        loop = asyncio.get_event_loop()
        try:
            ips = await loop.getaddrinfo(hostname, None, family=0, type=0, proto=0)
            return list(set(ip[4][0] for ip in ips))
        except Exception as e:
            raise ValueError(f"DNS resolution failed for {hostname}: {e}")
    
    def _check_ip_allowed(self, ip_str: str) -> None:
        ip = ipaddress.ip_address(ip_str)
        for blocked_net in self._blocked_networks:
            if ip in blocked_net:
                raise ValueError(f"IP {ip} is in blocked range {blocked_net}")


# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

class DomainValidator:
    DOMAIN_PATTERN: ClassVar[re.Pattern] = re.compile(
        r'^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63}(?<!-))*$',
        re.IGNORECASE
    )
    
    def __init__(self) -> None:
        self._cache: Dict[str, bool] = {}
        self._cache_order: deque = deque(maxlen=Constants.DNS_CACHE_SIZE)
    
    def is_valid(self, domain: str) -> bool:
        domain_lower = domain.lower().strip()
        
        if domain_lower in self._cache:
            return self._cache[domain_lower]
        
        valid = self._validate_syntax(domain_lower)
        
        if len(self._cache) >= Constants.DNS_CACHE_SIZE:
            oldest = self._cache_order.popleft()
            self._cache.pop(oldest, None)
        
        self._cache[domain_lower] = valid
        self._cache_order.append(domain_lower)
        
        return valid
    
    def _validate_syntax(self, domain: str) -> bool:
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
# AI TRACKER DETECTOR
# ============================================================================

class AITrackerDetector:
    TRACKER_PATTERNS: ClassVar[Tuple[Tuple[str, str, float], ...]] = (
        (r'analytics?', 'analytics', 0.82),
        (r'google-analytics', 'google_analytics', 0.95),
        (r'googletagmanager|gtm', 'google_tag_manager', 0.92),
        (r'track(?:ing)?', 'tracking', 0.80),
        (r'pixel', 'tracking_pixel', 0.85),
        (r'beacon', 'tracking_beacon', 0.85),
        (r'collect', 'data_collector', 0.80),
        (r'telemetry', 'telemetry', 0.85),
        (r'metrics', 'metrics', 0.78),
        (r'stat(?:s|istic)?', 'statistics', 0.75),
        (r'doubleclick', 'doubleclick', 0.95),
        (r'adservice', 'ad_service', 0.85),
        (r'ads?\.', 'ad_domain', 0.75),
        (r'amplitude', 'amplitude', 0.90),
        (r'mixpanel', 'mixpanel', 0.90),
        (r'segment\.com', 'segment', 0.90),
        (r'appsflyer', 'appsflyer', 0.90),
        (r'facebook\.com/tr', 'facebook_pixel', 0.95),
        (r'twitter\.com/i', 'twitter_tracker', 0.82),
    )
    
    def __init__(self, threshold: float = Constants.AI_CONFIDENCE_THRESHOLD) -> None:
        self.threshold = threshold
        self._cache: Dict[str, Tuple[float, Tuple[str, ...]]] = {}
        self._patterns = [(re.compile(p, re.I), r, c) for p, r, c in self.TRACKER_PATTERNS]
    
    def analyze(self, domain: str) -> Tuple[float, Tuple[str, ...]]:
        domain_lower = domain.lower()
        
        if domain_lower in self._cache:
            return self._cache[domain_lower]
        
        confidence = 0.0
        reasons = []
        
        for pattern, reason, base_conf in self._patterns:
            if pattern.search(domain_lower):
                confidence = max(confidence, base_conf)
                reasons.append(reason)
        
        if not reasons and domain_lower.count('.') > Constants.SUSPICIOUS_SUBDOMAIN_DEPTH:
            confidence = 0.60
            reasons.append('many_subdomains')
        
        confidence = min(confidence, 1.0)
        result = (confidence, tuple(reasons[:3]))
        
        if len(self._cache) < Constants.AI_CACHE_SIZE:
            self._cache[domain_lower] = result
        
        return result


# ============================================================================
# SOURCE PARSERS
# ============================================================================

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
# SOURCE MANAGER (FIXED)
# ============================================================================

class SourceManager:
    SOURCES: ClassVar[List[SourceDefinition]] = [
        SourceDefinition('StevenBlack', 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', SourceType.HOSTS),
        SourceDefinition('OISD', 'https://big.oisd.nl/domains', SourceType.DOMAINS),
        SourceDefinition('AdAway', 'https://adaway.org/hosts.txt', SourceType.HOSTS),
        SourceDefinition('URLhaus', 'https://urlhaus.abuse.ch/downloads/hostfile/', SourceType.HOSTS),
        SourceDefinition('ThreatFox', 'https://threatfox.abuse.ch/downloads/hostfile/', SourceType.HOSTS),
        SourceDefinition('CERT.PL', 'https://hole.cert.pl/domains/domains_hosts.txt', SourceType.HOSTS),
    ]
    
    def __init__(self, config: Config, session: aiohttp.ClientSession) -> None:
        self.config = config
        self.session = session
        self.logger = logging.getLogger(__name__)
        self.ssrf = SSRFProtector(session)
    
    async def fetch_all(self) -> Dict[str, Set[str]]:
        tasks = [self._fetch_with_retry(s) for s in self.SOURCES if s.enabled]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        domains_by_source = {}
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Source failed: {result}")
            elif result is not None:
                name, domains = result
                domains_by_source[name] = domains
        
        return domains_by_source
    
    async def _fetch_with_retry(self, source: SourceDefinition) -> Optional[Tuple[str, Set[str]]]:
        for attempt in range(self.config.max_retries):
            try:
                await self.ssrf.validate_url(source.url)
                content = await self._download_safe(source.url)
                
                if source.source_type == SourceType.HOSTS:
                    domains = parse_hosts(content)
                else:
                    domains = parse_domains(content)
                
                self.logger.info(f"✅ {source.name}: {len(domains):,} domains")
                return source.name, domains
                
            except Exception as e:
                self.logger.warning(f"⚠️ {source.name} attempt {attempt + 1}: {e}")
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(Constants.RETRY_BACKOFF ** attempt)
        
        return None
    
    async def _download_safe(self, url: str) -> str:
        max_bytes = Constants.MAX_FILE_SIZE_MB * 1024 * 1024
        
        async with self.session.get(
            url,
            timeout=ClientTimeout(total=self.config.timeout),
            headers={'User-Agent': Constants.USER_AGENT},
            max_redirects=5
        ) as resp:
            final_url = str(resp.url)
            await self.ssrf.validate_response(resp, final_url)
            
            if resp.status != 200:
                raise Exception(f"HTTP {resp.status}")
            
            data = bytearray()
            async for chunk in resp.content.iter_chunked(8192):
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise Exception("Size limit exceeded")
            
            return data.decode('utf-8', errors='ignore')


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    def __init__(self, config: Config, validator: DomainValidator, ai_detector: Optional[AITrackerDetector] = None) -> None:
        self.config = config
        self.validator = validator
        self.ai_detector = ai_detector
        self.logger = logging.getLogger(__name__)
        self.domains: Dict[str, DomainRecord] = {}
        self.ai_added: int = 0
    
    async def process_sources(self, domains_by_source: Dict[str, Set[str]]) -> None:
        total_raw = sum(len(d) for d in domains_by_source.values())
        self.logger.info(f"Processing {total_raw:,} raw domains...")
        
        for source_name, domains in domains_by_source.items():
            for domain in domains:
                if not self.validator.is_valid(domain):
                    continue
                if domain in self.domains:
                    continue
                
                self.domains[domain] = DomainRecord(
                    domain=domain,
                    source=source_name,
                    status=DomainStatus.VALID
                )
        
        if self.ai_detector and self.config.ai_enabled:
            await self._ai_analysis_batch()
        
        if len(self.domains) > self.config.max_domains:
            self.logger.warning(f"Truncating to {self.config.max_domains:,} domains")
            items = list(self.domains.items())[:self.config.max_domains]
            self.domains = dict(items)
        
        self.logger.info(f"✅ Final: {len(self.domains):,} unique domains (AI: {self.ai_added:,})")
    
    async def _ai_analysis_batch(self) -> None:
        self.logger.info("🤖 Running AI tracker detection...")
        
        domains_list = list(self.domains.keys())
        total = len(domains_list)
        
        for batch_start in range(0, total, Constants.AI_BATCH_SIZE):
            batch_end = min(batch_start + Constants.AI_BATCH_SIZE, total)
            batch = domains_list[batch_start:batch_end]
            
            for domain in batch:
                confidence, reasons = self.ai_detector.analyze(domain)
                if confidence >= self.config.ai_confidence_threshold:
                    old = self.domains[domain]
                    self.domains[domain] = DomainRecord(
                        domain=old.domain,
                        source=f"{old.source}+ai",
                        status=DomainStatus.AI_DETECTED,
                        ai_confidence=confidence,
                        ai_reasons=reasons
                    )
                    self.ai_added += 1
            
            await asyncio.sleep(0)
        
        self.logger.info(f"✅ AI complete: {self.ai_added:,} trackers detected")
    
    def get_records(self) -> List[DomainRecord]:
        return list(self.domains.values())


# ============================================================================
# OUTPUT GENERATOR
# ============================================================================

class OutputGenerator:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def generate(self, records: List[DomainRecord]) -> None:
        await self._generate_hosts_file(records, self.config.output_dynamic)
        await self._generate_simple_domains(records, self.config.output_simple)
        self.logger.info(f"✅ Generated: {self.config.output_dynamic} and {self.config.output_simple}")
    
    async def _generate_hosts_file(self, records: List[DomainRecord], output_path: Path) -> None:
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        backup_path = output_path.with_suffix(Constants.BACKUP_SUFFIX)
        ai_count = sum(1 for r in records if r.ai_confidence > 0)
        
        try:
            async with aiofiles.open(tmp_path, 'w', encoding='utf-8', buffering=Constants.BATCH_WRITE_SIZE) as f:
                await f.write(f"# DNS Security Blocklist v{VERSION}\n")
                await f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                await f.write(f"# Total domains: {len(records):,}\n")
                await f.write(f"# AI-detected: {ai_count:,}\n")
                await f.write("#\n\n")
                
                batch = []
                for record in records:
                    batch.append(record.to_hosts_entry() + "\n")
                    if len(batch) >= 1000:
                        await f.write(''.join(batch))
                        batch = []
                if batch:
                    await f.write(''.join(batch))
            
            if output_path.exists():
                shutil.copy2(output_path, backup_path)
            shutil.move(str(tmp_path), str(output_path))
            self.logger.info(f"   📄 {output_path}: {len(records):,} domains, {ai_count:,} AI")
            
        except Exception as e:
            self.logger.error(f"Failed to generate {output_path}: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise
    
    async def _generate_simple_domains(self, records: List[DomainRecord], output_path: Path) -> None:
        tmp_path = output_path.with_suffix(Constants.TEMP_SUFFIX)
        
        try:
            async with aiofiles.open(tmp_path, 'w', encoding='utf-8', buffering=Constants.BATCH_WRITE_SIZE) as f:
                batch = []
                for record in records:
                    batch.append(record.domain + "\n")
                    if len(batch) >= 1000:
                        await f.write(''.join(batch))
                        batch = []
                if batch:
                    await f.write(''.join(batch))
            
            shutil.move(str(tmp_path), str(output_path))
            self.logger.info(f"   📄 {output_path}: {len(records):,} domains")
            
        except Exception as e:
            self.logger.error(f"Failed to generate {output_path}: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise


# ============================================================================
# MAIN BUILDER
# ============================================================================

class BlocklistBuilder:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._shutdown = asyncio.Event()
    
    def _setup_signals(self) -> None:
        def handler(sig: int, frame: Any) -> None:
            self.logger.info("Shutdown signal received, stopping...")
            self._shutdown.set()
        
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)
    
    async def run(self) -> int:
        self._setup_signals()
        
        try:
            print("=" * 60)
            print(f"🔒 DNS Security Blocklist Builder v{VERSION}")
            print(f"🤖 AI: {'ON' if self.config.ai_enabled else 'OFF'}")
            print(f"📁 Output: {self.config.output_dynamic} + {self.config.output_simple}")
            print("=" * 60)
            
            connector = aiohttp.TCPConnector(
                limit=self.config.concurrent_downloads,
                ttl_dns_cache=300,
                ssl=True
            )
            
            async with aiohttp.ClientSession(connector=connector) as session:
                validator = DomainValidator()
                ai_detector = AITrackerDetector(self.config.ai_confidence_threshold) if self.config.ai_enabled else None
                
                source_manager = SourceManager(self.config, session)
                processor = DomainProcessor(self.config, validator, ai_detector)
                output_gen = OutputGenerator(self.config)
                
                print("\n📡 Fetching sources...")
                domains_by_source = await source_manager.fetch_all()
                
                if not domains_by_source:
                    self.logger.error("No sources fetched successfully")
                    return 1
                
                await processor.process_sources(domains_by_source)
                
                records = processor.get_records()
                if not records:
                    self.logger.error("No valid domains after processing")
                    return 1
                
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
# MAIN ENTRY POINT
# ============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f'DNS Security Blocklist Builder v{VERSION}')
    parser.add_argument('--output-dynamic', type=Path, default=Path('./dynamic-blocklist.txt'), help='Output path for hosts file')
    parser.add_argument('--output-simple', type=Path, default=Path('./blocklist.txt'), help='Output path for simple domains')
    parser.add_argument('--max-domains', type=int, help='Maximum domains to process')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI detection')
    parser.add_argument('--ai-confidence', type=float, default=0.65, help='AI confidence threshold')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    return parser.parse_args()


async def async_main() -> int:
    args = parse_args()
    
    config = Config()
    config.output_dynamic = args.output_dynamic
    config.output_simple = args.output_simple
    if args.max_domains:
        config.max_domains = args.max_domains
    if args.no_ai:
        config.ai_enabled = False
    if args.ai_confidence:
        config.ai_confidence_threshold = args.ai_confidence
    config.verbose = args.verbose
    
    setup_logging(config.verbose)
    
    builder = BlocklistBuilder(config)
    return await builder.run()


def main() -> int:
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        return 130


if __name__ == "__main__":
    sys.exit(main())
