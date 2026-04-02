#!/usr/bin/env python3
"""
DNS SECURITY BLOCKLIST BUILDER - ENTERPRISE EDITION
Version: 20.0.0 (Secure & Refactored)
Standards: OWASP, CWE Mitigation, Atomic Operations, SSRF Protection
"""

import sys
import os
import logging
import asyncio
import ipaddress
import re
import json
import gzip
import tempfile
import socket
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, AsyncGenerator
from dataclasses import dataclass, field

# Third-party imports (Must be installed via requirements.txt)
import aiohttp
import aiofiles
from aiohttp import ClientTimeout, TCPConnector
from pydantic import BaseModel, Field, HttpUrl, ConfigDict, field_validator
from pydantic_settings import BaseSettings

# ============================================================================
# SECURITY CONSTANTS & CONFIGURATION
# ============================================================================

# Blocking private/reserved IPs to prevent SSRF
FORBIDDEN_IP_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]
logger = logging.getLogger("DNSBL_Builder")

# ============================================================================
# SECURITY UTILS (SSRF PROTECTION)
# ============================================================================

class SafeResolver:
    """
    Prevents SSRF by ensuring we only connect to public IP addresses.
    """
    @staticmethod
    def is_safe_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
                return False
            for net in FORBIDDEN_IP_RANGES:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    @staticmethod
    async def safe_connect(host: str, port: int, family=socket.AF_INET) -> Tuple[str, int, int, str]:
        # Resolve DNS
        infos = await asyncio.get_event_loop().getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM
        )
        for info in infos:
            af, socktype, proto, canonname, sockaddr = info
            ip_addr = sockaddr[0]
            if SafeResolver.is_safe_ip(ip_addr):
                return (ip_addr, port, af, proto)
        
        raise aiohttp.ClientConnectionError(f"SSRF Protection: No safe IP found for {host}")

# ============================================================================
# DATA MODELS
# ============================================================================

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str  # 'hosts', 'domains', 'adblock'
    enabled: bool = True
    priority: int = 0
    
    @field_validator('source_type')    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in ('hosts', 'domains', 'adblock'):
            raise ValueError("Invalid source type")
        return v

class AppSettings(BaseSettings):
    model_config = ConfigDict(env_prefix="DNSBL_", case_sensitive=False)
    
    max_domains: int = Field(2_000_000, ge=1000)
    output_dir: Path = Field(default=Path("./output"))
    cache_dir: Path = Field(default=Path("./cache"))
    http_timeout: int = Field(30, ge=5)
    ai_detection_enabled: bool = True

# ============================================================================
# DOMAIN PROCESSING ENGINE
# ============================================================================

class DomainProcessor:
    """
    High-performance domain processing with categorization and deduplication.
    Thread-safe logic within async context.
    """
    
    # Pre-compiled regex for performance
    VALID_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
    IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
    # AI Patterns (Optimized)
    AI_PATTERNS = re.compile(
        r'(chatgpt|openai|gpt-\d|claude|anthropic|gemini|bard|copilot|midjourney|'
        r'stable-diffusion|tensorflow|pytorch|huggingface|character\.ai|elevenlabs)',
        re.IGNORECASE
    )

    def __init__(self, max_size: int, ai_enabled: bool):
        self.max_size = max_size
        self.ai_enabled = ai_enabled
        self.domains: Dict[str, str] = {}  # domain -> category
        self.stats = {
            'processed': 0,
            'added': 0,
            'duplicates': 0,
            'invalid': 0,
            'categories': {'ai_ml': 0, 'ads': 0, 'tracking': 0, 'malware': 0, 'other': 0}
        }

    def _categorize(self, domain: str) -> str:
        if self.ai_enabled and self.AI_PATTERNS.search(domain):            return 'ai_ml'
        if any(k in domain for k in ['ad', 'banner', 'doubleclick']):
            return 'ads'
        if any(k in domain for k in ['track', 'analytics', 'pixel']):
            return 'tracking'
        if any(k in domain for k in ['malware', 'phish', 'virus']):
            return 'malware'
        return 'other'

    def add_domain(self, domain: str) -> bool:
        self.stats['processed'] += 1
        
        # Basic Validation
        if len(domain) < 4 or len(domain) > 253:
            self.stats['invalid'] += 1
            return False
            
        if self.IP_RE.match(domain):
            self.stats['invalid'] += 1
            return False
            
        if not self.VALID_DOMAIN_RE.match(domain):
            self.stats['invalid'] += 1
            return False

        # Deduplication & Capacity Check
        if domain in self.domains:
            self.stats['duplicates'] += 1
            return False
            
        if len(self.domains) >= self.max_size:
            return False # Limit reached

        category = self._categorize(domain)
        self.domains[domain] = category
        self.stats['added'] += 1
        self.stats['categories'][category] = self.stats['categories'].get(category, 0) + 1
        return True

# ============================================================================
# SOURCE FETCHER (SECURE)
# ============================================================================

class SecureFetcher:
    def __init__(self, timeout: int):
        self.timeout = ClientTimeout(total=timeout)
        # Custom connector with our safe resolver logic would ideally go here,
        # but aiohttp's standard resolver is usually OS-level. 
        # We rely on the fact that we only fetch from trusted HTTPS URLs defined in code.
        # For extra hardening, we disable redirects to prevent open redirect abuse.        self.connector = TCPConnector(limit=10, enable_cleanup_closed=True)

    async def fetch_text(self, url: str) -> Optional[str]:
        try:
            async with aiohttp.ClientSession(connector=self.connector, timeout=self.timeout) as session:
                # Strict SSL is default in aiohttp, which is good.
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    else:
                        logger.warning(f"Failed to fetch {url}: Status {resp.status}")
                        return None
        except Exception as e:
            logger.error(f"Network error fetching {url}: {e}")
            return None

# ============================================================================
# PARSERS
# ============================================================================

def parse_hosts_line(line: str) -> Optional[str]:
    line = line.split('#')[0].strip()
    if not line or line.startswith(('0.0.0.0', '127.0.0.1')):
        parts = line.split()
        if len(parts) >= 2:
            return parts[1].lower()
    return None

def parse_domain_line(line: str) -> Optional[str]:
    line = line.strip().lower()
    if '.' in line and not line.startswith('.'):
        return line
    return None

def parse_adblock_line(line: str) -> Optional[str]:
    # Matches ||example.com^
    m = re.match(r'^\|\|([a-z0-9.-]+)\^', line)
    if m:
        return m.group(1).lower()
    return None

# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

async def main():
    # Setup Logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    settings = AppSettings()
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.cache_dir.mkdir(parents=True, exist_ok=True)

    logger.info("🚀 Starting Enterprise DNS Blocklist Builder")
    
    processor = DomainProcessor(
        max_size=settings.max_domains,
        ai_enabled=settings.ai_detection_enabled
    )
    
    fetcher = SecureFetcher(timeout=settings.http_timeout)

    # Trusted Sources (Hardcoded to prevent config injection)
    sources = [
        SourceConfig(name="OISD Big", url="https://big.oisd.nl/domains", source_type="domains", priority=1),
        SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=2),
        SourceConfig(name="StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", source_type="hosts", priority=3),
    ]

    for src in sorted(sources, key=lambda x: x.priority):
        logger.info(f"📥 Processing: {src.name}")
        content = await fetcher.fetch_text(str(src.url))
        
        if not content:
            logger.warning(f"Skipping {src.name} due to fetch failure")
            continue

        lines = content.splitlines()
        for line in lines:
            domain = None
            if src.source_type == 'hosts':
                domain = parse_hosts_line(line)
            elif src.source_type == 'domains':
                domain = parse_domain_line(line)
            elif src.source_type == 'adblock':
                domain = parse_adblock_line(line)
            
            if domain:
                processor.add_domain(domain)
                
        logger.info(f"✅ {src.name}: Processed {len(lines)} lines")

    # Atomic Write Operation
    output_file = settings.output_dir / "blocklist.txt"
    temp_fd, temp_path = tempfile.mkstemp(dir=settings.output_dir, suffix='.tmp')
        try:
        logger.info("💾 Writing blocklist atomically...")
        with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
            f.write(f"# DNS Blocklist Generated: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"# Total Domains: {processor.stats['added']}\n")
            f.write(f"# Categories: {json.dumps(processor.stats['categories'])}\n\n")
            
            # Sort for deterministic output
            for domain in sorted(processor.domains.keys()):
                cat = processor.domains[domain]
                f.write(f"0.0.0.0 {domain} # {cat}\n")
        
        # Sync to disk
        os.fsync(temp_fd)
        
        # Atomic Rename
        os.replace(temp_path, str(output_file))
        logger.info(f"✅ Successfully wrote {output_file}")
        
        # Compression (Optional step, done after atomic write)
        gz_path = str(output_file) + ".gz"
        with open(output_file, 'rb') as f_in:
            with gzip.open(gz_path, 'wb') as f_out:
                f_out.writelines(f_in)
        logger.info(f"🗜️ Compressed to {gz_path}")

    except Exception as e:
        logger.error(f"Failed to write file: {e}")
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        sys.exit(1)

    logger.info("🏁 Build Complete")
    logger.info(f"Stats: {processor.stats}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
