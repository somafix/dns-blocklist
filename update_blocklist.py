#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - Enterprise Edition
Version: 2.0.1
Standards: PEP 8, Type Hinting, SOLID, OWASP Secure Coding Practices
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
import sys
import tempfile
import gzip
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Set, Tuple

import aiofiles
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector, ClientRequest
from pydantic import BaseModel, Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ============================================================================
# CONFIGURATION & LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("DNSBL_Builder")


class AppSettings(BaseSettings):
    """Application configuration with environment variable support."""
    model_config = SettingsConfigDict(env_prefix="DNSBL_", case_sensitive=False)

    output_dir: Path = Field(default=Path("./output"))
    cache_dir: Path = Field(default=Path("./cache"))
    max_domains: int = Field(default=2_000_000, ge=1000)
    http_timeout: int = Field(default=30, ge=5)
    max_concurrent_requests: int = Field(default=5, ge=1, le=20)
    
    # Security Flags
    enable_ai_detection: bool = Field(default=True)
    strict_ssl: bool = Field(default=True)


# ============================================================================
# SECURITY UTILS (SSRF PROTECTION)
# ============================================================================

class SafeResolver:
    """
    Prevents SSRF by ensuring connections are only made to public IPs.
    Blocks RFC1918, loopback, link-local, and reserved addresses.
    """
    PRIVATE_IPS = [
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

    @classmethod
    def is_safe_ip(cls, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
                return False
            for net in cls.PRIVATE_IPS:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    @classmethod
    async def resolve_host(cls, host: str, port: int = 80) -> Tuple[str, int]:
        """Resolve hostname and return first safe IP."""
        try:
            infos = await asyncio.get_event_loop().getaddrinfo(
                host, port, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
            for info in infos:
                ip_addr = info[4][0]
                if cls.is_safe_ip(ip_addr):
                    return ip_addr, port
            raise aiohttp.ClientConnectionError(f"SSRF Protection: No public IP found for {host}")
        except Exception as e:
            raise aiohttp.ClientConnectionError(f"DNS Resolution failed for {host}: {e}")


class SafeTCPConnector(TCPConnector):
    """Custom connector that enforces SSRF protection."""
    async def connect(self, req: ClientRequest, traces, timeout):
        host = req.host
        
        # Check if this is an IP address or domain
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
        
        if not is_ip:
            try:
                safe_ip, safe_port = await SafeResolver.resolve_host(host, req.port)
                # Create new request with safe IP (clone is immutable)
                req = req.clone(host=safe_ip)
            except aiohttp.ClientConnectionError as e:
                logger.error(f"SSRF protection blocked {host}: {e}")
                raise
        
        return await super().connect(req, traces, timeout)


# ============================================================================
# DATA MODELS
# ============================================================================

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str  # 'hosts', 'domains', 'adblock'
    priority: int = 0

    @field_validator('source_type')
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        allowed = {'hosts', 'domains', 'adblock'}
        if v not in allowed:
            raise ValueError(f"Source type must be one of {allowed}")
        return v


# ============================================================================
# DOMAIN PROCESSOR (Business Logic)
# ============================================================================

class DomainProcessor:
    """
    Handles deduplication, categorization, and validation of domains.
    Thread-safe for async usage via locking if needed, but here used sequentially per batch.
    """
    
    # Optimized Regex Patterns
    VALID_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
    IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    
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
            "processed": 0,
            "added": 0,
            "duplicates": 0,
            "invalid": 0,
            "categories": {}
        }

    def _categorize(self, domain: str) -> str:
        if self.ai_enabled and self.AI_PATTERNS.search(domain):
            return "ai_ml"
        if any(k in domain for k in ["ad", "banner", "doubleclick"]):
            return "ads"
        if any(k in domain for k in ["track", "analytics", "pixel"]):
            return "tracking"
        if any(k in domain for k in ["malware", "phish", "virus"]):
            return "malware"
        return "other"

    def add_domain(self, domain: str) -> bool:
        self.stats["processed"] += 1
        
        # Validation
        if len(domain) < 4 or len(domain) > 253:
            self.stats["invalid"] += 1
            return False
        
        if self.IP_RE.match(domain):
            self.stats["invalid"] += 1
            return False
        
        if not self.VALID_DOMAIN_RE.match(domain):
            self.stats["invalid"] += 1
            return False

        # Deduplication & Capacity
        if domain in self.domains:
            self.stats["duplicates"] += 1
            return False
        
        if len(self.domains) >= self.max_size:
            return False  # Limit reached

        category = self._categorize(domain)
        self.domains[domain] = category
        self.stats["added"] += 1
        self.stats["categories"][category] = self.stats["categories"].get(category, 0) + 1
        return True


# ============================================================================
# SOURCE FETCHER & PARSER
# ============================================================================

class SourceFetcher:
    def __init__(self, timeout: int, ssl_context: bool = True):
        self.timeout = ClientTimeout(total=timeout)
        # Use SafeTCPConnector for SSRF protection
        self.connector = SafeTCPConnector(limit=10, enable_cleanup_closed=True, ssl=ssl_context)

    async def fetch_lines(self, url: str) -> AsyncGenerator[str, None]:
        """Fetches content and yields lines one by one to save memory."""
        try:
            async with ClientSession(connector=self.connector, timeout=self.timeout) as session:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status != 200:
                        logger.warning(f"Failed to fetch {url}: HTTP {resp.status}")
                        return
                    
                    # Stream response to handle large files
                    async for line in resp.content:
                        yield line.decode('utf-8', errors='ignore').strip()
        except Exception as e:
            logger.error(f"Network error fetching {url}: {e}")


def parse_line(line: str, source_type: str) -> Optional[str]:
    """Parses a single line based on source type."""
    if not line or line.startswith(('#', '!', '[', '*')):
        return None

    domain = None
    if source_type == 'hosts':
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
            domain = parts[1]
    elif source_type == 'domains':
        domain = line
    elif source_type == 'adblock':
        match = re.match(r'^\|\|([a-z0-9.-]+)\^', line)
        if match:
            domain = match.group(1)
    
    if domain:
        return domain.lower().rstrip('.')
    return None


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

async def process_source(fetcher: SourceFetcher, source: SourceConfig, processor: DomainProcessor) -> None:
    logger.info(f"Processing source: {source.name}")
    async for line in fetcher.fetch_lines(str(source.url)):
        domain = parse_line(line, source.source_type)
        if domain:
            processor.add_domain(domain)
    logger.info(f"Finished source: {source.name}")


async def atomic_write(filepath: Path, content: str) -> None:
    """Writes content to file atomically to prevent corruption."""
    dir_path = filepath.parent
    dir_path.mkdir(parents=True, exist_ok=True)
    
    # Create temp file in same directory to ensure same filesystem for rename
    fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        
        # Atomic rename
        os.replace(tmp_path, str(filepath))
        logger.info(f"Successfully wrote {filepath}")
    except Exception as e:
        logger.error(f"Failed to write file: {e}")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


async def write_blocklist_optimized(filepath: Path, domains: Dict[str, str], header: str) -> None:
    """Writes blocklist line by line to save memory."""
    dir_path = filepath.parent
    dir_path.mkdir(parents=True, exist_ok=True)
    
    fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(header)
            for domain, cat in sorted(domains.items()):
                f.write(f"0.0.0.0 {domain} # {cat}\n")
            f.flush()
            os.fsync(f.fileno())
        
        os.replace(tmp_path, str(filepath))
        logger.info(f"Successfully wrote {filepath}")
    except Exception as e:
        logger.error(f"Failed to write file: {e}")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


async def main() -> None:
    settings = AppSettings()
    logger.info("🚀 Starting DNS Blocklist Builder v2.0.1")
    
    processor = DomainProcessor(
        max_size=settings.max_domains,
        ai_enabled=settings.enable_ai_detection
    )
    
    fetcher = SourceFetcher(timeout=settings.http_timeout, ssl_context=settings.strict_ssl)

    # Trusted Sources (Hardcoded for security)
    sources = [
        SourceConfig(name="OISD Big", url="https://big.oisd.nl/domains", source_type="hosts", priority=1),
        SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=2),
        SourceConfig(name="StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", source_type="hosts", priority=3),
    ]

    # Process sources sequentially to respect memory limits and simplicity
    for source in sorted(sources, key=lambda x: x.priority):
        await process_source(fetcher, source, processor)

    # Generate Output
    logger.info("Generating output...")
    timestamp = datetime.now(timezone.utc).isoformat()
    header = (
        f"# DNS Security Blocklist\n"
        f"# Generated: {timestamp}\n"
        f"# Total Domains: {processor.stats['added']}\n"
        f"# Categories: {json.dumps(processor.stats['categories'])}\n\n"
    )
    
    output_file = settings.output_dir / "blocklist.txt"
    await write_blocklist_optimized(output_file, processor.domains, header)
    
    # Compress with streaming to save memory
    gz_path = settings.output_dir / "blocklist.txt.gz"
    with open(output_file, 'rb') as f_in:
        with gzip.open(gz_path, 'wb', compresslevel=6) as f_out:
            # Copy in chunks to avoid loading entire file into memory
            while chunk := f_in.read(8192):
                f_out.write(chunk)
    
    logger.info(f"Compressed version saved to {gz_path}")
    logger.info(f"✅ Build Complete. Stats: {processor.stats}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception("Fatal error occurred")
        sys.exit(1)
