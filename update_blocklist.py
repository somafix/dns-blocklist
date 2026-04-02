#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - Enterprise Edition
Version: 3.0.0 - Clean (No AI)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import tempfile
import gzip
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator, Dict, Optional

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
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
    max_domains: int = Field(default=2_000_000, ge=1000)
    http_timeout: int = Field(default=30, ge=5)


# ============================================================================
# DATA MODELS
# ============================================================================

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str  # 'hosts' or 'domains'
    priority: int = 0

    @field_validator('source_type')
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        allowed = {'hosts', 'domains'}
        if v not in allowed:
            raise ValueError(f"Source type must be one of {allowed}")
        return v


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    """Handles deduplication and validation of domains."""
    
    VALID_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
    IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    def __init__(self, max_size: int):
        self.max_size = max_size
        self.domains: Dict[str, str] = {}
        self.stats = {
            "processed": 0,
            "added": 0,
            "duplicates": 0,
            "invalid": 0,
        }

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
            return False

        self.domains[domain] = True
        self.stats["added"] += 1
        return True


# ============================================================================
# SOURCE FETCHER & PARSER
# ============================================================================

class SourceFetcher:
    def __init__(self, timeout: int):
        self.timeout = ClientTimeout(total=timeout)
        self.connector = TCPConnector(limit=10, enable_cleanup_closed=True)

    async def fetch_lines(self, url: str) -> AsyncGenerator[str, None]:
        """Fetches content and yields lines one by one."""
        try:
            async with ClientSession(connector=self.connector, timeout=self.timeout) as session:
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status != 200:
                        logger.warning(f"Failed to fetch {url}: HTTP {resp.status}")
                        return
                    
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


async def write_blocklist(filepath: Path, domains: Dict[str, str], header: str) -> None:
    """Writes blocklist line by line."""
    dir_path = filepath.parent
    dir_path.mkdir(parents=True, exist_ok=True)
    
    fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(header)
            for domain in sorted(domains.keys()):
                f.write(f"0.0.0.0 {domain}\n")
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
    logger.info("🚀 Starting DNS Blocklist Builder v3.0")
    
    processor = DomainProcessor(max_size=settings.max_domains)
    fetcher = SourceFetcher(timeout=settings.http_timeout)

    # Trusted Sources
    sources = [
        SourceConfig(name="OISD Big", url="https://big.oisd.nl/domains", source_type="hosts", priority=1),
        SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=2),
        SourceConfig(name="StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", source_type="hosts", priority=3),
    ]

    for source in sorted(sources, key=lambda x: x.priority):
        await process_source(fetcher, source, processor)

    # Generate Output
    logger.info("Generating output...")
    timestamp = datetime.now(timezone.utc).isoformat()
    header = (
        f"# DNS Security Blocklist\n"
        f"# Generated: {timestamp}\n"
        f"# Total Domains: {processor.stats['added']}\n\n"
    )
    
    output_file = settings.output_dir / "blocklist.txt"
    await write_blocklist(output_file, processor.domains, header)
    
    # Compress
    gz_path = settings.output_dir / "blocklist.txt.gz"
    with open(output_file, 'rb') as f_in:
        with gzip.open(gz_path, 'wb', compresslevel=6) as f_out:
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
