#!/usr/bin/env python3
"""
DNS Blocklist Builder - Production Ready v5.2.1
Author: Security Team
Version: 5.2.1 (Fixed: Removed HaGeZi, Fixed errors, Optimized)
License: MIT
"""

import sys
import os
import subprocess

# ============================================================================
# AUTO-INSTALL DEPENDENCIES
# ============================================================================

def install_dependencies():
    """Auto-install required packages"""
    required = ['aiohttp', 'aiofiles', 'yaml']
    missing = []
    
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    
    if missing:
        print(f"📦 Installing missing packages: {missing}")
        for pkg in missing:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'])
        print("✅ Dependencies installed successfully")

# Run auto-install
install_dependencies()

# ============================================================================
# IMPORTS
# ============================================================================

import asyncio
import aiohttp
import hashlib
import logging
import time
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Set, Dict, List, Optional
from dataclasses import dataclass, field

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Source:
    """Blocklist source definition"""
    name: str
    url: str
    enabled: bool = True
    timeout: int = 30
    
@dataclass
class BuildStats:
    """Build statistics"""
    total_domains: int = 0
    sources_processed: int = 0
    sources_failed: int = 0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    
    @property
    def duration(self) -> float:
        end = self.end_time or datetime.now(timezone.utc)
        return (end - self.start_time).total_seconds()

# ============================================================================
# SOURCE MANAGER
# ============================================================================

class SourceManager:
    """Manages blocklist sources - HaGeZi EXCLUDED"""
    
    def __init__(self):
        # Only reliable sources - HaGeZi removed due to false positives
        self.sources: Dict[str, Source] = {
            'stevenblack': Source(
                name='StevenBlack',
                url='https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
            ),
            'adaway': Source(
                name='AdAway',
                url='https://adaway.org/hosts.txt'
            ),
            'oisd': Source(
                name='OISD',
                url='https://big.oisd.nl/domainswild2'
            ),
            'someonewhocares': Source(
                name='SomeoneWhoCares',
                url='https://someonewhocares.org/hosts/zero/hosts'
            )
        }
    
    def get_sources(self) -> List[Source]:
        """Get all enabled sources"""
        return [s for s in self.sources.values() if s.enabled]
    
    def get_names(self) -> List[str]:
        """Get source names"""
        return [s.name for s in self.get_sources()]

# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """RFC-compliant domain validator"""
    
    # Reserved TLDs
    RESERVED_TLDS = {
        'localhost', 'local', 'example', 'invalid', 'test', 'lan',
        'internal', 'localdomain', 'home', 'arpa'
    }
    
    @classmethod
    def validate(cls, domain: str) -> bool:
        """Validate domain according to RFC standards"""
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # Length checks
        if len(domain_lower) < 3 or len(domain_lower) > 253:
            return False
        
        # Character checks
        allowed = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        if not all(c in allowed for c in domain_lower):
            return False
        
        # Hyphen position
        if domain_lower.startswith('-') or domain_lower.endswith('-'):
            return False
        
        # Double dots
        if '..' in domain_lower:
            return False
        
        # Label validation
        labels = domain_lower.split('.')
        if len(labels) < 2:
            return False
        
        for label in labels:
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
        
        # TLD validation
        tld = labels[-1]
        if tld in cls.RESERVED_TLDS:
            return False
        if len(tld) < 2:
            return False
        
        # Skip IP addresses
        if domain_lower.replace('.', '').isdigit():
            return False
        
        return True

# ============================================================================
# FETCHER
# ============================================================================

class SourceFetcher:
    """Fetch and parse blocklist sources"""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
    
    async def fetch(self, source: Source) -> Set[str]:
        """Fetch and parse a single source"""
        domains = set()
        
        try:
            logger.info(f"  Fetching {source.name}...")
            
            async with self.session.get(source.url, timeout=source.timeout) as response:
                if response.status != 200:
                    logger.warning(f"  ⚠ {source.name}: HTTP {response.status}")
                    return domains
                
                content = await response.text()
                
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse hosts format (0.0.0.0 domain or 127.0.0.1 domain)
                    if '0.0.0.0' in line or '127.0.0.1' in line or '::1' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            domain = parts[1].lower()
                            if DomainValidator.validate(domain):
                                domains.add(domain)
                    
                    # Parse plain domain format
                    elif '.' in line and not line.startswith('!'):
                        domain = line.lower()
                        if DomainValidator.validate(domain):
                            domains.add(domain)
                
                logger.info(f"  ✓ {source.name}: {len(domains):,} domains")
                return domains
                
        except asyncio.TimeoutError:
            logger.error(f"  ✗ {source.name}: Timeout after {source.timeout}s")
            return domains
        except aiohttp.ClientError as e:
            logger.error(f"  ✗ {source.name}: Connection error - {e}")
            return domains
        except Exception as e:
            logger.error(f"  ✗ {source.name}: {e}")
            return domains

# ============================================================================
# OUTPUT GENERATOR
# ============================================================================

class OutputGenerator:
    """Generate blocklist file"""
    
    def __init__(self, output_path: Path = Path('dynamic-blocklist.txt')):
        self.output_path = output_path
    
    def generate(self, domains: List[str], stats: BuildStats, sources: List[str]) -> bool:
        """Generate blocklist file"""
        if not domains:
            logger.error("No domains to generate")
            return False
        
        # Calculate hash
        domain_string = ''.join(domains)
        file_hash = hashlib.sha256(domain_string.encode()).hexdigest()
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as tmp:
                # Header
                tmp.write("# ====================================================================\n")
                tmp.write("# DNS SECURITY BLOCKLIST\n")
                tmp.write("# ====================================================================\n")
                tmp.write(f"# Version: 5.2.1\n")
                tmp.write(f"# Generated: {stats.end_time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                tmp.write(f"# Total domains: {len(domains):,}\n")
                tmp.write(f"# Sources: {', '.join(sources)}\n")
                tmp.write(f"# Duration: {stats.duration:.2f} seconds\n")
                tmp.write(f"# SHA-256: {file_hash}\n")
                tmp.write("# ====================================================================\n")
                tmp.write("\n")
                tmp.write("127.0.0.1 localhost\n")
                tmp.write("::1 localhost\n")
                tmp.write("\n")
                
                # Domains
                for domain in domains:
                    tmp.write(f"0.0.0.0 {domain}\n")
                
                tmp.flush()
            
            # Atomic rename
            shutil.move(tmp.name, self.output_path)
            logger.info(f"✅ Generated: {self.output_path} ({len(domains):,} domains)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate output: {e}")
            return False

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate build report"""
    
    @staticmethod
    def print_header():
        """Print header"""
        print("\n" + "=" * 80)
        print("🚀 DNS SECURITY BLOCKLIST BUILDER v5.2.1")
        print("Enterprise-grade threat intelligence aggregation")
        print("=" * 80)
    
    @staticmethod
    def print_report(domains: Set[str], source_stats: Dict[str, Set[str]], stats: BuildStats):
        """Print build report"""
        print("\n" + "=" * 80)
        print("📊 BUILD REPORT")
        print("=" * 80)
        
        # Source statistics
        print(f"\n{'SOURCE':<25} {'DOMAINS':>12} {'PERCENTAGE':>12}")
        print("-" * 80)
        
        total = len(domains)
        for name, source_domains in source_stats.items():
            count = len(source_domains)
            pct = (count / total * 100) if total > 0 else 0
            print(f"{name:<25} {count:>12,} {pct:>11.1f}%")
        
        print("-" * 80)
        print(f"{'TOTAL':<25} {total:>12,} {'100.0%':>12}")
        print("=" * 80)
        
        # Performance metrics
        print(f"\n📈 Performance:")
        print(f"  • Duration: {stats.duration:.2f} seconds")
        print(f"  • Rate: {total / stats.duration:.0f} domains/second")
        print(f"  • Sources: {stats.sources_processed} processed, {stats.sources_failed} failed")
        
        print("=" * 80)

# ============================================================================
# MAIN BUILDER
# ============================================================================

class BlocklistBuilder:
    """Main blocklist builder"""
    
    def __init__(self):
        self.source_manager = SourceManager()
        self.stats = BuildStats()
        self.source_stats: Dict[str, Set[str]] = {}
    
    async def build(self) -> bool:
        """Build the blocklist"""
        ReportGenerator.print_header()
        
        sources = self.source_manager.get_sources()
        self.stats.sources_processed = len(sources)
        
        print(f"\n📡 Sources: {', '.join(self.source_manager.get_names())}")
        print()
        
        # Fetch all sources
        async with aiohttp.ClientSession() as session:
            fetcher = SourceFetcher(session)
            
            tasks = []
            for source in sources:
                tasks.append(fetcher.fetch(source))
            
            results = await asyncio.gather(*tasks)
            
            # Collect results
            all_domains: Set[str] = set()
            for source, domains in zip(sources, results):
                if domains:
                    self.source_stats[source.name] = domains
                    all_domains.update(domains)
                else:
                    self.stats.sources_failed += 1
                    self.source_stats[source.name] = set()
        
        # Check results
        if not all_domains:
            logger.error("No domains collected from any source")
            return False
        
        # Sort domains
        sorted_domains = sorted(all_domains)
        self.stats.total_domains = len(sorted_domains)
        self.stats.end_time = datetime.now(timezone.utc)
        
        # Generate output
        output = OutputGenerator()
        success = output.generate(sorted_domains, self.stats, self.source_manager.get_names())
        
        if success:
            ReportGenerator.print_report(all_domains, self.source_stats, self.stats)
        
        return success

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def async_main() -> int:
    """Async main entry point"""
    try:
        builder = BlocklistBuilder()
        success = await builder.build()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Build failed: {e}", exc_info=True)
        return 1

def main() -> int:
    """Synchronous main entry point"""
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        return 130
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
