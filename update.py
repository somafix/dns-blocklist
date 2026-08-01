#!/usr/bin/env python3
"""
DNS Blocklist Manager - Production Ready v12.0.0
High Availability DNS блоклист с автоматическим failover
"""

import asyncio
import json
import logging
import logging.handlers
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Set, List, Dict, Optional

try:
    import aiohttp
    from aiohttp import ClientTimeout, ClientError
except ImportError:
    print("❌ Error: Install aiohttp: pip install aiohttp")
    sys.exit(1)

__version__ = "12.0.0"

# Python 3.11+ compatibility
try:
    UTC = timezone.UTC
except AttributeError:
    UTC = timezone(timedelta(0))


# ============================================================================
# CONSTANTS
# ============================================================================

FALLBACK_SOURCES: List[Dict[str, str]] = [
    {
        "name": "HaGeZi PRO (Primary)",
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
    },
    {
        "name": "HaGeZi PRO (Mirror 1)",
        "url": "https://gitlab.com/hagezi/dns-blocklists/-/raw/main/domains/pro.txt",
    },
    {
        "name": "OISD Full",
        "url": "https://big.oisd.nl/domainswild2",
    },
    {
        "name": "StevenBlack Hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    },
    {
        "name": "AdGuard DNS Filter",
        "url": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
    },
    {
        "name": "EasyList",
        "url": "https://easylist.to/easylist/easylist.txt",
    },
    {
        "name": "Peter Lowe's List",
        "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    },
]

DEFAULT_SOURCE = FALLBACK_SOURCES[0]

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Application configuration with persistence support"""
    
    # Network settings
    timeout: int = 30
    max_retries: int = 3
    parallel_downloads: int = 2
    user_agent: str = f"DNS-Blocklist-Manager/{__version__}"
    
    # Sources (will be restored from state if available)
    sources: List[Dict[str, str]] = field(default_factory=lambda: [DEFAULT_SOURCE])
    
    # Paths
    hosts_output: Path = Path("hosts.txt")
    backup_dir: Path = Path("backup")
    whitelist_file: Path = Path("whitelist.txt")
    blacklist_file: Path = Path("blacklist.txt")
    wildcard_whitelist_file: Path = Path("wildcard_whitelist.txt")
    log_file: Path = Path("logs/dns_blocker.log")
    stats_file: Path = Path("stats.json")
    state_file: Path = Path(".source_state.json")
    
    def __post_init__(self) -> None:
        """Restore last working source if available"""
        saved = self._restore_state()
        if saved:
            self.sources = [saved]
    
    def _restore_state(self) -> Optional[Dict[str, str]]:
        """Restore last working source from state file"""
        if not self.state_file.exists():
            return None
        
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return data.get("source")
        except (json.JSONDecodeError, OSError, KeyError):
            return None
    
    def save_state(self, source: Dict[str, str]) -> None:
        """Save working source for future runs"""
        try:
            self.state_file.write_text(
                json.dumps({
                    "source": source,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "version": __version__
                }, indent=2),
                encoding="utf-8"
            )
        except OSError as e:
            print(f"⚠️ Failed to save state: {e}")
    
    def init_directories(self) -> None:
        """Create required directories"""
        self.backup_dir.mkdir(exist_ok=True)
        self.log_file.parent.mkdir(exist_ok=True)


# ============================================================================
# LOGGER
# ============================================================================

class Logger:
    """Professional logger with rotation and emoji support"""
    
    _EMOJIS = {
        "info": "ℹ️",
        "warning": "⚠️",
        "error": "❌",
        "success": "✅",
        "progress": "📊",
        "failover": "🔄"
    }
    
    def __init__(self, log_file: Path, verbose: bool = False) -> None:
        self.logger = logging.getLogger("DNSBlocker")
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
        )
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(console_handler)
        
        self.verbose = verbose
    
    def _log(self, level: str, msg: str, emoji_key: str = "") -> None:
        """Internal logging method"""
        emoji = self._EMOJIS.get(emoji_key, "")
        formatted = f"{emoji} {msg}" if emoji else msg
        getattr(self.logger, level)(formatted)
    
    def info(self, msg: str) -> None:
        self._log("info", msg, "info")
    
    def warning(self, msg: str) -> None:
        self._log("warning", msg, "warning")
    
    def error(self, msg: str) -> None:
        self._log("error", msg, "error")
    
    def success(self, msg: str) -> None:
        self._log("info", msg, "success")
    
    def progress(self, msg: str) -> None:
        self._log("info", msg, "progress")
    
    def failover(self, msg: str) -> None:
        self._log("warning", msg, "failover")
    
    def debug(self, msg: str) -> None:
        if self.verbose:
            self._log("debug", msg, "debug")


# ============================================================================
# DOMAIN VALIDATOR
# ============================================================================

class DomainValidator:
    """Domain name validation and normalization"""
    
    # Compiled regex patterns for performance
    _IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    _DOMAIN_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
    _PREFIXES = ("https://", "http://", "||", "0.0.0.0 ", "127.0.0.1 ")
    
    @classmethod
    def clean(cls, line: str) -> Optional[str]:
        """Clean and validate domain string"""
        if not line or not isinstance(line, str):
            return None
        
        # Remove comments
        if "#" in line:
            line = line[:line.index("#")]
        
        # Normalize
        line = line.strip().lower()
        if not line:
            return None
        
        # Remove prefixes
        for prefix in cls._PREFIXES:
            if line.startswith(prefix):
                line = line[len(prefix):]
                break
        
        # Remove suffixes
        line = line.rstrip("/^")
        
        # Skip wildcard patterns
        if "*" in line:
            return None
        
        # Skip IP addresses
        if cls._IP_PATTERN.match(line):
            return None
        
        # Validate domain
        if len(line) < 3 or len(line) > 253:
            return None
        if line[0] == "." or line[-1] == "." or ".." in line:
            return None
        if not cls._DOMAIN_PATTERN.match(line):
            return None
        
        return line
    
    @staticmethod
    def match_wildcard(domain: str, patterns: Set[str]) -> bool:
        """Check if domain matches any wildcard pattern"""
        for pattern in patterns:
            if pattern.endswith("*"):
                if domain.startswith(pattern[:-1]):
                    return True
            elif pattern.startswith("*"):
                if domain.endswith(pattern[1:]):
                    return True
            elif domain == pattern:
                return True
        return False


# ============================================================================
# SOURCE MANAGER (FAILOVER)
# ============================================================================

class SourceManager:
    """Source management with automatic failover"""
    
    def __init__(self, logger: Logger, config: Config) -> None:
        self.logger = logger
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self) -> "SourceManager":
        timeout = ClientTimeout(total=self.config.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": self.config.user_agent}
        )
        return self
    
    async def __aexit__(self, *args) -> None:
        if self._session:
            await self._session.close()
    
    async def _is_available(self, source: Dict[str, str]) -> bool:
        """Check if source is available with HEAD request"""
        if not self._session:
            raise RuntimeError("Session not initialized")
        
        try:
            async with self._session.head(source["url"], allow_redirects=True) as resp:
                if resp.status == 200:
                    return True
                # Fallback to GET with range if HEAD not supported
                if resp.status in (405, 403):
                    async with self._session.get(
                        source["url"],
                        headers={"Range": "bytes=0-1024"}
                    ) as get_resp:
                        return get_resp.status in (200, 206)
                return False
        except (asyncio.TimeoutError, ClientError):
            return False
    
    async def _find_alternative(self) -> Optional[Dict[str, str]]:
        """Find first working alternative source"""
        self.logger.failover("Searching for alternative sources...")
        
        for idx, source in enumerate(FALLBACK_SOURCES, 1):
            # Skip current source
            if source["url"] == self.config.sources[0]["url"]:
                continue
            
            self.logger.progress(f"Checking [{idx}/{len(FALLBACK_SOURCES)}]: {source['name']}")
            
            if await self._is_available(source):
                self.logger.success(f"Found working source: {source['name']}")
                return source
            
            await asyncio.sleep(0.1)
        
        return None
    
    async def get_working_source(self) -> Optional[Dict[str, str]]:
        """Get working source with automatic failover"""
        primary = self.config.sources[0]
        self.logger.info(f"Checking primary source: {primary['name']}")
        
        # Check primary source
        if await self._is_available(primary):
            self.logger.success(f"Primary source available: {primary['name']}")
            self.config.save_state(primary)
            return primary
        
        # Primary unavailable - activate failover
        self.logger.failover(f"Primary source unavailable: {primary['name']}")
        
        # Try restored source if different
        restored = self.config._restore_state()
        if restored and restored["url"] != primary["url"]:
            self.logger.progress("Checking restored source...")
            if await self._is_available(restored):
                self.logger.success(f"Restored source available: {restored['name']}")
                self.config.save_state(restored)
                return restored
        
        # Find alternative
        alternative = await self._find_alternative()
        if alternative:
            self.logger.failover(f"Switching to: {alternative['name']}")
            self.config.sources = [alternative]
            self.config.save_state(alternative)
            self.logger.warning(
                f"Using alternative source: {alternative['name']}\n"
                f"Primary source {primary['name']} is temporarily unavailable"
            )
            return alternative
        
        self.logger.error("No available sources found")
        return None


# ============================================================================
# DATA FETCHER
# ============================================================================

class DataFetcher:
    """Asynchronous data fetcher with retry logic"""
    
    def __init__(self, logger: Logger, config: Config) -> None:
        self.logger = logger
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self) -> "DataFetcher":
        timeout = ClientTimeout(total=self.config.timeout)
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": self.config.user_agent}
        )
        return self
    
    async def __aexit__(self, *args) -> None:
        if self._session:
            await self._session.close()
    
    async def _fetch_source(self, source: Dict[str, str]) -> Set[str]:
        """Fetch domains from single source with retries"""
        if not self._session:
            raise RuntimeError("Session not initialized")
        
        for attempt in range(self.config.max_retries):
            try:
                async with self._session.get(source["url"]) as response:
                    if response.status == 200:
                        content = await response.text()
                        domains = self._parse_content(content)
                        self.logger.info(f"Downloaded {source['name']}: {len(domains):,} domains")
                        return domains
                    
                    self.logger.warning(
                        f"{source['name']}: HTTP {response.status} "
                        f"(attempt {attempt + 1}/{self.config.max_retries})"
                    )
                    
            except asyncio.TimeoutError:
                self.logger.warning(
                    f"{source['name']}: Timeout "
                    f"(attempt {attempt + 1}/{self.config.max_retries})"
                )
            except ClientError as e:
                self.logger.warning(
                    f"{source['name']}: Network error - {str(e)[:50]}"
                )
            except Exception as e:
                self.logger.warning(
                    f"{source['name']}: Unexpected error - {str(e)[:50]}"
                )
            
            if attempt < self.config.max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        
        return set()
    
    @staticmethod
    def _parse_content(content: str) -> Set[str]:
        """Parse domains from content"""
        domains = set()
        for line in content.splitlines():
            domain = DomainValidator.clean(line)
            if domain:
                domains.add(domain)
        return domains
    
    async def fetch_all(self, sources: List[Dict[str, str]]) -> Set[str]:
        """Fetch domains from multiple sources in parallel"""
        semaphore = asyncio.Semaphore(self.config.parallel_downloads)
        
        async def fetch_one(source: Dict[str, str]) -> Set[str]:
            async with semaphore:
                return await self._fetch_source(source)
        
        results = await asyncio.gather(*[fetch_one(src) for src in sources])
        
        # Merge results
        all_domains = set()
        for domains in results:
            all_domains.update(domains)
        
        return all_domains


# ============================================================================
# BLOCKLIST BUILDER
# ============================================================================

@dataclass
class BuildStats:
    """Build statistics"""
    total: int = 0
    whitelisted: int = 0
    wildcard_filtered: int = 0
    blacklisted: int = 0
    output: int = 0
    reduction_percent: float = 0.0
    source_name: str = ""
    source_url: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "total": self.total,
            "whitelisted": self.whitelisted,
            "wildcard_filtered": self.wildcard_filtered,
            "blacklisted": self.blacklisted,
            "output": self.output,
            "reduction_percent": self.reduction_percent,
            "source_name": self.source_name,
            "source_url": self.source_url
        }


class BlocklistBuilder:
    """Blocklist builder with filtering"""
    
    def __init__(self, logger: Logger, config: Config) -> None:
        self.logger = logger
        self.config = config
        self.stats = BuildStats()
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._wildcard_whitelist: Set[str] = set()
        
        self._load_lists()
    
    def _load_lists(self) -> None:
        """Load user lists"""
        self._whitelist = self._load_domain_file(self.config.whitelist_file)
        self._blacklist = self._load_domain_file(self.config.blacklist_file)
        self._wildcard_whitelist = self._load_domain_file(self.config.wildcard_whitelist_file)
        
        self.logger.info(f"Whitelist: {len(self._whitelist):,} domains")
        self.logger.info(f"Blacklist: {len(self._blacklist):,} domains")
        self.logger.info(f"Wildcard whitelist: {len(self._wildcard_whitelist):,} patterns")
    
    @staticmethod
    def _load_domain_file(file_path: Path) -> Set[str]:
        """Load domains from file"""
        domains = set()
        if not file_path.exists():
            return domains
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        domains.add(domain)
        except (OSError, UnicodeDecodeError) as e:
            print(f"⚠️ Failed to load {file_path}: {e}")
        
        return domains
    
    async def build(self) -> List[str]:
        """Build final blocklist with automatic failover"""
        self.logger.progress("Starting blocklist build...")
        
        # Get working source with failover
        async with SourceManager(self.logger, self.config) as source_manager:
            source = await source_manager.get_working_source()
            if not source:
                self.logger.error("No available sources")
                return []
            
            self.stats.source_name = source["name"]
            self.stats.source_url = source["url"]
            
            # Fetch data
            self.logger.progress("Downloading sources...")
            async with DataFetcher(self.logger, self.config) as fetcher:
                all_domains = await fetcher.fetch_all([source])
        
        if not all_domains:
            self.logger.error("Failed to load domains")
            return []
        
        self.stats.total = len(all_domains)
        self.logger.info(f"Total unique domains: {len(all_domains):,}")
        self.logger.info(f"Source: {self.stats.source_name}")
        
        # Filter domains
        self.logger.progress("Filtering domains...")
        filtered = []
        
        for domain in all_domains:
            # Check wildcard whitelist
            if DomainValidator.match_wildcard(domain, self._wildcard_whitelist):
                self.stats.wildcard_filtered += 1
                continue
            
            # Check whitelist
            if domain in self._whitelist:
                self.stats.whitelisted += 1
                continue
            
            # Check blacklist (keep blacklisted domains)
            if domain in self._blacklist:
                self.stats.blacklisted += 1
            
            filtered.append(domain)
        
        self.stats.output = len(filtered)
        if self.stats.total > 0:
            self.stats.reduction_percent = (1 - self.stats.output / self.stats.total) * 100
        
        self._print_stats()
        return filtered
    
    def _print_stats(self) -> None:
        """Print build statistics"""
        self.logger.info("Build statistics:")
        self.logger.info(f"  ├─ Source: {self.stats.source_name}")
        self.logger.info(f"  ├─ Input: {self.stats.total:,} domains")
        self.logger.info(f"  ├─ Output: {self.stats.output:,} domains")
        self.logger.info(f"  ├─ Whitelisted: {self.stats.whitelisted:,}")
        self.logger.info(f"  ├─ Wildcard filtered: {self.stats.wildcard_filtered:,}")
        self.logger.info(f"  ├─ Blacklisted (kept): {self.stats.blacklisted:,}")
        self.logger.info(f"  └─ Reduction: {self.stats.reduction_percent:.1f}%")
    
    def save_stats(self) -> None:
        """Save statistics to JSON"""
        try:
            data = {
                "timestamp": datetime.now(UTC).isoformat(),
                "version": __version__,
                "stats": self.stats.to_dict()
            }
            self.config.stats_file.write_text(
                json.dumps(data, indent=2),
                encoding="utf-8"
            )
        except (OSError, json.JSONDecodeError) as e:
            self.logger.warning(f"Failed to save stats: {e}")


# ============================================================================
# HOSTS FILE WRITER
# ============================================================================

class HostsFileWriter:
    """Hosts file writer"""
    
    @staticmethod
    def write(domains: List[str], output_path: Path, source_name: str) -> bool:
        """Write domains to hosts file"""
        if not domains:
            return False
        
        try:
            header = (
                f"# DNS Blocklist v{__version__}\n"
                f"# Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"# Total: {len(domains):,} domains\n"
                f"# Source: {source_name}\n\n"
            )
            
            content = header + "".join(f"0.0.0.0 {domain}\n" for domain in domains)
            output_path.write_text(content, encoding="utf-8")
            
            return output_path.exists() and output_path.stat().st_size > 0
        except OSError as e:
            print(f"❌ Error writing hosts file: {e}")
            return False


# ============================================================================
# BACKUP MANAGER
# ============================================================================

class BackupManager:
    """Backup management"""
    
    @staticmethod
    def create_backup(file_path: Path, backup_dir: Path) -> Optional[Path]:
        """Create backup of existing file"""
        if not file_path.exists():
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"{file_path.stem}_{timestamp}{file_path.suffix}"
        
        try:
            shutil.copy2(file_path, backup_path)
            return backup_path
        except (OSError, shutil.Error) as e:
            print(f"⚠️ Failed to create backup: {e}")
            return None


# ============================================================================
# MAIN
# ============================================================================

async def main() -> int:
    """Main application entry point"""
    config = Config()
    config.init_directories()
    
    logger = Logger(config.log_file, verbose=os.getenv("DEBUG", "0") == "1")
    
    # Banner
    print(f"\n{'=' * 60}")
    print(f"🚀 DNS BLOCKLIST MANAGER v{__version__} (High Availability)")
    print(f"{'=' * 60}")
    print(f"📅 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📦 Fallback sources: {len(FALLBACK_SOURCES)}")
    print(f"📁 Output: {config.hosts_output}")
    print(f"{'=' * 60}\n")
    
    try:
        # Create backup
        backup = BackupManager.create_backup(config.hosts_output, config.backup_dir)
        if backup:
            logger.info(f"Backup created: {backup.name}")
        
        # Build blocklist
        builder = BlocklistBuilder(logger, config)
        domains = await builder.build()
        
        if not domains:
            logger.error("No domains to export")
            return 1
        
        # Write hosts file
        logger.progress("Writing hosts.txt...")
        if not HostsFileWriter.write(domains, config.hosts_output, builder.stats.source_name):
            logger.error("Failed to write hosts.txt")
            return 1
        
        # Save statistics
        builder.save_stats()
        
        # Final output
        file_size = config.hosts_output.stat().st_size / (1024 * 1024)
        print(f"\n{'=' * 60}")
        print(f"✅ BUILD COMPLETED SUCCESSFULLY")
        print(f"{'=' * 60}")
        print(f"📊 Blocked domains: {len(domains):,}")
        print(f"📌 Source: {builder.stats.source_name}")
        print(f"💾 File size: {file_size:.2f} MB")
        print(f"📁 Output: {config.hosts_output.absolute()}")
        print(f"{'=' * 60}\n")
        
        return 0
        
    except asyncio.CancelledError:
        logger.warning("Operation cancelled")
        return 130
    except Exception as e:
        logger.error(f"Critical error: {e}")
        if os.getenv("DEBUG"):
            import traceback
            traceback.print_exc()
        return 1


def cli_main() -> None:
    """CLI entry point with signal handling"""
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    cli_main()