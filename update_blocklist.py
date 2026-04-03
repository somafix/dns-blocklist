#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - Autonomous Edition
Version: 4.0.6 - FIXED: saves to root directory, not output folder
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
import signal
import tempfile
import gzip
import json
import pickle
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import AsyncGenerator, Dict, Optional, Tuple
from dataclasses import dataclass

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from pydantic import BaseModel, Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("DNSBL_Builder")

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class HealthStatus:
    last_success: Optional[datetime] = None
    consecutive_failures: int = 0
    total_updates: int = 0
    last_error: Optional[str] = None
    
    def record_success(self):
        self.last_success = datetime.now(timezone.utc)
        self.consecutive_failures = 0
        self.total_updates += 1
    
    def record_failure(self, error: str):
        self.consecutive_failures += 1
        self.last_error = error
    
    def is_healthy(self) -> bool:
        return self.consecutive_failures < 3


class AppSettings(BaseSettings):
    """Configuration - saves blocklist.txt to root directory"""
    model_config = SettingsConfigDict(env_prefix="DNSBL_", case_sensitive=False)
    
    # Directories - FIXED: output goes to root (.)
    output_dir: Path = Field(default=Path("."))  # ← ИСПРАВЛЕНО: теперь в корень
    cache_dir: Path = Field(default=Path("./cache"))
    state_dir: Path = Field(default=Path("./state"))
    
    # Limits
    max_domains: int = Field(default=2_000_000, ge=1000)
    http_timeout: int = Field(default=30, ge=5)
    max_retries: int = Field(default=3, ge=1)
    retry_delay: int = Field(default=5, ge=1)
    
    # Auto-healing
    auto_repair: bool = Field(default=True)
    checkpoint_interval: int = Field(default=100000)
    max_checkpoints: int = Field(default=5)
    
    # Schedule
    update_interval_hours: int = Field(default=6, ge=1)
    
    def setup_dirs(self):
        """Create required directories (cache and state only)"""
        for dir_path in [self.cache_dir, self.state_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        # output_dir is root (.), no need to create


# ============================================================================
# PERSISTENT STATE MANAGER
# ============================================================================

class StateManager:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.checkpoint_file = state_dir / "checkpoint.pkl"
        self.domains_file = state_dir / "domains.pkl"
        
    def save_checkpoint(self, domains: Dict[str, bool], processed_count: int, source_index: int) -> None:
        try:
            checkpoint = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "processed_count": processed_count,
                "source_index": source_index,
                "domain_count": len(domains)
            }
            with open(self.checkpoint_file, 'wb') as f:
                pickle.dump(checkpoint, f)
            with open(self.domains_file, 'wb') as f:
                pickle.dump(domains, f)
            logger.info(f"💾 Checkpoint saved: {processed_count} domains processed")
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")
    
    def load_checkpoint(self) -> Tuple[Optional[Dict], Optional[int], Optional[int]]:
        if self.checkpoint_file.exists() and self.domains_file.exists():
            try:
                with open(self.checkpoint_file, 'rb') as f:
                    checkpoint = pickle.load(f)
                with open(self.domains_file, 'rb') as f:
                    domains = pickle.load(f)
                logger.info(f"🔄 Restored checkpoint: {checkpoint['domain_count']} domains from {checkpoint['timestamp']}")
                return domains, checkpoint['processed_count'], checkpoint['source_index']
            except Exception as e:
                logger.warning(f"Failed to load checkpoint: {e}")
        return None, None, None
    
    def clear_checkpoint(self) -> None:
        try:
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
            if self.domains_file.exists():
                self.domains_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to clear checkpoint: {e}")


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    VALID_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
    IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    def __init__(self, max_size: int, state_manager: StateManager, checkpoint_interval: int):
        self.max_size = max_size
        self.state_manager = state_manager
        self.checkpoint_interval = checkpoint_interval
        self.domains: Dict[str, bool] = {}
        self.processed_count = 0
        self.stats = {"processed": 0, "added": 0, "duplicates": 0, "invalid": 0}
        
        restored_domains, restored_count, _ = state_manager.load_checkpoint()
        if restored_domains:
            self.domains = restored_domains
            self.processed_count = restored_count or 0
            self.stats["added"] = len(restored_domains)
            logger.info(f"🔄 Restored {len(self.domains)} domains from previous run")

    def add_domain(self, domain: str) -> bool:
        self.processed_count += 1
        self.stats["processed"] += 1
        
        if len(domain) < 4 or len(domain) > 253:
            self.stats["invalid"] += 1
            return False
        
        if self.IP_RE.match(domain):
            self.stats["invalid"] += 1
            return False
        
        if not self.VALID_DOMAIN_RE.match(domain):
            self.stats["invalid"] += 1
            return False

        if domain in self.domains:
            self.stats["duplicates"] += 1
            return False
        
        if len(self.domains) >= self.max_size:
            return False

        self.domains[domain] = True
        self.stats["added"] += 1
        
        if self.processed_count % self.checkpoint_interval == 0:
            self.state_manager.save_checkpoint(self.domains, self.processed_count, 0)
        
        return True


# ============================================================================
# AUTO-RETRY FETCHER
# ============================================================================

class RobustFetcher:
    def __init__(self, timeout: int, max_retries: int, retry_delay: int):
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
    
    async def fetch_with_retry(self, url: str, source_name: str) -> AsyncGenerator[str, None]:
        last_error = None
        for attempt in range(self.max_retries):
            try:
                async for line in self._fetch(url):
                    yield line
                return
            except Exception as e:
                last_error = e
                wait_time = self.retry_delay * (2 ** attempt)
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed for {source_name}: {e}")
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Failed to fetch {source_name} after {self.max_retries} attempts")
                    raise last_error
    
    async def _fetch(self, url: str) -> AsyncGenerator[str, None]:
        connector = TCPConnector(limit=10, enable_cleanup_closed=True)
        async with ClientSession(connector=connector, timeout=self.timeout) as session:
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                async for line in resp.content:
                    yield line.decode('utf-8', errors='ignore').strip()


# ============================================================================
# HEALTH MONITOR
# ============================================================================

class HealthMonitor:
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager
        self.health = HealthStatus()
        self.health_file = state_manager.state_dir / "health.json"
        self._load_health()
    
    def _load_health(self):
        if self.health_file.exists():
            try:
                with open(self.health_file, 'r') as f:
                    data = json.load(f)
                    if data.get('last_success'):
                        self.health.last_success = datetime.fromisoformat(data['last_success'])
                    self.health.consecutive_failures = data.get('consecutive_failures', 0)
                    self.health.total_updates = data.get('total_updates', 0)
            except Exception:
                pass
    
    def _save_health(self):
        try:
            with open(self.health_file, 'w') as f:
                json.dump({
                    'last_success': self.health.last_success.isoformat() if self.health.last_success else None,
                    'consecutive_failures': self.health.consecutive_failures,
                    'total_updates': self.health.total_updates,
                    'last_error': self.health.last_error
                }, f)
        except Exception:
            pass
    
    def record_success(self):
        self.health.record_success()
        self._save_health()
    
    def record_failure(self, error: str):
        self.health.record_failure(error)
        self._save_health()
    
    def needs_repair(self) -> bool:
        if self.health.consecutive_failures >= 3:
            return True
        if self.health.last_success:
            if datetime.now(timezone.utc) - self.health.last_success > timedelta(hours=24):
                return True
        return False
    
    async def auto_repair(self):
        logger.warning("🔧 Attempting auto-repair...")
        self.state_manager.clear_checkpoint()
        self.health.consecutive_failures = 0
        self.health.last_error = None
        self._save_health()
        logger.info("✅ Auto-repair completed")
        return True


# ============================================================================
# SCHEDULER
# ============================================================================

class AutonomousScheduler:
    def __init__(self, update_interval_hours: int, update_func):
        self.update_interval = update_interval_hours * 3600
        self.update_func = update_func
        self.running = True
        self.last_run: Optional[datetime] = None
    
    async def run_forever(self):
        logger.info(f"⏰ Scheduler started. Update interval: {self.update_interval // 3600} hours")
        await self._run_with_handling()
        while self.running:
            for _ in range(self.update_interval):
                if not self.running:
                    return
                await asyncio.sleep(1)
            await self._run_with_handling()
    
    async def _run_with_handling(self):
        try:
            logger.info("🔄 Scheduled update starting...")
            await self.update_func()
            self.last_run = datetime.now(timezone.utc)
            logger.info("✅ Scheduled update completed")
        except Exception as e:
            logger.error(f"Scheduled update failed: {e}")
    
    def stop(self):
        self.running = False


# ============================================================================
# SOURCE CONFIGURATION
# ============================================================================

class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    source_type: str
    priority: int = 0
    enabled: bool = True
    etag: Optional[str] = None
    
    @field_validator('source_type')
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        allowed = {'hosts', 'domains'}
        if v not in allowed:
            raise ValueError(f"Source type must be one of {allowed}")
        return v


def parse_line(line: str, source_type: str) -> Optional[str]:
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
# MAIN UPDATER
# ============================================================================

class AutonomousUpdater:
    def __init__(self, settings: AppSettings):
        self.settings = settings
        self.settings.setup_dirs()
        self.state_manager = StateManager(settings.state_dir)
        self.health_monitor = HealthMonitor(self.state_manager)
        self.fetcher = RobustFetcher(
            timeout=settings.http_timeout,
            max_retries=settings.max_retries,
            retry_delay=settings.retry_delay
        )
        
    async def update(self) -> bool:
        try:
            if self.health_monitor.needs_repair() and self.settings.auto_repair:
                await self.health_monitor.auto_repair()
            
            processor = DomainProcessor(
                max_size=self.settings.max_domains,
                state_manager=self.state_manager,
                checkpoint_interval=self.settings.checkpoint_interval
            )
            
            sources = [
                SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=1),
                SourceConfig(name="StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", source_type="hosts", priority=2),
                SourceConfig(name="Peter Lowe", url="https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", source_type="hosts", priority=3),
            ]
            
            for source in sorted(sources, key=lambda x: x.priority):
                if not source.enabled:
                    continue
                logger.info(f"📥 Processing: {source.name}")
                try:
                    async for line in self.fetcher.fetch_with_retry(str(source.url), source.name):
                        domain = parse_line(line, source.source_type)
                        if domain:
                            processor.add_domain(domain)
                except Exception as e:
                    logger.error(f"Source {source.name} failed, continuing with next source: {e}")
                    continue
            
            if len(processor.domains) == 0:
                raise Exception("No domains were collected from any source")
            
            await self._generate_output(processor)
            self.state_manager.clear_checkpoint()
            self.health_monitor.record_success()
            logger.info(f"✅ Update successful. Stats: {processor.stats}")
            return True
            
        except Exception as e:
            logger.exception(f"Update failed: {e}")
            self.health_monitor.record_failure(str(e))
            return False
    
    async def _generate_output(self, processor: DomainProcessor):
        logger.info("📝 Generating output...")
        
        timestamp = datetime.now(timezone.utc).isoformat()
        header = (
            f"# DNS Security Blocklist\n"
            f"# Generated: {timestamp}\n"
            f"# Total Domains: {processor.stats['added']}\n"
            f"# Total Processed: {processor.stats['processed']}\n"
            f"# Duplicates Removed: {processor.stats['duplicates']}\n"
            f"# Invalid Skipped: {processor.stats['invalid']}\n\n"
        )
        
        # FIXED: saves directly to current directory, not to output folder
        output_file = self.settings.output_dir / "blocklist.txt"
        
        fd, tmp_path = tempfile.mkstemp(dir=str(self.settings.output_dir), suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(header)
                for domain in sorted(processor.domains.keys()):
                    f.write(f"0.0.0.0 {domain}\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, str(output_file))
        except Exception as e:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        
        gz_path = self.settings.output_dir / "blocklist.txt.gz"
        with open(output_file, 'rb') as f_in:
            with gzip.open(gz_path, 'wb', compresslevel=6) as f_out:
                while chunk := f_in.read(8192):
                    f_out.write(chunk)
        
        logger.info(f"✅ Blocklist saved: {output_file} ({len(processor.domains):,} domains)")


# ============================================================================
# MAIN
# ============================================================================

async def main():
    settings = AppSettings()
    updater = AutonomousUpdater(settings)
    
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        logger.info("🚀 Running single update...")
        success = await updater.update()
        sys.exit(0 if success else 1)
    else:
        logger.info("🤖 Starting Autonomous DNS Blocklist Builder")
        logger.info("=" * 50)
        
        scheduler = AutonomousScheduler(
            update_interval_hours=settings.update_interval_hours,
            update_func=updater.update
        )
        
        def shutdown(signum, frame):
            logger.info("🛑 Shutdown signal received")
            scheduler.stop()
        
        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)
        
        try:
            await scheduler.run_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.exception(f"Fatal error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error occurred: {e}")
        sys.exit(1)
