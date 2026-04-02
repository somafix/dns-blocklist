#!/usr/bin/env python3
"""
DNS Security Blocklist Builder - Autonomous Edition
Version: 4.0.0 - Self-Healing, Auto-Update, Zero Supervision
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
import hashlib
import pickle
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import AsyncGenerator, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from functools import wraps

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from pydantic import BaseModel, Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class HealthStatus:
    """Tracks health of the application"""
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
    """Auto-recovering configuration"""
    model_config = SettingsConfigDict(env_prefix="DNSBL_", case_sensitive=False)
    
    # Directories
    output_dir: Path = Field(default=Path("./output"))
    cache_dir: Path = Field(default=Path("./cache"))
    state_dir: Path = Field(default=Path("./state"))
    
    # Limits
    max_domains: int = Field(default=2_000_000, ge=1000)
    http_timeout: int = Field(default=30, ge=5)
    max_retries: int = Field(default=3, ge=1)
    retry_delay: int = Field(default=5, ge=1)
    
    # Auto-healing
    auto_repair: bool = Field(default=True)
    checkpoint_interval: int = Field(default=100000)  # Save state every N domains
    max_checkpoints: int = Field(default=5)
    
    # Schedule (cron in seconds)
    update_interval_hours: int = Field(default=6, ge=1)
    
    def setup_dirs(self):
        """Create all required directories"""
        for dir_path in [self.output_dir, self.cache_dir, self.state_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)


# ============================================================================
# PERSISTENT STATE MANAGER (для восстановления после сбоев)
# ============================================================================

class StateManager:
    """Saves and restores processing state for crash recovery"""
    
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.checkpoint_file = state_dir / "checkpoint.pkl"
        self.domains_file = state_dir / "domains.pkl"
        
    def save_checkpoint(self, domains: Dict[str, bool], processed_count: int, source_index: int) -> None:
        """Save current state for recovery"""
        try:
            checkpoint = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "processed_count": processed_count,
                "source_index": source_index,
                "domain_count": len(domains)
            }
            
            # Save checkpoint metadata
            with open(self.checkpoint_file, 'wb') as f:
                pickle.dump(checkpoint, f)
            
            # Save domains (incremental)
            with open(self.domains_file, 'wb') as f:
                pickle.dump(domains, f)
            
            logger.info(f"💾 Checkpoint saved: {processed_count} domains processed")
        except Exception as e:
            logger.warning(f"Failed to save checkpoint: {e}")
    
    def load_checkpoint(self) -> Tuple[Optional[Dict], Optional[int], Optional[int]]:
        """Load previous state if exists"""
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
        """Clear checkpoint after successful completion"""
        try:
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
            if self.domains_file.exists():
                self.domains_file.unlink()
        except Exception as e:
            logger.warning(f"Failed to clear checkpoint: {e}")


# ============================================================================
# DOMAIN PROCESSOR (с автосохранением)
# ============================================================================

class DomainProcessor:
    """Handles deduplication with automatic checkpointing"""
    
    VALID_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$')
    IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

    def __init__(self, max_size: int, state_manager: StateManager, checkpoint_interval: int):
        self.max_size = max_size
        self.state_manager = state_manager
        self.checkpoint_interval = checkpoint_interval
        self.domains: Dict[str, bool] = {}
        self.processed_count = 0
        self.stats = {"processed": 0, "added": 0, "duplicates": 0, "invalid": 0}
        
        # Try to restore from checkpoint
        restored_domains, restored_count, _ = state_manager.load_checkpoint()
        if restored_domains:
            self.domains = restored_domains
            self.processed_count = restored_count or 0
            self.stats["added"] = len(restored_domains)
            logger.info(f"🔄 Restored {len(self.domains)} domains from previous run")

    def add_domain(self, domain: str) -> bool:
        self.processed_count += 1
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

        if domain in self.domains:
            self.stats["duplicates"] += 1
            return False
        
        if len(self.domains) >= self.max_size:
            return False

        self.domains[domain] = True
        self.stats["added"] += 1
        
        # Auto-checkpoint
        if self.processed_count % self.checkpoint_interval == 0:
            self.state_manager.save_checkpoint(self.domains, self.processed_count, 0)
        
        return True


# ============================================================================
# AUTO-RETRY FETCHER (с экспоненциальной задержкой)
# ============================================================================

class RobustFetcher:
    """Fetches with automatic retry and backoff"""
    
    def __init__(self, timeout: int, max_retries: int, retry_delay: int):
        self.timeout = ClientTimeout(total=timeout)
        self.connector = TCPConnector(limit=10, enable_cleanup_closed=True)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
    
    async def fetch_with_retry(self, url: str, source_name: str) -> AsyncGenerator[str, None]:
        """Fetch with exponential backoff retry"""
        for attempt in range(self.max_retries):
            try:
                async for line in self._fetch(url):
                    yield line
                return  # Success
            except Exception as e:
                wait_time = self.retry_delay * (2 ** attempt)
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed for {source_name}: {e}")
                
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Failed to fetch {source_name} after {self.max_retries} attempts")
                    raise
    
    async def _fetch(self, url: str) -> AsyncGenerator[str, None]:
        """Internal fetch method"""
        async with ClientSession(connector=self.connector, timeout=self.timeout) as session:
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                
                async for line in resp.content:
                    yield line.decode('utf-8', errors='ignore').strip()


# ============================================================================
# HEALTH MONITOR & AUTO-REPAIR
# ============================================================================

class HealthMonitor:
    """Monitors system health and triggers repairs"""
    
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager
        self.health = HealthStatus()
        self.health_file = state_manager.state_dir / "health.json"
        self._load_health()
    
    def _load_health(self):
        """Load previous health status"""
        if self.health_file.exists():
            try:
                with open(self.health_file, 'r') as f:
                    data = json.load(f)
                    self.health.last_success = datetime.fromisoformat(data['last_success']) if data.get('last_success') else None
                    self.health.consecutive_failures = data.get('consecutive_failures', 0)
                    self.health.total_updates = data.get('total_updates', 0)
            except Exception:
                pass
    
    def _save_health(self):
        """Save health status"""
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
        """Check if system needs repair"""
        if self.health.consecutive_failures >= 3:
            return True
        if self.health.last_success:
            # No success in last 24 hours
            if datetime.now(timezone.utc) - self.health.last_success > timedelta(hours=24):
                return True
        return False
    
    async def auto_repair(self):
        """Attempt automatic repair"""
        logger.warning("🔧 Attempting auto-repair...")
        
        # Clear corrupted checkpoint
        self.state_manager.clear_checkpoint()
        
        # Reset health
        self.health.consecutive_failures = 0
        self.health.last_error = None
        self._save_health()
        
        logger.info("✅ Auto-repair completed")
        return True


# ============================================================================
# SCHEDULER (автоматический запуск)
# ============================================================================

class AutonomousScheduler:
    """Runs the updater automatically on schedule"""
    
    def __init__(self, update_interval_hours: int, update_func):
        self.update_interval = update_interval_hours * 3600
        self.update_func = update_func
        self.running = True
        self.last_run: Optional[datetime] = None
    
    async def run_forever(self):
        """Main scheduler loop"""
        logger.info(f"⏰ Scheduler started. Update interval: {self.update_interval // 3600} hours")
        
        # Run immediately on start
        await self._run_with_handling()
        
        while self.running:
            # Wait for next interval
            for _ in range(self.update_interval):
                if not self.running:
                    return
                await asyncio.sleep(1)
            
            await self._run_with_handling()
    
    async def _run_with_handling(self):
        """Run update with error handling"""
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
    source_type: str  # 'hosts' or 'domains'
    priority: int = 0
    enabled: bool = True
    etag: Optional[str] = None  # For conditional requests
    
    @field_validator('source_type')
    @classmethod
    def validate_source_type(cls, v: str) -> str:
        allowed = {'hosts', 'domains'}
        if v not in allowed:
            raise ValueError(f"Source type must be one of {allowed}")
        return v


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
        """Main update process with full autonomy"""
        try:
            # Check if repair is needed
            if self.health_monitor.needs_repair() and self.settings.auto_repair:
                await self.health_monitor.auto_repair()
            
            # Initialize processor
            processor = DomainProcessor(
                max_size=self.settings.max_domains,
                state_manager=self.state_manager,
                checkpoint_interval=self.settings.checkpoint_interval
            )
            
            # Sources (hardcoded for security)
            sources = [
                SourceConfig(name="OISD Big", url="https://big.oisd.nl/domains", source_type="hosts", priority=1),
                SourceConfig(name="AdAway", url="https://adaway.org/hosts.txt", source_type="hosts", priority=2),
                SourceConfig(name="StevenBlack", url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", source_type="hosts", priority=3),
            ]
            
            # Process each source
            for source in sorted(sources, key=lambda x: x.priority):
                if not source.enabled:
                    continue
                
                logger.info(f"📥 Processing: {source.name}")
                async for line in self.fetcher.fetch_with_retry(str(source.url), source.name):
                    domain = parse_line(line, source.source_type)
                    if domain:
                        processor.add_domain(domain)
            
            # Generate output
            await self._generate_output(processor)
            
            # Success!
            self.state_manager.clear_checkpoint()
            self.health_monitor.record_success()
            
            logger.info(f"✅ Update successful. Stats: {processor.stats}")
            return True
            
        except Exception as e:
            logger.exception(f"Update failed: {e}")
            self.health_monitor.record_failure(str(e))
            return False
    
    async def _generate_output(self, processor: DomainProcessor):
        """Generate final blocklist files"""
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
        
        output_file = self.settings.output_dir / "blocklist.txt"
        
        # Write blocklist
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
        
        # Compress
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
    """Main autonomous entry point"""
    settings = AppSettings()
    updater = AutonomousUpdater(settings)
    
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        # Single run mode
        logger.info("🚀 Running single update...")
        success = await updater.update()
        sys.exit(0 if success else 1)
    else:
        # Daemon mode with scheduler
        logger.info("🤖 Starting Autonomous DNS Blocklist Builder")
        logger.info("=" * 50)
        
        scheduler = AutonomousScheduler(
            update_interval_hours=settings.update_interval_hours,
            update_func=updater.update
        )
        
        # Handle shutdown signals
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
        logger.info("Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception("Fatal error occurred")
        sys.exit(1)
