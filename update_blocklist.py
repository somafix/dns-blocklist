#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import re
import sys
import threading
import queue
import urllib.request
import urllib.error
import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Iterable, Any
from functools import lru_cache
import time
import signal
import os
import json
import hashlib
from socket import timeout as SocketTimeout
from datetime import datetime
from contextlib import contextmanager
import tempfile
import shutil
import atexit

try:
    import prometheus_client
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    max_domains: int = 10_000_000
    queue_size: int = 500_000
    workers: int = 10
    fetch_workers: int = 10
    max_retries: int = 3
    retry_backoff: float = 1.5
    fetch_timeout: int = 30
    queue_timeout: float = 0.5
    shutdown_timeout: float = 10.0
    max_output_size_mb: int = 1024
    enable_metrics: bool = True
    log_level: str = "INFO"
    log_json: bool = False
    sources: List[str] = field(default_factory=lambda: [
        # Оригинальные источники
        "https://someonewhocares.org/hosts/zero/hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        
        # Новые активные источники (формат 0.0.0.0)
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        "https://raw.githubusercontent.com/kadiremrah/Lists/master/everything.txt",
        "https://raw.githubusercontent.com/Aetherinox/blocklists/main/blocklists/master.hosts",
        
        # Дополнительные проверенные источники
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt",
        "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
        "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
        "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
    ])
    rate_limit_per_second: int = 10
    state_file: Optional[Path] = None
    backup_output: bool = True
    dead_letter_limit: int = 10000
    wait_timeout_seconds: int = 300


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(config: Config) -> None:
    if STRUCTLOG_AVAILABLE and config.log_json:
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        logging.basicConfig(level=getattr(logging, config.log_level), format="%(message)s")
    else:
        logging.basicConfig(
            level=getattr(logging, config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )


def get_logger(name: str):
    if STRUCTLOG_AVAILABLE:
        return structlog.get_logger(name)
    return logging.getLogger(name)


# ============================================================================
# METRICS
# ============================================================================

class MetricsCollector:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and PROMETHEUS_AVAILABLE
        self.metrics = {}
        
        if self.enabled:
            try:
                self.metrics['domains_added'] = prometheus_client.Counter('domains_added_total', 'Total domains added')
                self.metrics['domains_rejected'] = prometheus_client.Counter('domains_rejected_total', 'Total domains rejected')
                self.metrics['domains_duplicates'] = prometheus_client.Counter('domains_duplicates_total', 'Total duplicate domains')
                self.metrics['fetch_errors'] = prometheus_client.Counter('fetch_errors_total', 'Total fetch errors')
                self.metrics['queue_size'] = prometheus_client.Gauge('queue_size', 'Current queue size')
                self.metrics['processing_duration'] = prometheus_client.Histogram('processing_duration_seconds', 'Processing duration')
                self.metrics['active_workers'] = prometheus_client.Gauge('active_workers', 'Number of active workers')
            except Exception:
                self.enabled = False
                self.metrics = {}
    
    def inc(self, name: str, value: int = 1):
        if self.enabled and name in self.metrics:
            self.metrics[name].inc(value)
    
    def set_gauge(self, name: str, value: int):
        if self.enabled and name in self.metrics:
            self.metrics[name].set(value)
    
    @contextmanager
    def time(self, name: str):
        if self.enabled and name in self.metrics:
            with self.metrics[name].time():
                yield
        else:
            yield


# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

@dataclass
class ValidationResult:
    is_valid: bool
    normalized: Optional[str]
    error: Optional[str]


class DomainValidator:
    DOMAIN_REGEX = re.compile(
        r'^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*'
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))$'
    )
    
    ALLOWED_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'eu', 'ru', 'su', 'ua', 'by', 'kz',
        'de', 'uk', 'fr', 'es', 'it', 'nl', 'pl', 'ca', 'au', 'jp', 'cn', 'in', 'br', 'mx'
    }
    CHECK_TLD = False

    @classmethod
    @lru_cache(maxsize=200000)
    def validate(cls, domain: str) -> ValidationResult:
        if not domain or not isinstance(domain, str):
            return ValidationResult(False, None, "empty_domain")

        domain = domain.strip().lower().rstrip('.')

        if len(domain) > 253:
            return ValidationResult(False, None, "domain_too_long")

        if not cls.DOMAIN_REGEX.match(domain):
            return ValidationResult(False, None, "invalid_format")

        labels = domain.split('.')
        if len(labels) < 2:
            return ValidationResult(False, None, "too_few_labels")

        for label in labels:
            if not label or len(label) > 63:
                return ValidationResult(False, None, "invalid_label")
            if label[0] == '-' or label[-1] == '-':
                return ValidationResult(False, None, "hyphen")
        
        if cls.CHECK_TLD and labels[-1] not in cls.ALLOWED_TLDS:
            return ValidationResult(False, None, "invalid_tld")

        return ValidationResult(True, domain, None)

    @classmethod
    def is_valid(cls, domain: str) -> bool:
        return cls.validate(domain).is_valid


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    def __init__(self, rate_per_second: int):
        self.rate = rate_per_second
        self.interval = 1.0 / rate_per_second if rate_per_second > 0 else 0
        self.last_time = time.time()
        self._lock = threading.Lock()
    
    def acquire(self):
        if self.rate <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self.last_time
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self.last_time = time.time()


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    def __init__(self, config: Config, metrics: MetricsCollector):
        self.config = config
        self.metrics = metrics
        self.max_domains = config.max_domains

        self._domains: Set[str] = set()
        self._queue: queue.Queue = queue.Queue(maxsize=config.queue_size)
        self._stats: Dict[str, int] = {'added': 0, 'rejected': 0, 'errors': 0, 'duplicates': 0}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._shutdown = False
        self._active_tasks = 0
        self._tasks_lock = threading.Lock()
        self._dead_letter: List[str] = []
        self._dead_letter_lock = threading.Lock()

    def start(self) -> None:
        for i in range(self.config.workers):
            t = threading.Thread(target=self._worker, name=f"worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)
        self.metrics.set_gauge('active_workers', len(self._threads))
        get_logger(__name__).info("started_workers", count=self.config.workers)

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                domain = self._queue.get(timeout=self.config.queue_timeout)
                
                if domain is None:
                    self._queue.task_done()
                    break

                with self.metrics.time('processing_duration'):
                    result = DomainValidator.validate(domain)

                with self._lock:
                    if result.is_valid and result.normalized:
                        if result.normalized not in self._domains:
                            if len(self._domains) < self.max_domains:
                                self._domains.add(result.normalized)
                                self._stats['added'] += 1
                                self.metrics.inc('domains_added')
                            else:
                                self._stats['rejected'] += 1
                                self.metrics.inc('domains_rejected')
                        else:
                            self._stats['duplicates'] += 1
                            self.metrics.inc('domains_duplicates')
                    else:
                        self._stats['rejected'] += 1
                        self.metrics.inc('domains_rejected')
                        with self._dead_letter_lock:
                            if len(self._dead_letter) < self.config.dead_letter_limit:
                                self._dead_letter.append(f"{domain}|{result.error}")

                self._queue.task_done()
                
                with self._tasks_lock:
                    self._active_tasks -= 1

            except queue.Empty:
                continue
            except Exception as e:
                get_logger(__name__).error("worker_error", error=str(e))
                with self._lock:
                    self._stats['errors'] += 1
                self._queue.task_done()
                with self._tasks_lock:
                    self._active_tasks -= 1

    def submit_batch(self, domains: Iterable[str]) -> None:
        for d in domains:
            with self._tasks_lock:
                if self._shutdown:
                    get_logger(__name__).warning("shutdown_dropping_domains")
                    return
                self._active_tasks += 1
            self._queue.put(d)
            self.metrics.set_gauge('queue_size', self._queue.qsize())

    def shutdown(self) -> None:
        get_logger(__name__).info("shutting_down")
        self._shutdown = True
        self._stop.set()
        
        start = time.time()
        for t in self._threads:
            remaining = self.config.shutdown_timeout - (time.time() - start)
            if remaining > 0:
                t.join(timeout=remaining)
                if t.is_alive():
                    get_logger(__name__).warning("worker_timeout", name=t.name)
        
        if self._dead_letter:
            get_logger(__name__).warning("dead_letter_count", count=len(self._dead_letter))

    def wait(self) -> None:
        start = time.time()
        while time.time() - start < self.config.wait_timeout_seconds:
            with self._tasks_lock:
                if self._active_tasks == 0 and self._queue.empty():
                    break
            time.sleep(0.5)
        else:
            with self._tasks_lock:
                get_logger(__name__).warning("wait_timeout", 
                                            active=self._active_tasks, 
                                            queue=self._queue.qsize())

    def get_domains(self) -> Set[str]:
        with self._lock:
            return set(self._domains)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)
    
    def save_state(self, state_file: Path) -> None:
        if not state_file:
            return
        try:
            state = {
                'domains': list(self._domains),
                'stats': self._stats,
                'timestamp': datetime.now().isoformat()
            }
            with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False, dir=state_file.parent) as f:
                json.dump(state, f)
                temp_path = Path(f.name)
            shutil.move(str(temp_path), str(state_file))
            get_logger(__name__).info("state_saved", path=str(state_file), count=len(self._domains))
        except Exception as e:
            get_logger(__name__).error("state_save_failed", error=str(e))
    
    def load_state(self, state_file: Path) -> bool:
        if not state_file or not state_file.exists():
            return False
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
            with self._lock:
                self._domains.update(state.get('domains', []))
                self._stats.update(state.get('stats', {}))
            get_logger(__name__).info("state_loaded", count=len(self._domains))
            return True
        except Exception as e:
            get_logger(__name__).error("state_load_failed", error=str(e))
            return False


# ============================================================================
# FETCH
# ============================================================================

class RateLimitedFetcher:
    def __init__(self, config: Config):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit_per_second)
    
    def fetch(self, url: str) -> Optional[bytes]:
        self.rate_limiter.acquire()
        
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'DomainFetcher/3.0 (Enterprise Production)',
                'Accept': 'text/plain,text/html,application/json,*/*'
            }
        )
        
        for attempt in range(self.config.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=self.config.fetch_timeout) as r:
                    content = r.read()
                    get_logger(__name__).debug("fetch_success", url=url, size=len(content))
                    return content
            except (urllib.error.URLError, urllib.error.HTTPError, SocketTimeout) as e:
                wait_time = self.config.retry_backoff ** attempt + (attempt * 0.1)
                if attempt == self.config.max_retries - 1:
                    get_logger(__name__).error("fetch_failed", url=url, error=str(e), attempt=attempt+1)
                    return None
                get_logger(__name__).warning("fetch_retry", url=url, error=str(e), attempt=attempt+1, wait=round(wait_time, 2))
                time.sleep(wait_time)
            except Exception as e:
                get_logger(__name__).error("fetch_unexpected", url=url, error=str(e))
                return None
        return None


def parse_hosts_content(content: bytes) -> List[str]:
    result = []
    try:
        text = content.decode('utf-8', errors='ignore')
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', ';', '//', '!', '[', ']')):
                continue
            
            parts = line.split()
            if len(parts) >= 2 and (parts[0] == '0.0.0.0' or parts[0] == '127.0.0.1' or parts[0] == '::1'):
                domain = parts[1]
            elif len(parts) == 1 and '.' in parts[0] and not parts[0].startswith('#'):
                domain = parts[0]
            else:
                continue
            
            if DomainValidator.is_valid(domain):
                result.append(domain)
    except Exception as e:
        get_logger(__name__).error("parse_error", error=str(e))
    return result


def fetch_all(config: Config, processor: DomainProcessor, metrics: MetricsCollector) -> bool:
    fetcher = RateLimitedFetcher(config)
    any_success = False
    results_lock = threading.Lock()
    
    def fetch_and_submit(source: str) -> None:
        nonlocal any_success
        content = fetcher.fetch(source)
        if content:
            domains = parse_hosts_content(content)
            if domains:
                with results_lock:
                    any_success = True
                processor.submit_batch(domains)
                get_logger(__name__).info("source_processed", source=source, count=len(domains))
            else:
                get_logger(__name__).warning("source_empty", source=source)
        else:
            metrics.inc('fetch_errors')
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.fetch_workers) as executor:
        futures = [executor.submit(fetch_and_submit, source) for source in config.sources]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                get_logger(__name__).error("fetch_task_failed", error=str(e))
                metrics.inc('fetch_errors')
    
    return any_success


# ============================================================================
# OUTPUT
# ============================================================================

def format_dnsmasq(domains: Set[str]) -> str:
    return '\n'.join(f"address=/{d}/0.0.0.0" for d in sorted(domains))


def format_plain(domains: Set[str]) -> str:
    return '\n'.join(sorted(domains))


def write_output(output_path: Path, domains: Set[str], config: Config, format_func) -> None:
    if config.backup_output and output_path.exists():
        backup_path = output_path.with_suffix(f".backup.{int(time.time())}")
        shutil.copy2(output_path, backup_path)
        get_logger(__name__).info("backup_created", path=str(backup_path))
    
    content = format_func(domains)
    content_bytes = content.encode('utf-8')
    content_size_mb = len(content_bytes) / (1024 * 1024)
    
    if content_size_mb > config.max_output_size_mb:
        get_logger(__name__).error("output_too_large", size_mb=round(content_size_mb, 2), max_mb=config.max_output_size_mb)
        raise ValueError(f"Output size {content_size_mb:.2f}MB exceeds limit {config.max_output_size_mb}MB")
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False, dir=output_path.parent) as f:
        f.write(content)
        temp_path = Path(f.name)
    
    shutil.move(str(temp_path), str(output_path))
    get_logger(__name__).info("output_written", path=str(output_path), domains=len(domains), size_mb=round(content_size_mb, 2))


# ============================================================================
# MAIN
# ============================================================================

class GracefulKiller:
    def __init__(self):
        self.kill_now = threading.Event()
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
    
    def exit_gracefully(self, signum, frame):
        get_logger(__name__).info("received_signal", signal=signum)
        self.kill_now.set()


def main() -> None:
    parser = argparse.ArgumentParser(description='Enterprise domain list fetcher and validator - Production Grade')
    parser.add_argument("--fetch", action="store_true", help="Fetch domains from remote sources")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Output file path")
    parser.add_argument("-w", "--workers", type=int, help="Number of worker threads")
    parser.add_argument("-f", "--format", choices=['dnsmasq', 'plain'], default='dnsmasq', help="Output format")
    parser.add_argument("--version", action="version", version="%(prog)s 3.0")
    parser.add_argument("--config", type=Path, help="JSON config file")
    parser.add_argument("--state-file", type=Path, help="State file for resume")
    parser.add_argument("--no-metrics", action="store_true", help="Disable metrics")
    parser.add_argument("--log-json", action="store_true", help="JSON logging")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO')
    parser.add_argument("--no-backup", action="store_true", help="Disable backup")
    parser.add_argument("--dead-letter-limit", type=int, default=10000, help="Dead letter queue limit")
    
    args = parser.parse_args()
    
    config = Config()
    
    if args.config and args.config.exists():
        try:
            with open(args.config, 'r') as f:
                config_data = json.load(f)
                for key, value in config_data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
        except Exception as e:
            print(f"Failed to load config: {e}", file=sys.stderr)
            sys.exit(1)
    
    if args.workers:
        config.workers = args.workers
    if args.state_file:
        config.state_file = args.state_file
    if args.no_metrics:
        config.enable_metrics = False
    if args.log_json:
        config.log_json = True
    if args.log_level:
        config.log_level = args.log_level
    if args.no_backup:
        config.backup_output = False
    if args.dead_letter_limit:
        config.dead_letter_limit = args.dead_letter_limit
    
    setup_logging(config)
    logger = get_logger(__name__)
    
    logger.info("starting_production_domain_fetcher", 
                workers=config.workers,
                max_domains=config.max_domains,
                sources=len(config.sources))
    
    metrics = MetricsCollector(enabled=config.enable_metrics)
    processor = DomainProcessor(config, metrics)
    killer = GracefulKiller()
    
    if config.state_file and processor.load_state(config.state_file):
        logger.info("resumed_from_state")
    
    processor.start()
    
    exit_code = 0
    
    try:
        if args.fetch:
            logger.info("starting_fetch", sources=len(config.sources))
            success = fetch_all(config, processor, metrics)
            if not success:
                logger.error("all_sources_failed")
                exit_code = 1
                return
        else:
            test_domains = ["example.com", "google.com", "github.com", "stackoverflow.com"]
            processor.submit_batch(test_domains)
            logger.warning("using_test_domains", count=len(test_domains))
        
        if killer.kill_now.is_set():
            logger.info("interrupt_during_fetch")
            exit_code = 130
            return
        
        processor.wait()
        
        if killer.kill_now.is_set():
            logger.info("interrupt_during_processing")
            exit_code = 130
            return
        
        valid = processor.get_domains()
        stats = processor.get_stats()
        
        if not valid:
            logger.error("no_valid_domains")
            exit_code = 1
            return
        
        formatter = format_dnsmasq if args.format == "dnsmasq" else format_plain
        write_output(args.output, valid, config, formatter)
        
        logger.info("completed_successfully", 
                   domains=len(valid),
                   added=stats['added'],
                   duplicates=stats['duplicates'],
                   rejected=stats['rejected'],
                   errors=stats['errors'],
                   output=str(args.output))
        
        if config.state_file:
            processor.save_state(config.state_file)
    
    except KeyboardInterrupt:
        logger.info("keyboard_interrupt")
        exit_code = 130
    except ValueError as e:
        logger.error(str(e))
        exit_code = 1
    except Exception as e:
        logger.error("unhandled_exception", error=str(e), exc_info=True)
        exit_code = 1
    finally:
        processor.shutdown()
        logger.info("shutdown_complete")
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()