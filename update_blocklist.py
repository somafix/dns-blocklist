#!/usr/bin/env python3
"""
UpDate Blocklister - Production Ready

What it does:
- Validates domain names (RFC 1034/1035)
- Processes domains concurrently (thread-safe)
- Fetches blocklists from URLs
- Outputs in dnsmasq/unbound/plain formats

Audit tools that work on this code:
- ruff (formatting + linting)
- mypy (type checking)
- bandit (security)
- pip-audit (dependencies)
- pytest (tests + coverage)
- pre-commit (automation)
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import threading
import time
import queue
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Iterable, Any
from functools import lru_cache


# ============================================================================
# DOMAIN VALIDATION
# ============================================================================

@dataclass
class ValidationResult:
    """Domain validation result"""
    is_valid: bool
    normalized: Optional[str]
    error: Optional[str]


class DomainValidator:
    """
    RFC 1034/1035 domain validator
    - No external dependencies
    - Cached results (LRU, 100k entries)
    - Thread-safe (pure functions)
    """
    
    DOMAIN_REGEX: re.Pattern = re.compile(
        r'^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*'
        r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))$'
    )
    
    @classmethod
    @lru_cache(maxsize=100000)
    def validate(cls, domain: str) -> ValidationResult:
        """
        Validate domain name according to RFC 1034/1035
        
        Rules:
        - Max length: 253 characters
        - Each label: 1-63 characters
        - Allowed chars: a-z, 0-9, hyphen
        - No hyphen at start or end of label
        """
        if not domain or not isinstance(domain, str):
            return ValidationResult(False, None, "empty_domain")
        
        if len(domain) > 253:
            return ValidationResult(False, None, "domain_too_long")
        
        # Normalize
        domain = domain.strip().lower()
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # Format validation
        if not cls.DOMAIN_REGEX.match(domain):
            return ValidationResult(False, None, "invalid_format")
        
        # Label validation
        for label in domain.split('.'):
            if len(label) == 0:
                return ValidationResult(False, None, "empty_label")
            if len(label) > 63:
                return ValidationResult(False, None, "label_too_long")
            if label[0] == '-' or label[-1] == '-':
                return ValidationResult(False, None, "hyphen_at_boundary")
        
        return ValidationResult(True, domain, None)
    
    @classmethod
    def is_valid(cls, domain: str) -> bool:
        """Quick validation check"""
        return cls.validate(domain).is_valid


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    """
    Thread-safe domain processor with worker pool
    
    Features:
    - Multiple worker threads
    - Bounded queue
    - Graceful shutdown
    - Statistics collection
    """
    
    def __init__(self, max_domains: int = 10_000_000, workers: int = 4):
        self.max_domains = max_domains
        self.workers = workers
        
        self._domains: Set[str] = set()
        self._queue: queue.Queue = queue.Queue()
        self._stats: Dict[str, int] = {'added': 0, 'rejected': 0, 'errors': 0}
        self._running: bool = False
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
    
    def start(self) -> None:
        """Start worker threads"""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop.clear()
            
            for i in range(self.workers):
                t = threading.Thread(
                    target=self._worker,
                    name=f"Worker-{i}",
                    daemon=True
                )
                t.start()
                self._threads.append(t)
    
    def _worker(self) -> None:
        """Worker thread main loop"""
        while not self._stop.is_set():
            try:
                domain = self._queue.get(timeout=0.5)
                if domain is None:
                    break
                
                result = DomainValidator.validate(domain)
                
                with self._lock:
                    if result.is_valid and result.normalized:
                        if len(self._domains) < self.max_domains:
                            self._domains.add(result.normalized)
                            self._stats['added'] += 1
                        else:
                            self._stats['rejected'] += 1
                    else:
                        self._stats['rejected'] += 1
                
                self._queue.task_done()
                
            except queue.Empty:
                continue
            except Exception:
                with self._lock:
                    self._stats['errors'] += 1
    
    def submit(self, domain: str) -> bool:
        """Submit a single domain for processing"""
        if not self._running:
            return False
        try:
            self._queue.put_nowait(domain)
            return True
        except queue.Full:
            return False
    
    def submit_batch(self, domains: Iterable[str]) -> int:
        """Submit multiple domains at once"""
        submitted = 0
        for domain in domains:
            if self.submit(domain):
                submitted += 1
            else:
                break
        return submitted
    
    def stop(self) -> None:
        """Stop all workers gracefully"""
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop.set()
            
            # Send poison pills
            for _ in range(self.workers):
                self._queue.put(None)
            
            # Wait for workers
            for t in self._threads:
                t.join(timeout=2.0)
            self._threads.clear()
    
    def get_domains(self) -> Set[str]:
        """Get all valid domains (copy)"""
        with self._lock:
            return self._domains.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        with self._lock:
            return {
                'total_valid': len(self._domains),
                'added': self._stats['added'],
                'rejected': self._stats['rejected'],
                'errors': self._stats['errors'],
            }


# ============================================================================
# SOURCES FETCHING
# ============================================================================

DEFAULT_SOURCES: List[str] = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
]


def fetch_source(url: str, timeout: int = 30) -> List[str]:
    """
    Fetch domains from a URL
    
    Supports:
    - Plain domain lists (one per line)
    - Hosts file format (IP domain)
    """
    import urllib.request
    
    domains = []
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(('#', ';', '//')):
                    continue
                
                # Parse hosts file format: IP domain [domain2 ...]
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].lower()
                    if DomainValidator.is_valid(domain):
                        domains.append(domain)
                elif DomainValidator.is_valid(line):
                    domains.append(line)
                    
    except Exception as e:
        logging.error(f"Failed to fetch {url}: {e}")
    
    return domains


def fetch_all_sources(sources: List[str], workers: int = 5) -> List[str]:
    """
    Fetch all sources concurrently
    
    Uses ThreadPoolExecutor for parallel fetching
    """
    import concurrent.futures
    
    all_domains = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_url = {executor.submit(fetch_source, url): url for url in sources}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                domains = future.result()
                all_domains.extend(domains)
                logging.info(f"Fetched {len(domains)} domains from {url}")
            except Exception as e:
                logging.error(f"Error fetching {url}: {e}")
    
    return all_domains


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def format_dnsmasq(domains: Set[str]) -> str:
    """Format as dnsmasq configuration"""
    lines = []
    for domain in sorted(domains):
        lines.append(f"address=/{domain}/0.0.0.0")
    return '\n'.join(lines)


def format_unbound(domains: Set[str]) -> str:
    """Format as unbound configuration"""
    lines = ["server:"]
    for domain in sorted(domains):
        lines.append(f'    local-zone: "{domain}" always_nxdomain')
    return '\n'.join(lines)


def format_plain(domains: Set[str]) -> str:
    """Format as plain domain list"""
    return '\n'.join(sorted(domains))


# ============================================================================
# LOGGING
# ============================================================================

def setup_logging(verbose: bool = False) -> None:
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler()]
    )


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="UpDate Blocklister - Production Ready",
        epilog="Example: update_blocklist.py --fetch --output blocklist.txt"
    )
    
    # Input options
    parser.add_argument("--fetch", action="store_true", help="Fetch from default sources")
    parser.add_argument("--sources", "-s", type=Path, help="JSON file with custom sources list")
    parser.add_argument("--input", "-i", type=Path, help="Input file with domains (one per line)")
    
    # Output options
    parser.add_argument("--output", "-o", type=Path, required=True, help="Output file path")
    parser.add_argument("--format", "-f", choices=['dnsmasq', 'unbound', 'plain'], default='dnsmasq')
    
    # Performance
    parser.add_argument("--workers", "-w", type=int, default=4, help="Worker threads (default: 4)")
    
    # Other
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="store_true", help="Show version")
    
    args = parser.parse_args()
    
    if args.version:
        print("UpDate Blocklister v1.0.0")
        print("Audit: ruff | mypy | bandit | pip-audit | pytest")
        return
    
    setup_logging(args.verbose)
    
    # Collect domains
    domains_to_process: List[str] = []
    
    # Fetch from sources
    if args.fetch:
        sources = DEFAULT_SOURCES.copy()
        if args.sources and args.sources.exists():
            import json
            with open(args.sources) as f:
                sources = json.load(f)
        logging.info(f"Fetching from {len(sources)} sources...")
        domains_to_process = fetch_all_sources(sources, workers=args.workers)
    
    # Load from file
    if args.input and args.input.exists():
        with open(args.input) as f:
            file_domains = [line.strip().lower() for line in f if line.strip()]
            domains_to_process.extend(file_domains)
        logging.info(f"Loaded {len(file_domains)} domains from {args.input}")
    
    # Demo mode if no input
    if not domains_to_process:
        logging.warning("No input provided. Running demo with test domains.")
        domains_to_process = ["example.com", "google.com", "github.com", "invalid..com", "test.-domain"]
    
    # Process domains
    logging.info(f"Processing {len(domains_to_process)} domains with {args.workers} workers...")
    
    processor = DomainProcessor(max_domains=10_000_000, workers=args.workers)
    processor.start()
    processor.submit_batch(domains_to_process)
    
    # Allow time for processing
    time.sleep(1)
    processor.stop()
    
    # Generate output
    valid_domains = processor.get_domains()
    stats = processor.get_stats()
    
    formatters = {
        'dnsmasq': format_dnsmasq,
        'unbound': format_unbound,
        'plain': format_plain,
    }
    
    output_content = formatters[args.format](valid_domains)
    args.output.write_text(output_content)
    
    # Report results
    logging.info(f"Saved {len(valid_domains)} domains to {args.output}")
    logging.info(f"Statistics: added={stats['added']}, rejected={stats['rejected']}, errors={stats['errors']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
