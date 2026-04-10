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
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Iterable
from functools import lru_cache
import time
import signal
import os
from socket import timeout as SocketTimeout


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

    @classmethod
    @lru_cache(maxsize=100000)
    def validate(cls, domain: str) -> ValidationResult:
        if not domain or not isinstance(domain, str):
            return ValidationResult(False, None, "empty_domain")

        domain = domain.strip().lower().rstrip('.')

        if len(domain) > 253:
            return ValidationResult(False, None, "domain_too_long")

        if not cls.DOMAIN_REGEX.match(domain):
            return ValidationResult(False, None, "invalid_format")

        for label in domain.split('.'):
            if not label or len(label) > 63:
                return ValidationResult(False, None, "invalid_label")
            if label[0] == '-' or label[-1] == '-':
                return ValidationResult(False, None, "hyphen")

        return ValidationResult(True, domain, None)

    @classmethod
    def is_valid(cls, domain: str) -> bool:
        return cls.validate(domain).is_valid


# ============================================================================
# DOMAIN PROCESSOR
# ============================================================================

class DomainProcessor:
    def __init__(self, max_domains: int = 10_000_000, workers: int = 4):
        self.max_domains = max_domains
        self.workers = workers

        self._domains: Set[str] = set()
        self._queue: queue.Queue = queue.Queue(maxsize=100_000)
        self._stats: Dict[str, int] = {'added': 0, 'rejected': 0, 'errors': 0}

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._shutdown = False
        self._active_tasks = 0
        self._tasks_lock = threading.Lock()

    def start(self) -> None:
        for i in range(self.workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                domain = self._queue.get(timeout=0.5)
                
                if domain is None:
                    self._queue.task_done()
                    break

                result = DomainValidator.validate(domain)

                with self._lock:
                    if result.is_valid and result.normalized:
                        if result.normalized not in self._domains:
                            if len(self._domains) < self.max_domains:
                                self._domains.add(result.normalized)
                                self._stats['added'] += 1
                            else:
                                self._stats['rejected'] += 1
                    else:
                        self._stats['rejected'] += 1

                self._queue.task_done()
                
                with self._tasks_lock:
                    self._active_tasks -= 1

            except queue.Empty:
                continue
            except Exception:
                with self._lock:
                    self._stats['errors'] += 1
                self._queue.task_done()
                with self._tasks_lock:
                    self._active_tasks -= 1

    def submit_batch(self, domains: Iterable[str]) -> None:
        for d in domains:
            with self._tasks_lock:
                if self._shutdown:
                    return
                self._active_tasks += 1
            self._queue.put(d)

    def shutdown(self) -> None:
        self._shutdown = True
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5.0)

    def wait(self) -> None:
        while True:
            with self._tasks_lock:
                if self._active_tasks == 0 and self._queue.empty():
                    break
            time.sleep(0.1)

    def get_domains(self) -> Set[str]:
        with self._lock:
            return set(self._domains)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ============================================================================
# FETCH
# ============================================================================

DEFAULT_SOURCES = [
    "https://someonewhocares.org/hosts/zero/hosts",
]


def fetch_source(url: str, retries: int = 3) -> List[str]:
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'Mozilla/5.0 (compatible; DomainFetcher/1.0)'}
    )

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                content = r.read().decode('utf-8', errors='ignore')

            result = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(('#', ';', '//')):
                    continue

                parts = line.split()
                domain = parts[1] if len(parts) >= 2 else line

                if DomainValidator.is_valid(domain):
                    result.append(domain)

            return result

        except (urllib.error.URLError, urllib.error.HTTPError, SocketTimeout) as e:
            if attempt == retries - 1:
                logging.error(f"Failed to fetch {url}: {str(e)}")
                return []
            time.sleep(1.5 ** attempt + 0.1)
        except Exception as e:
            logging.error(f"Unexpected error fetching {url}: {str(e)}")
            return []

    return []


def fetch_all(sources: List[str], workers: int, processor: DomainProcessor) -> bool:
    any_success = False
    
    def fetch_and_submit(url: str) -> None:
        nonlocal any_success
        domains = fetch_source(url)
        if domains:
            any_success = True
            processor.submit_batch(domains)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(fetch_and_submit, s) for s in sources]
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as e:
                logging.error(f"Fetch task failed: {str(e)}")
    
    return any_success


# ============================================================================
# FORMAT
# ============================================================================

def format_dnsmasq(domains: Set[str]) -> str:
    return '\n'.join(f"address=/{d}/0.0.0.0" for d in sorted(domains))


def format_plain(domains: Set[str]) -> str:
    return '\n'.join(sorted(domains))


# ============================================================================
# MAIN
# ============================================================================

def signal_handler(signum, frame) -> None:
    raise KeyboardInterrupt()


def main() -> None:
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='Fetch and validate domain lists')
    parser.add_argument("--fetch", action="store_true", help="Fetch domains from remote sources")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Output file path")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Number of worker threads")
    parser.add_argument("-f", "--format", choices=['dnsmasq', 'plain'], default='dnsmasq',
                        help="Output format")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    processor = DomainProcessor(workers=args.workers)
    processor.start()

    try:
        if args.fetch:
            logging.info("Fetching domains from sources...")
            success = fetch_all(DEFAULT_SOURCES, args.workers, processor)
            if not success:
                logging.error("All sources failed to fetch any domains")
                sys.exit(1)
        else:
            test_domains = ["example.com", "google.com"]
            processor.submit_batch(test_domains)
            logging.warning("No fetch mode, using test domains")

        processor.wait()
        valid = processor.get_domains()
        stats = processor.get_stats()

        if not valid:
            logging.error("No valid domains found")
            sys.exit(1)

        formatter = format_dnsmasq if args.format == "dnsmasq" else format_plain

        try:
            args.output.write_text(formatter(valid))
            logging.info(f"Saved {len(valid)} domains to {args.output}")
            logging.info(f"Stats: added={stats['added']}, rejected={stats['rejected']}, errors={stats['errors']}")
        except (IOError, OSError) as e:
            logging.error(f"Cannot write to {args.output}: {str(e)}")
            sys.exit(1)

    except KeyboardInterrupt:
        logging.info("Received interrupt, cleaning up...")
        processor.shutdown()
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        processor.shutdown()
        sys.exit(1)
    finally:
        processor.shutdown()


if __name__ == "__main__":
    main()
