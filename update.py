#!/usr/bin/env python3
"""
DNS Blocklist Manager v3.0 - Полностью автономная система блокировки трекеров
"""

import requests
import re
from datetime import datetime, timedelta
import hashlib
import os
import sys
import tempfile
import shutil
import json
import math
import threading
import time
import gzip
import signal
from typing import Set, Dict, Optional, Tuple, List
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

__author__ = "somafix"
__version__ = "3.0.0"

CONFIG = {
    "urls": [
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    ],
    "timeout": 30,
    "max_file_size_mb": 50,
    "max_domains_to_analyze": 100000,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "cleanup_days": 30,
    "reputation_threshold": 5.0,
    "min_reputation": -10.0,
    "max_reputation": 10.0,
    "workers": 10,
    "cache_ttl_seconds": 3600,
    "enable_dns_cache": True,
    "enable_log_rotation": True,
    "max_log_size_mb": 10,
    "backup_count": 3,
}

FILES = {
    "output": Path("hosts.txt"),
    "backup": Path("hosts.backup"),
    "ai_db": Path("ai_trackers.json"),
    "ai_blocklist": Path("ai_custom_blocklist.txt"),
    "whitelist": Path("ai_whitelist.txt"),
    "log": Path("dns_blocker.log")
}

SUSPICIOUS_KEYWORDS = [
    'track', 'analytics', 'metrics', 'stat', 'pixel', 'tag',
    'click', 'adserver', 'doubleclick', 'googlead', 'google-analytics',
    'facebook', 'criteo', 'taboola', 'outbrain', 'exelator', 'adsrv',
    'ssp', 'dsp', 'rtb', 'bid', 'impression', 'beacon', 'counter',
    'adzerk', 'appnexus', 'adnxs', 'rubicon', 'openx', 'pubmatic',
    'indexww', 'contextweb', 'monetize', 'mediation', 'adsystem',
    'clicktrack', 'trk', 'pixel', 'tracker', 'telemetry'
]

LEGIT_EXCEPTIONS = {
    'cloudflare', 'amazonaws', 'googleapis', 'github', 'cdn', 
    'cloudfront', 'akamaiedge', 'fastly', 'stackpath'
}


class Logger:
    def __init__(self, log_file: Path):
        self.log_file = log_file
        self.lock = threading.Lock()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _rotate_log(self):
        if not CONFIG["enable_log_rotation"] or not self.log_file.exists():
            return
        if self.log_file.stat().st_size > CONFIG["max_log_size_mb"] * 1024 * 1024:
            for i in range(CONFIG["backup_count"] - 1, 0, -1):
                old = self.log_file.with_suffix(f'.{i}.gz')
                new = self.log_file.with_suffix(f'.{i-1}.gz')
                old.unlink(missing_ok=True)
                if new.exists():
                    new.rename(old)
            with open(self.log_file, 'rb') as f_in:
                with gzip.open(self.log_file.with_suffix('.1.gz'), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            self.log_file.unlink()
    
    def log(self, level: str, message: str):
        with self.lock:
            timestamp = datetime.now().isoformat()
            log_line = f"[{timestamp}] [{level}] {message}\n"
            try:
                self._rotate_log()
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(log_line)
            except Exception:
                pass
            print(f"[{level}] {message}")
    
    def info(self, msg): self.log("INFO", msg)
    def error(self, msg): self.log("ERROR", msg)
    def warning(self, msg): self.log("WARNING", msg)


class DNSCache:
    def __init__(self):
        self.cache = {}
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
    
    def get(self, domain: str) -> Optional[bool]:
        if not CONFIG["enable_dns_cache"]:
            return None
        with self.lock:
            if domain in self.cache:
                entry = self.cache[domain]
                if time.time() < entry['expires']:
                    self.hits += 1
                    return entry['is_suspicious']
                del self.cache[domain]
            self.misses += 1
            return None
    
    def set(self, domain: str, is_suspicious: bool):
        if not CONFIG["enable_dns_cache"]:
            return
        with self.lock:
            self.cache[domain] = {
                'is_suspicious': is_suspicious,
                'expires': time.time() + CONFIG["cache_ttl_seconds"]
            }
    
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0


class TrackerAI:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.db_file = FILES["ai_db"]
        self.blocklist_file = FILES["ai_blocklist"]
        self.whitelist_file = FILES["whitelist"]
        
        self.reputation: Dict[str, float] = {}
        self.last_seen: Dict[str, str] = {}
        self.first_added: Dict[str, str] = {}
        self.custom_domains: Set[str] = set()
        self.whitelist: Set[str] = set()
        
        self.dns_cache = DNSCache()
        self.stats = {"analyzed": 0, "added": 0, "removed": 0, "whitelisted": 0}
        self.lock = threading.RLock()
        
        self._load_all()
    
    def _load_all(self):
        self._load_db()
        self._load_custom_blocklist()
        self._load_whitelist()
        self._cleanup_false_positives()
    
    def _load_db(self):
        if not self.db_file.exists():
            return
        try:
            with open(self.db_file, 'r') as f:
                data = json.load(f)
                self.reputation = data.get('reputation', {})
                self.last_seen = data.get('last_seen', {})
                self.first_added = data.get('first_added', {})
            self.logger.info(f"Loaded DB: {len(self.reputation)} domains")
        except Exception as e:
            self.logger.error(f"Failed to load DB: {e}")
    
    def _load_custom_blocklist(self):
        if not self.blocklist_file.exists():
            return
        try:
            with open(self.blocklist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    domain = line[8:] if line.startswith('0.0.0.0 ') else line
                    self.custom_domains.add(domain.lower())
            self.logger.info(f"Loaded {len(self.custom_domains)} custom blocked domains")
        except Exception as e:
            self.logger.error(f"Failed to load custom blocklist: {e}")
    
    def _load_whitelist(self):
        if not self.whitelist_file.exists():
            return
        try:
            with open(self.whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self.whitelist.add(line)
            self.logger.info(f"Loaded {len(self.whitelist)} whitelisted domains")
        except Exception as e:
            self.logger.error(f"Failed to load whitelist: {e}")
    
    def _save_custom_blocklist(self):
        try:
            with open(self.blocklist_file, 'w') as f:
                f.write(f"# AI Self-Learning Blocklist\n")
                f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total domains: {len(self.custom_domains)}\n\n")
                for domain in sorted(self.custom_domains):
                    f.write(f"0.0.0.0 {domain}\n")
        except Exception as e:
            self.logger.error(f"Failed to save custom blocklist: {e}")
    
    def _cleanup_false_positives(self):
        to_remove = []
        now = datetime.now()
        
        with self.lock:
            for domain in list(self.custom_domains):
                if domain in self.whitelist:
                    to_remove.append(domain)
                    self.stats["whitelisted"] += 1
                    continue
                
                rep = self.reputation.get(domain, 0.0)
                if rep >= CONFIG["reputation_threshold"]:
                    to_remove.append(domain)
                    self.stats["removed"] += 1
                    continue
                
                last_seen_str = self.last_seen.get(domain)
                if last_seen_str:
                    try:
                        last_seen = datetime.fromisoformat(last_seen_str)
                        if (now - last_seen).days > CONFIG["cleanup_days"] and rep > -2:
                            to_remove.append(domain)
                            self.stats["removed"] += 1
                    except Exception:
                        pass
            
            for domain in to_remove:
                self.custom_domains.discard(domain)
        
        if to_remove:
            self.logger.info(f"Cleaned up {len(to_remove)} false positives")
    
    @staticmethod
    def _calculate_entropy(s: str) -> float:
        if not s:
            return 0.0
        length = len(s)
        prob = [s.count(c) / length for c in set(s)]
        return -sum(p * math.log(p) / math.log(2) for p in prob if p > 0)
    
    def _is_suspicious_domain(self, domain: str) -> Tuple[bool, int]:
        cached = self.dns_cache.get(domain)
        if cached is not None:
            return cached, 0
        
        domain_lower = domain.lower()
        score = 0
        
        for exc in LEGIT_EXCEPTIONS:
            if exc in domain_lower:
                self.dns_cache.set(domain, False)
                return False, 0
        
        parts = domain_lower.split('.')
        
        if len(parts) > 5:
            score += 2
        
        for part in parts[:-2]:
            if len(part) > 20:
                score += 1
            if re.search(r'\d{5,}', part):
                score += 2
            if '_' in part:
                score += 1
            if re.search(r'[a-z0-9]{15,}', part) and self._calculate_entropy(part) > 3.5:
                score += 2
        
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                score += 2
        
        suspicious_patterns = [
            r'^ad[\d\-\.]', r'^ads[\d\-\.]', r'\.ad[\d\-\.]', r'\.ads[\d\-\.]',
            r'-ad[\-\.]', r'-ads[\-\.]', r'trk[\-\.]', r'track[\-\.]',
            r'click[\-\.]', r'redirect[\-\.]', r'banner[\-\.]',
            r'^[a-z0-9]{20,}\.', r'[0-9a-f]{16,}', r'pixel\.[a-z]+'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain_lower, re.IGNORECASE):
                score += 1
        
        if len(parts) >= 2:
            main_part = parts[-2]
            if len(main_part) <= 3 and main_part not in {'com', 'net', 'org', 'ru', 'cn', 'io', 'co'}:
                score += 2
        
        is_suspicious = score >= 4
        self.dns_cache.set(domain, is_suspicious)
        return is_suspicious, score
    
    def analyze_and_remember(self, domain: str) -> bool:
        now_iso = datetime.now().isoformat()
        domain_lower = domain.lower()
        
        with self.lock:
            self.last_seen[domain_lower] = now_iso
            self.stats["analyzed"] += 1
            
            if domain_lower in self.whitelist:
                self.reputation[domain_lower] = min(
                    self.reputation.get(domain_lower, 0.0) + 1.0,
                    CONFIG["max_reputation"]
                )
                self.custom_domains.discard(domain_lower)
                return False
            
            is_suspicious, score = self._is_suspicious_domain(domain_lower)
            
            if is_suspicious:
                self.reputation[domain_lower] = max(
                    self.reputation.get(domain_lower, 0.0) - 1.0,
                    CONFIG["min_reputation"]
                )
                
                if self.reputation[domain_lower] <= -3 and domain_lower not in self.whitelist:
                    if domain_lower not in self.custom_domains:
                        self.custom_domains.add(domain_lower)
                        if domain_lower not in self.first_added:
                            self.first_added[domain_lower] = now_iso
                        self.stats["added"] += 1
                        return True
            else:
                self.reputation[domain_lower] = min(
                    self.reputation.get(domain_lower, 0.0) + 0.5,
                    CONFIG["max_reputation"]
                )
        
        return False
    
    def batch_analyze(self, domains: List[str]) -> int:
        added = 0
        with ThreadPoolExecutor(max_workers=CONFIG["workers"]) as executor:
            futures = {executor.submit(self.analyze_and_remember, d): d for d in domains}
            for future in as_completed(futures):
                if future.result():
                    added += 1
        return added
    
    def get_custom_domains(self) -> Set[str]:
        with self.lock:
            return self.custom_domains.copy()
    
    def save_all(self):
        with self.lock:
            try:
                with open(self.db_file, 'w') as f:
                    json.dump({
                        'reputation': self.reputation,
                        'last_seen': self.last_seen,
                        'first_added': self.first_added,
                        'version': __version__
                    }, f, indent=2)
                self._save_custom_blocklist()
                self.logger.info("All data saved successfully")
            except Exception as e:
                self.logger.error(f"Failed to save data: {e}")


def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    segments = domain.lower().split('.')
    if len(segments) < 2:
        return False
    for seg in segments:
        if not seg or len(seg) > 63:
            return False
        if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', seg):
            return False
        if seg.startswith('-') or seg.endswith('-'):
            return False
    return True


def download_with_retry(url: str, max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                timeout=CONFIG["timeout"],
                headers={'User-Agent': CONFIG["user_agent"]},
                stream=True
            )
            response.raise_for_status()
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > CONFIG["max_file_size_mb"] * 1024 * 1024:
                raise ValueError(f"File too large")
            return response
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
    return None


def download_blocklist(url: str) -> Set[str]:
    domains = set()
    try:
        response = download_with_retry(url)
        if not response:
            return set()
        
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 2:
                continue
            
            domain = parts[1].lower()
            if validate_domain(domain):
                domains.add(domain)
        
        return domains
    except Exception as e:
        print(f"  Warning: Failed to download {url}: {e}")
        return set()


def merge_blocklists(urls: List[str]) -> Set[str]:
    all_domains = set()
    with ThreadPoolExecutor(max_workers=len(urls)) as executor:
        futures = {executor.submit(download_blocklist, url): url for url in urls}
        for future in as_completed(futures):
            domains = future.result()
            all_domains.update(domains)
            print(f"  Loaded {len(domains)} domains from {futures[future]}")
    return all_domains


def write_hosts_file(domains: Set[str], output_path: Path, backup_path: Path) -> bool:
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp:
            temp_file = tmp.name
            tmp.write("# DNS Blocklist Manager v3.0\n")
            tmp.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            tmp.write(f"# Total domains: {len(domains)}\n")
            tmp.write("# ==========================================\n\n")
            
            for domain in sorted(domains):
                tmp.write(f"0.0.0.0 {domain}\n")
        
        if output_path.exists():
            shutil.copy2(output_path, backup_path)
        shutil.move(temp_file, output_path)
        return True
    except Exception as e:
        print(f"ERROR: Failed to write hosts file: {e}")
        if temp_file and os.path.exists(temp_file):
            os.unlink(temp_file)
        return False


def signal_handler(signum, frame):
    print("\n\nInterrupted by user")
    sys.exit(0)


def main() -> int:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"DNS Blocklist Manager v{__version__}")
    print(f"Author: {__author__}\n")
    print("=" * 50)
    
    logger = Logger(FILES["log"])
    logger.info(f"Starting DNS Blocklist Manager v{__version__}")
    
    ai = TrackerAI(logger)
    
    print("\n[1/4] Downloading blocklists...")
    main_domains = merge_blocklists(CONFIG["urls"])
    
    if not main_domains:
        logger.error("Failed to download any blocklist")
        return 1
    
    print(f"\n[2/4] Analyzing domains...")
    print(f"Total domains: {len(main_domains):,}")
    
    suspicious_domains = []
    with ThreadPoolExecutor(max_workers=CONFIG["workers"]) as executor:
        futures = {}
        for domain in list(main_domains)[:CONFIG["max_domains_to_analyze"]]:
            future = executor.submit(ai._is_suspicious_domain, domain)
            futures[future] = domain
        
        for future in as_completed(futures):
            is_suspicious, _ = future.result()
            if is_suspicious:
                suspicious_domains.append(futures[future])
    
    print(f"Suspicious domains found: {len(suspicious_domains):,}")
    
    print("\n[3/4] Training AI...")
    added_count = ai.batch_analyze(suspicious_domains)
    
    ai.save_all()
    
    stats = ai.stats
    print(f"\n[4/4] Results:")
    print(f"  AI Statistics:")
    print(f"    - Analyzed: {stats['analyzed']:,}")
    print(f"    - Added: {stats['added']:,}")
    print(f"    - Removed: {stats['removed']:,}")
    print(f"    - Whitelisted: {stats['whitelisted']:,}")
    print(f"    - Custom blocked: {len(ai.get_custom_domains()):,}")
    print(f"    - DNS Cache hit rate: {ai.dns_cache.hit_rate():.1f}%")
    
    ai_domains = ai.get_custom_domains()
    all_domains = main_domains.union(ai_domains)
    
    print(f"\n  Total domains to block: {len(all_domains):,}")
    print(f"    - From lists: {len(main_domains):,}")
    print(f"    - AI learned: {len(ai_domains):,}")
    
    print("\nWriting hosts file...")
    if write_hosts_file(all_domains, FILES["output"], FILES["backup"]):
        output_size_mb = FILES["output"].stat().st_size / 1024 / 1024
        print(f"\n✓ SUCCESS! Hosts file created: {FILES['output']}")
        print(f"  Size: {output_size_mb:.2f} MB")
        print(f"  Domains: {len(all_domains):,}")
        logger.info(f"Successfully created hosts file with {len(all_domains)} domains")
        return 0
    else:
        print("\n✗ ERROR: Failed to write hosts file")
        return 1


if __name__ == "__main__":
    sys.exit(main())