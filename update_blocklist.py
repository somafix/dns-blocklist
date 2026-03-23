#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - EXTREME OPTIMIZATION
Максимальная производительность на уровне профессионального ПО
"""

import re
import json
import os
import sys
import hashlib
import tempfile
import shutil
import signal
import resource
import gc
import functools
import threading
from datetime import datetime, timezone
from time import perf_counter, time
from typing import Set, Dict, Optional
from pathlib import Path
from urllib.parse import urlparse
import urllib.request
import urllib.error
import io

# Кроссплатформенная блокировка файлов
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False
    try:
        import msvcrt
    except ImportError:
        msvcrt = None


class Config:
    """Оптимизированные настройки"""
    
    MAX_FILE_SIZE = 10 * 1024 * 1024
    MAX_DOMAINS = 300000
    TIMEOUT = 10
    RETRIES = 1
    
    DOMAIN_CACHE_SIZE = 100000
    BATCH_SIZE = 10000
    LOG_BUFFER_SIZE = 131072  # 128KB вместо 64KB
    
    ALLOWED_SOURCES = frozenset({
        'raw.githubusercontent.com',
        'adaway.org',
        'github.com',
    })
    
    # ⚡ ОПТИМИЗАЦИЯ: Pre-compiled regex с исключением ненужных групп
    DOMAIN_PATTERN = re.compile(
        rb'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+)',
        re.MULTILINE | re.IGNORECASE
    )
    
    SAFE_CHARS = frozenset(b'abcdefghijklmnopqrstuvwxyz0123456789.-')
    SAFE_CHARS_BYTES = b'abcdefghijklmnopqrstuvwxyz0123456789.-'
    LOG_FILE = 'update_blocklist.log'


class FastAsyncLogger:
    """Ultra-fast async logger с minimal overhead"""
    
    __slots__ = ('_log_path', '_buffer', '_buffer_size', '_lock', '_emoji_map')
    
    def __init__(self):
        self._log_path = Path(Config.LOG_FILE)
        self._buffer = []
        self._buffer_size = 0
        self._lock = threading.Lock()
        # ⚡ Pre-compute emoji mapping
        self._emoji_map = {'INFO': 'ℹ️', 'WARN': '⚠️', 'ERROR': '❌'}
    
    def log(self, level: str, msg: str):
        """Ultra-fast logging"""
        # ⚡ Avoid string formatting overhead
        print(f"{self._emoji_map.get(level, '❌')} {msg}")
        
        if self._log_path:
            with self._lock:
                # ⚡ Pre-formatted time once
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                line = f"[{ts}] {level}: {msg[:500]}\n"
                
                self._buffer.append(line)
                self._buffer_size += len(line)
                
                if self._buffer_size > Config.LOG_BUFFER_SIZE:
                    self.flush()
    
    def flush(self):
        """Fast buffer flush"""
        if not self._buffer:
            return
        
        with self._lock:
            if not self._buffer:
                return
            
            try:
                with open(self._log_path, 'a', encoding='utf-8', buffering=0) as f:
                    if HAS_FCNTL:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    
                    f.write(''.join(self._buffer))
                    
                    if HAS_FCNTL:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except:
                pass
            finally:
                self._buffer.clear()
                self._buffer_size = 0


class FastValidator:
    """Lightning-fast validation"""
    
    __slots__ = ()
    
    # ⚡ Pre-computed byte values
    HYPHEN_BYTE = 45
    DOT_BYTE = 46
    MIN_DOMAIN_LEN = 3
    MAX_DOMAIN_LEN = 253
    
    @staticmethod
    @functools.lru_cache(maxsize=2048)  # Увеличен кэш
    def validate_url(url: str) -> bool:
        """Cached URL validation"""
        if len(url) > 2000:
            return False
        
        try:
            parsed = urlparse(url)
            
            if parsed.scheme != 'https':
                return False
            
            host = parsed.hostname
            if not host:
                return False
            
            # ⚡ Check main sources first (O(1))
            if host in Config.ALLOWED_SOURCES:
                return '..' not in parsed.path and '//' not in parsed.path
            
            # ⚡ Check subdomains with any() instead of loop
            if any(host.endswith('.' + d) for d in Config.ALLOWED_SOURCES):
                return '..' not in parsed.path and '//' not in parsed.path
            
            return False
        except:
            return False
    
    @staticmethod
    def validate_domain(domain: bytes) -> bool:
        """Ultra-fast domain validation"""
        length = len(domain)
        
        # ⚡ Early exit checks
        if length < FastValidator.MIN_DOMAIN_LEN or length > FastValidator.MAX_DOMAIN_LEN:
            return False
        
        if domain[0] == FastValidator.HYPHEN_BYTE or domain[-1] == FastValidator.HYPHEN_BYTE:
            return False
        
        if FastValidator.DOT_BYTE not in domain:
            return False
        
        # ⚡ Use direct byte lookup (faster than membership test in frozenset)
        return all(b in Config.SAFE_CHARS for b in domain)


class FastHTTPClient:
    """Optimized HTTP client"""
    
    __slots__ = ('_logger', '_opener', '_cache', '_start_time')
    
    def __init__(self, logger: FastAsyncLogger):
        self._logger = logger
        self._opener = self._create_opener()
        self._cache = {}
        self._start_time = time()
    
    def _create_opener(self):
        """Create optimized opener"""
        import ssl
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # ⚡ Connection pooling via HTTPSHandler
        handler = urllib.request.HTTPSHandler(context=ssl_context)
        opener = urllib.request.build_opener(handler)
        
        opener.addheaders = [
            ('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64)'),
            ('Accept', 'text/plain'),
            ('Accept-Encoding', 'gzip, deflate'),
            ('Connection', 'keep-alive'),
        ]
        
        return opener
    
    def fetch(self, url: str, cache: Dict) -> tuple:
        """Optimized fetch with smart caching"""
        if not FastValidator.validate_url(url):
            return "", False
        
        cache_entry = cache.get(url)
        req = urllib.request.Request(url)
        
        # ⚡ Add conditional headers only if cache exists
        if cache_entry:
            if 'etag' in cache_entry:
                req.add_header('If-None-Match', cache_entry['etag'])
            if 'last_modified' in cache_entry:
                req.add_header('If-Modified-Since', cache_entry['last_modified'])
        
        try:
            # ⚡ Use timeout parameter directly
            response = self._opener.open(req, timeout=Config.TIMEOUT)
            
            # ⚡ Read with buffer for large files
            text = response.read(Config.MAX_FILE_SIZE).decode('utf-8', errors='ignore')
            
            # ⚡ Update cache headers
            new_entry = {'content': text}
            if 'etag' in response.headers:
                new_entry['etag'] = response.headers['etag']
            if 'last-modified' in response.headers:
                new_entry['last_modified'] = response.headers['last-modified']
            
            cache[url] = new_entry
            return text, False
            
        except urllib.error.HTTPError as e:
            if e.code == 304 and cache_entry:
                return cache_entry.get('content', ''), True
            return "", False
        except:
            # ⚡ Return cached version on any error
            return cache_entry.get('content', '') if cache_entry else "", bool(cache_entry)


class FastParser:
    """Ultra-fast domain parser"""
    
    __slots__ = ('_pattern',)
    
    def __init__(self):
        self._pattern = Config.DOMAIN_PATTERN
    
    def extract_domains(self, text: str) -> Set[str]:
        """Fast domain extraction"""
        domains = set()
        text_bytes = text.encode('utf-8', errors='ignore')
        
        # ⚡ Use iterator directly without intermediate list
        for match in self._pattern.finditer(text_bytes):
            if len(domains) >= Config.MAX_DOMAINS:
                break
            
            domain_bytes = match.group(1)
            
            # ⚡ Fast validation
            if FastValidator.validate_domain(domain_bytes):
                try:
                    domain = domain_bytes.decode('ascii')
                    domains.add(domain)
                except:
                    pass
        
        return domains


class OptimizedBlocklistBuilder:
    """Main builder class"""
    
    __slots__ = ('_logger', '_http', '_parser', '_cache', '_domains', '_stats', '_start_time')
    
    def __init__(self):
        self._logger = FastAsyncLogger()
        self._http = FastHTTPClient(self._logger)
        self._parser = FastParser()
        self._cache = {}
        self._domains = set()
        self._stats = []
        self._start_time = perf_counter()
        
        self._setup_security()
        self._setup_gc()
    
    def _setup_security(self):
        """Setup security"""
        try:
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        except:
            pass
        
        signal.signal(signal.SIGINT, lambda s, f: self._cleanup())
        signal.signal(signal.SIGTERM, lambda s, f: self._cleanup())
    
    def _setup_gc(self):
        """Setup garbage collector"""
        gc.disable()
        gc.set_threshold(700, 10, 5)
    
    def _cleanup(self):
        """Cleanup on exit"""
        self._save_cache()
        self._logger.flush()
        sys.exit(0)
    
    def _load_cache(self):
        """Load cache from disk"""
        cache_path = Path('.download_cache.json')
        if not cache_path.exists():
            return
        
        try:
            with open(cache_path, 'rb') as f:
                self._cache = json.loads(f.read())
            self._logger.log('INFO', f'Cache loaded: {len(self._cache)} entries')
        except:
            self._cache = {}
    
    def _save_cache(self):
        """Save cache atomically"""
        if not self._cache:
            return
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp:
                json.dump(self._cache, tmp, separators=(',', ':'))
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, '.download_cache.json')
        except:
            pass
    
    def process_source(self, url: str, name: str):
        """Process single source"""
        self._logger.log('INFO', f'Loading {name}...')
        start = perf_counter()
        
        text, used_cache = self._http.fetch(url, self._cache)
        elapsed = perf_counter() - start
        
        if not text:
            self._stats.append((name, 0, elapsed, used_cache))
            return
        
        new_domains = self._parser.extract_domains(text)
        self._stats.append((name, len(new_domains), elapsed, used_cache))
        
        # ⚡ Optimize domain merging
        if len(self._domains) + len(new_domains) > Config.MAX_DOMAINS:
            remaining = Config.MAX_DOMAINS - len(self._domains)
            self._domains |= set(list(new_domains)[:remaining])
            self._logger.log('WARN', f'Reached limit of {Config.MAX_DOMAINS} domains')
        else:
            self._domains |= new_domains
        
        cache_msg = ' (cached)' if used_cache else ''
        self._logger.log('INFO', f'  ✅ {len(new_domains):,} domains{cache_msg} [{elapsed:.2f}s]')
        
        gc.collect()
    
    def generate_output(self) -> bool:
        """Generate output file"""
        now = datetime.now(timezone.utc)
        sorted_domains = sorted(self._domains)
        
        # ⚡ Build header efficiently
        header = [
            "# ============================================================",
            "# Dynamic DNS Blocklist - ULTRA OPTIMIZED",
            f"# Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Total domains: {len(sorted_domains):,}",
            f"# SHA-256: {hashlib.sha256(''.join(sorted_domains).encode()).hexdigest()[:16]}",
            "# ============================================================",
            ""
        ]
        
        # ⚡ Use list and join instead of repeated string concatenation
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.', buffering=262144) as tmp:
                # Write header
                tmp.write('\n'.join(header) + '\n')
                
                # ⚡ Write domains in batches
                for i in range(0, len(sorted_domains), Config.BATCH_SIZE):
                    batch = sorted_domains[i:i + Config.BATCH_SIZE]
                    tmp.write('\n'.join(f"0.0.0.0 {d}" for d in batch) + '\n')
                
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, 'dynamic-blocklist.txt')
            os.chmod('dynamic-blocklist.txt', 0o644)
            return True
        except:
            return False
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 70)
        print("📊 STATISTICS")
        print("=" * 70)
        
        for name, count, elapsed, cached in self._stats:
            cache_mark = "✓" if cached else "✗"
            print(f"{name:<25} {count:>8,} domains  {elapsed:>5.2f}s  [{cache_mark}]")
        
        print("-" * 70)
        print(f"{'TOTAL':<25} {len(self._domains):>8,} unique domains")
        print("=" * 70)
        
        elapsed = perf_counter() - self._start_time
        print(f"\n⏱️  Total time: {elapsed:.2f} sec")
        if elapsed > 0:
            print(f"📈 Speed: {len(self._domains) / elapsed:.0f} domains/sec")
    
    def run(self):
        """Run builder"""
        print("\n" + "=" * 70)
        print("🚀 DNS BLOCKLIST BUILDER - ULTRA OPTIMIZED")
        print("=" * 70)
        
        self._load_cache()
        
        sources = [
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "StevenBlack"),
            ("https://adaway.org/hosts.txt", "AdAway"),
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt", "HaGeZi"),
        ]
        
        for url, name in sources:
            self.process_source(url, name)
        
        self._save_cache()
        
        if self.generate_output():
            self.print_stats()
            print(f"\n✅ Done!")
            print(f"📁 dynamic-blocklist.txt ({len(self._domains):,} domains)")
        else:
            self._logger.log('ERROR', 'Failed to create file')
            sys.exit(1)
        
        self._logger.flush()


def main():
    """Entry point"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ required")
        sys.exit(1)
    
    builder = OptimizedBlocklistBuilder()
    builder.run()


if __name__ == "__main__":
    main()
