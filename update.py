import requests
import re
from datetime import datetime
import hashlib
import os
import sys
import tempfile
import shutil
import json
import math
from typing import Set, Dict, Optional
from pathlib import Path

URL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt"
AI_BLOCKLIST_FILE = "ai_custom_blocklist.txt"
OUTPUT_FILE = "hosts.txt"
BACKUP_FILE = "hosts.backup"
AI_DB_FILE = "ai_trackers.json"

TIMEOUT = 30
MAX_FILE_SIZE = 50 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

_SUSPICIOUS_KEYWORDS = [
    'track', 'analytics', 'metrics', 'stat', 'pixel', 'tag',
    'click', 'adserver', 'doubleclick', 'googlead', 'google-analytics',
    'facebook', 'criteo', 'taboola', 'outbrain', 'exelator', 'adsrv',
    'ssp', 'dsp', 'rtb', 'bid', 'impression', 'beacon', 'counter',
    'adzerk', 'appnexus', 'adnxs', 'rubicon', 'openx', 'pubmatic',
    'indexww', 'contextweb', 'monetize', 'mediation', 'adsystem',
    'clicktrack', 'trk', 'pixel', 'metrics'
]

_SHORT_TLDS = {'com', 'net', 'org', 'ru', 'cn'}

_LEGIT_EXCEPTIONS = {'cloudflare', 'amazonaws', 'googleapis', 'github', 'cdn', 'cloudfront'}


class TrackerAI:
    def __init__(self, auto_cleanup_days: int = 30, reputation_threshold: float = 5.0) -> None:
        self._db_file = Path(AI_DB_FILE)
        self._blocklist_file = Path(AI_BLOCKLIST_FILE)
        self._whitelist_file = Path("ai_whitelist.txt")
        self._reputation: Dict[str, float] = {}
        self._last_seen: Dict[str, str] = {}
        self._first_added: Dict[str, str] = {}
        self._custom_domains: Set[str] = set()
        self._whitelist: Set[str] = set()
        self._auto_cleanup_days = auto_cleanup_days
        self._reputation_threshold = reputation_threshold
        self._load_db()
        self._load_custom_blocklist()
        self._load_whitelist()
        self._cleanup_false_positives()

    def _load_db(self) -> None:
        if not self._db_file.exists():
            return
        try:
            with open(self._db_file, 'r') as f:
                data = json.load(f)
                self._reputation = data.get('reputation', {})
                self._last_seen = data.get('last_seen', {})
                self._first_added = data.get('first_added', {})
        except (json.JSONDecodeError, IOError):
            pass

    def _load_custom_blocklist(self) -> None:
        if not self._blocklist_file.exists():
            return
        try:
            with open(self._blocklist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('0.0.0.0 '):
                        domain = line[8:]
                    else:
                        domain = line
                    self._custom_domains.add(domain.lower())
        except IOError:
            pass

    def _load_whitelist(self) -> None:
        if not self._whitelist_file.exists():
            self._whitelist_file.touch()
            return
        try:
            with open(self._whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        self._whitelist.add(line)
        except IOError:
            pass

    def _save_custom_blocklist(self) -> None:
        with open(self._blocklist_file, 'w') as f:
            f.write(f"# AI Self-Learning Blocklist\n")
            f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(self._custom_domains)}\n\n")
            for domain in sorted(self._custom_domains):
                f.write(f"0.0.0.0 {domain}\n")

    def _cleanup_false_positives(self) -> None:
        to_remove = []
        now = datetime.now()
        for domain in self._custom_domains:
            if domain in self._whitelist:
                continue
            rep = self._reputation.get(domain, 0.0)
            first_added_str = self._first_added.get(domain)
            last_seen_str = self._last_seen.get(domain)
            if rep >= self._reputation_threshold:
                to_remove.append(domain)
                continue
            if first_added_str and last_seen_str:
                try:
                    first_added = datetime.fromisoformat(first_added_str)
                    last_seen = datetime.fromisoformat(last_seen_str)
                    days_since_added = (now - first_added).days
                    days_since_last_seen = (now - last_seen).days
                    if days_since_added > self._auto_cleanup_days and days_since_last_seen > 7 and rep > -2:
                        to_remove.append(domain)
                except (ValueError, TypeError):
                    pass
        for domain in to_remove:
            self._custom_domains.discard(domain)
        if to_remove:
            print(f"Cleaned up {len(to_remove)} false positives")

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        if not s:
            return 0.0
        length = len(s)
        prob = [s.count(c) / length for c in set(s)]
        return -sum(p * math.log(p) / math.log(2) for p in prob)

    def _is_suspicious_domain(self, domain: str) -> bool:
        domain_lower = domain.lower()
        
        for exc in _LEGIT_EXCEPTIONS:
            if exc in domain_lower:
                return False
        
        score = 0
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
        
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                score += 2
        
        suspicious_patterns = [
            r'^ad[\d\-\.]', r'^ads[\d\-\.]', r'\.ad[\d\-\.]', r'\.ads[\d\-\.]',
            r'-ad[\-\.]', r'-ads[\-\.]', r'trk[\-\.]', r'track[\-\.]',
            r'click[\-\.]', r'redirect[\-\.]', r'banner[\-\.]',
            r'^[a-z0-9]{20,}\.', r'[0-9a-f]{16,}'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain_lower):
                score += 1
        
        main_part = parts[-2] if len(parts) >= 2 else parts[0]
        if len(main_part) <= 3 and main_part not in _SHORT_TLDS:
            score += 2
        
        return score >= 4

    def analyze_and_remember(self, domain: str) -> bool:
        now_iso = datetime.now().isoformat()
        domain_lower = domain.lower()
        
        self._last_seen[domain_lower] = now_iso
        
        if domain_lower in self._whitelist:
            self._reputation[domain_lower] = min(self._reputation.get(domain_lower, 0.0) + 1.0, 10.0)
            if domain_lower in self._custom_domains:
                self._custom_domains.discard(domain_lower)
            return False
        
        if domain_lower in self._custom_domains:
            if not self._is_suspicious_domain(domain_lower):
                self._reputation[domain_lower] = min(self._reputation.get(domain_lower, 0.0) + 1.0, 10.0)
            return True
        
        if domain_lower in self._reputation and self._reputation[domain_lower] <= -3:
            if domain_lower not in self._whitelist:
                self._custom_domains.add(domain_lower)
                if domain_lower not in self._first_added:
                    self._first_added[domain_lower] = now_iso
                return True
        
        if self._is_suspicious_domain(domain_lower):
            self._reputation[domain_lower] = self._reputation.get(domain_lower, 0.0) - 2
            self._reputation[domain_lower] = max(self._reputation[domain_lower], -10.0)
            if self._reputation[domain_lower] <= -3 and domain_lower not in self._whitelist:
                self._custom_domains.add(domain_lower)
                if domain_lower not in self._first_added:
                    self._first_added[domain_lower] = now_iso
                return True
        else:
            self._reputation[domain_lower] = self._reputation.get(domain_lower, 0.0) + 0.5
            self._reputation[domain_lower] = min(self._reputation[domain_lower], 10.0)
        
        return False

    def get_custom_domains(self) -> Set[str]:
        return self._custom_domains.copy()

    def save_all(self) -> None:
        with open(self._db_file, 'w') as f:
            json.dump({
                'reputation': self._reputation,
                'last_seen': self._last_seen,
                'first_added': self._first_added
            }, f, indent=2)
        self._save_custom_blocklist()


def get_file_hash(filepath: Path) -> Optional[str]:
    if not filepath.exists():
        return None
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()


def validate_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    segments = domain.lower().split('.')
    for seg in segments:
        if not seg or len(seg) > 63:
            return False
        if len(seg) == 1:
            if not seg.isalnum():
                return False
        else:
            if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', seg):
                return False
        if seg.startswith('-') or seg.endswith('-'):
            return False
    return True


def download_blocklist(url: str) -> Set[str]:
    domains = set()
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            headers={'User-Agent': USER_AGENT},
            stream=True
        )
        response.raise_for_status()
        content_length = response.headers.get('content-length')
        if content_length and int(content_length) > MAX_FILE_SIZE:
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
    except (requests.RequestException, IOError):
        return set()


def write_hosts_file(domains: Set[str], output_path: Path, backup_path: Path) -> bool:
    temp_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tmp:
            temp_file = tmp.name
            tmp.write("# DNS Blocklist: HaGeZi PRO++ + AI Self-Learning\n")
            tmp.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            tmp.write(f"# Total domains: {len(domains)}\n\n")
            for domain in sorted(domains):
                tmp.write(f"0.0.0.0 {domain}\n")
        if output_path.exists():
            old_hash = get_file_hash(output_path)
            shutil.copy2(output_path, backup_path)
            shutil.move(temp_file, output_path)
            new_hash = get_file_hash(output_path)
            return old_hash != new_hash
        else:
            shutil.move(temp_file, output_path)
            return True
    except (IOError, OSError):
        if temp_file and os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except OSError:
                pass
        return False


def main() -> int:
    ai = TrackerAI()
    main_domains = download_blocklist(URL)
    if not main_domains:
        print("ERROR: Failed to download main blocklist")
        return 1
    for domain in main_domains:
        ai.analyze_and_remember(domain)
    ai.save_all()
    ai_domains = ai.get_custom_domains()
    all_domains = main_domains.union(ai_domains)
    output_path = Path(OUTPUT_FILE)
    backup_path = Path(BACKUP_FILE)
    if not write_hosts_file(all_domains, output_path, backup_path):
        print("ERROR: Failed to write hosts file")
        return 1
    print(f"SUCCESS: {len(all_domains)} domains blocked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
