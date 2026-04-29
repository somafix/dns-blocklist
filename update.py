import requests
import re
from datetime import datetime
import hashlib
import os
import tempfile
import shutil
import json
import math
from collections import defaultdict
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
    'click', 'adserver', 'doubleclick', 'googlead', 'facebook',
    'criteo', 'taboola', 'outbrain', 'exelator', 'adsrv',
    'ssp', 'dsp', 'rtb', 'bid', 'impression', 'beacon', 'counter'
]

_SHORT_TLDS = {'com', 'net', 'org', 'ru', 'cn'}


class TrackerAI:
    def __init__(self) -> None:
        self._db_file = Path(AI_DB_FILE)
        self._blocklist_file = Path(AI_BLOCKLIST_FILE)
        self._reputation: Dict[str, float] = {}
        self._custom_domains: Set[str] = set()
        self._load_db()
        self._load_custom_blocklist()

    def _load_db(self) -> None:
        if not self._db_file.exists():
            return
        
        try:
            with open(self._db_file, 'r') as f:
                data = json.load(f)
                self._reputation = data.get('reputation', {})
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

    def _save_custom_blocklist(self) -> None:
        with open(self._blocklist_file, 'w') as f:
            f.write(f"# AI Self-Learning Blocklist\n")
            f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(self._custom_domains)}\n\n")
            for domain in sorted(self._custom_domains):
                f.write(f"0.0.0.0 {domain}\n")

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        if not s:
            return 0.0
        
        length = len(s)
        prob = [s.count(c) / length for c in set(s)]
        return -sum(p * math.log(p) / math.log(2) for p in prob)

    def _is_suspicious_domain(self, domain: str) -> bool:
        score = 0
        parts = domain.split('.')
        
        if len(parts) > 5:
            score += 2
        
        for part in parts[:-2]:
            if len(part) > 20:
                score += 1
            if re.search(r'\d{5,}', part):
                score += 2
            if self._calculate_entropy(part) > 4.0:
                score += 2
            if '_' in part:
                score += 1
        
        domain_lower = domain.lower()
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                score += 1
        
        main_part = parts[-2] if len(parts) >= 2 else parts[0]
        if len(main_part) <= 3 and main_part not in _SHORT_TLDS:
            score += 2
        
        return score >= 5

    def analyze_and_remember(self, domain: str) -> bool:
        if domain in self._custom_domains:
            return True
        
        if domain in self._reputation and self._reputation[domain] <= -3:
            self._custom_domains.add(domain)
            return True
        
        if self._is_suspicious_domain(domain):
            self._reputation[domain] = self._reputation.get(domain, 0.0) - 2
            self._custom_domains.add(domain)
            return True
        
        self._reputation[domain] = self._reputation.get(domain, 0.0) + 0.5
        return False

    def get_custom_domains(self) -> Set[str]:
        return self._custom_domains.copy()

    def save_all(self) -> None:
        with open(self._db_file, 'w') as f:
            json.dump({'reputation': self._reputation}, f, indent=2)
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
        return 1
    
    ai_domains = ai.get_custom_domains()
    
    for domain in main_domains:
        ai.analyze_and_remember(domain)
    
    ai.save_all()
    ai_domains = ai.get_custom_domains()
    
    all_domains = main_domains.union(ai_domains)
    
    output_path = Path(OUTPUT_FILE)
    backup_path = Path(BACKUP_FILE)
    
    if not write_hosts_file(all_domains, output_path, backup_path):
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
