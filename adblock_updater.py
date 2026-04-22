#!/usr/bin/env python3
import os
import re
import sys
import logging
import urllib.request
import urllib.error
import socket
import ssl
from datetime import datetime
from typing import Set
from time import sleep

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OUTPUT_FILE = "blocklist.txt"
BACKUP_FILE = "blocklist.backup.txt"

SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt",
    "https://raw.githubusercontent.com/Windows-Warrior-Dark-Web-Defender/Blocklist/master/native-hosts.txt",
    "https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts",
    "https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts",
]

def download_url(url: str) -> bytes:
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                if len(data) < 100:
                    raise ValueError(f"Empty response: {len(data)} bytes")
                return data
        except (urllib.error.URLError, ssl.SSLError, socket.timeout) as e:
            if attempt == 0 and ("SSL" in str(e) or "certificate" in str(e)):
                try:
                    context = ssl._create_unverified_context()
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, context=context, timeout=30) as resp:
                        data = resp.read()
                        if len(data) < 100:
                            raise ValueError("Empty response")
                        return data
                except Exception:
                    pass
            if attempt == 0:
                sleep(2)
            else:
                raise Exception(f"Failed to download {url}: {e}")
    raise Exception(f"Failed to download {url}")

def parse_hosts(content: bytes) -> Set[str]:
    domains = set()
    text = content.decode('utf-8', errors='ignore')
    
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\.\-_]+)', line)
        if match:
            domain = match.group(2).lower()
            if '.' in domain and len(domain) > 3 and domain not in ['localhost', 'local']:
                domains.add(domain)
        else:
            if re.match(r'^[a-zA-Z0-9\.\-_]+\.[a-zA-Z]{2,}$', line):
                domains.add(line.lower())
    
    return domains

def load_existing(filepath: str) -> Set[str]:
    if not os.path.exists(filepath):
        return set()
    
    domains = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        domains.add(parts[1])
    except Exception:
        pass
    return domains

def save_blocklist(domains: Set[str], filepath: str) -> bool:
    try:
        sorted_domains = sorted(domains)
        
        lines = [
            f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Total: {len(sorted_domains)} domains",
            "# License: Proprietary - All Rights Reserved",
            "# Format: 0.0.0.0 domain",
            "",
        ]
        
        for domain in sorted_domains:
            lines.append(f"0.0.0.0 {domain}")
        
        content = '\n'.join(lines)
        
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as old:
                    with open(BACKUP_FILE, 'w', encoding='utf-8') as backup:
                        backup.write(old.read())
            except Exception:
                pass
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        if os.path.getsize(filepath) > 1000:
            logger.info(f"Saved: {len(sorted_domains)} domains to {filepath}")
            return True
        return False
    except Exception as e:
        logger.error(f"Save failed: {e}")
        return False

def main():
    logger.info("Starting blocklist update")
    
    all_domains = set()
    
    for url in SOURCES:
        source_name = url.split('/')[2]
        logger.info(f"Downloading: {source_name}")
        
        try:
            data = download_url(url)
            domains = parse_hosts(data)
            logger.info(f"  Got {len(domains)} domains")
            all_domains.update(domains)
        except Exception as e:
            logger.error(f"  Failed: {e}")
    
    if not all_domains:
        logger.error("No domains downloaded")
        if os.path.exists(BACKUP_FILE):
            import shutil
            shutil.copy2(BACKUP_FILE, OUTPUT_FILE)
            logger.info("Restored from backup")
            sys.exit(0)
        sys.exit(1)
    
    existing = load_existing(OUTPUT_FILE)
    new_count = len(all_domains - existing)
    removed_count = len(existing - all_domains)
    
    if new_count or removed_count:
        logger.info(f"Changes: +{new_count} -{removed_count}")
        if save_blocklist(all_domains, OUTPUT_FILE):
            logger.info("Blocklist updated successfully")
        else:
            sys.exit(1)
    else:
        logger.info("No changes, blocklist is up to date")
    
    sys.exit(0)

if __name__ == "__main__":
    main()
