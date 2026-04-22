#!/usr/bin/env python3
"""
AdBlock List Manager - Working Version
"""

import hashlib
import json
import logging
import os
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict
import requests

# Настройка логов
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Источники блоклистов (реально работающие)
SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0",
    "https://someonewhocares.org/hosts/zero/hosts",
]

class BlocklistManager:
    def __init__(self):
        self.output_file = "blocklist.txt"
        self.backup_dir = "backups"
        Path(self.backup_dir).mkdir(exist_ok=True)
        
    def download_list(self, url: str) -> Set[str]:
        """Скачать и распарсить список блокировки"""
        domains = set()
        try:
            logger.info(f"Downloading: {url}")
            response = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            
            for line in response.text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('!'):
                    continue
                
                # Ищем домены в формате 0.0.0.0 domain.com
                match = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\.\-_]+)', line)
                if match:
                    domain = match.group(1).lower()
                    if self.is_valid_domain(domain):
                        domains.add(domain)
                # Ищем просто домены
                elif re.match(r'^[a-zA-Z0-9\.\-_]+\.[a-zA-Z]{2,}$', line):
                    domains.add(line.lower())
                        
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            
        return domains
    
    def is_valid_domain(self, domain: str) -> bool:
        """Проверка валидности домена"""
        if len(domain) > 253:
            return False
        if '..' in domain:
            return False
        if domain.startswith('.') or domain.endswith('.'):
            return False
        return True
    
    def update(self) -> bool:
        """Обновление блоклиста"""
        logger.info("Starting blocklist update...")
        
        # Создаем бэкап
        if os.path.exists(self.output_file):
            backup_name = f"{self.backup_dir}/blocklist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            shutil.copy2(self.output_file, backup_name)
            logger.info(f"Backup created: {backup_name}")
        
        # Собираем все домены
        all_domains = set()
        for url in SOURCES:
            domains = self.download_list(url)
            all_domains.update(domains)
            logger.info(f"Added {len(domains)} domains from {url}")
        
        if not all_domains:
            logger.error("No domains downloaded!")
            return False
        
        # Сортируем и сохраняем
        sorted_domains = sorted(all_domains)
        
        with open(self.output_file, 'w') as f:
            f.write(f"# Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total domains: {len(sorted_domains)}\n")
            f.write("# =============================================\n\n")
            
            for domain in sorted_domains:
                f.write(f"0.0.0.0 {domain}\n")
        
        # Сохраняем простой список доменов
        with open("domains.txt", 'w') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")
        
        logger.info(f"Blocklist updated! Total domains: {len(sorted_domains)}")
        return True

def main():
    manager = BlocklistManager()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        success = manager.update()
        sys.exit(0 if success else 1)
    else:
        # Раз в сутки
        while True:
            manager.update()
            logger.info("Waiting 24 hours...")
            time.sleep(86400)

if __name__ == "__main__":
    main()