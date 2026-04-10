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
from typing import Dict, List, Optional, Set, Iterable
from functools import lru_cache
import time
import signal
import json
from socket import timeout as SocketTimeout
from datetime import datetime
from contextlib import contextmanager
import tempfile
import shutil

# ============================================================================
# КОНФИГ - ОПТИМИЗИРОВАН ПОД ГИТХАБ
# ============================================================================

@dataclass
class Config:
    max_domains: int = 500_000  # Ограничиваем 500к доменов (будет ~15-20 МБ)
    queue_size: int = 100_000
    workers: int = 5  # Меньше воркеров для GitHub
    fetch_workers: int = 5
    max_retries: int = 2
    retry_backoff: float = 1.0
    fetch_timeout: int = 20
    queue_timeout: float = 0.5
    shutdown_timeout: float = 5.0
    max_output_size_mb: int = 50  # Жесткий лимит 50 МБ
    log_level: str = "INFO"
    sources: List[str] = field(default_factory=lambda: [
        # ТОП-5 лучших источников, не дублирующихся между собой
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",  # База
        "https://someonewhocares.org/hosts/zero/hosts",  # Хороший доп
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",  # Реклама
        "https://raw.githubusercontent.com/kadiremrah/Lists/master/everything.txt",  # Всё в одном
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",  # Малварь
    ])
    state_file: Optional[Path] = None
    backup_output: bool = False  # Отключаем бэкапы, экономим место
    dead_letter_limit: int = 1000

# ============================================================================
# ЛОГГИНГ (минимальный)
# ============================================================================

logging.basicConfig(
    level=getattr(logging, "INFO"),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# ВАЛИДАЦИЯ ДОМЕНОВ
# ============================================================================

DOMAIN_REGEX = re.compile(
    r'^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*'
    r'(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-))$'
)

@lru_cache(maxsize=100000)
def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    domain = domain.strip().lower().rstrip('.')
    if not DOMAIN_REGEX.match(domain):
        return False
    labels = domain.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or label[0] == '-' or label[-1] == '-':
            return False
    return True

# ============================================================================
# ОСНОВНАЯ ЛОГИКА
# ============================================================================

class DomainProcessor:
    def __init__(self, max_domains: int):
        self.max_domains = max_domains
        self.domains: Set[str] = set()
        self.queue: queue.Queue = queue.Queue(maxsize=100000)
        self.stats = {'added': 0, 'duplicates': 0}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.active_tasks = 0
        self.tasks_lock = threading.Lock()
        
    def start(self, workers: int):
        for i in range(workers):
            t = threading.Thread(target=self._worker, name=f"w-{i}", daemon=True)
            t.start()
    
    def _worker(self):
        while not self.stop.is_set():
            try:
                domain = self.queue.get(timeout=0.5)
                
                if is_valid_domain(domain):
                    with self.lock:
                        if domain not in self.domains and len(self.domains) < self.max_domains:
                            self.domains.add(domain)
                            self.stats['added'] += 1
                        elif domain in self.domains:
                            self.stats['duplicates'] += 1
                
                self.queue.task_done()
                with self.tasks_lock:
                    self.active_tasks -= 1
                    
            except queue.Empty:
                continue
            except Exception:
                self.queue.task_done()
                with self.tasks_lock:
                    self.active_tasks -= 1
    
    def submit_batch(self, domains: List[str]):
        for d in domains:
            with self.tasks_lock:
                self.active_tasks += 1
            self.queue.put(d)
    
    def shutdown(self):
        self.stop.set()
    
    def wait(self, timeout: int = 60):
        start = time.time()
        while time.time() - start < timeout:
            with self.tasks_lock:
                if self.active_tasks == 0 and self.queue.empty():
                    break
            time.sleep(0.5)
    
    def get_domains(self) -> Set[str]:
        with self.lock:
            return self.domains.copy()
    
    def get_stats(self) -> Dict:
        with self.lock:
            return self.stats.copy()

def fetch_url(url: str) -> Optional[bytes]:
    """Загрузка с ретраями"""
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; BlocklistUpdater/1.0)'}
    req = urllib.request.Request(url, headers=headers)
    
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read()
        except Exception as e:
            if attempt == 0:
                time.sleep(1)
            else:
                logger.error(f"Failed {url}: {e}")
                return None
    return None

def parse_hosts(content: bytes) -> List[str]:
    """Парсинг hosts файлов"""
    domains = []
    try:
        text = content.decode('utf-8', errors='ignore')
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in '#;![':
                continue
            
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1', '::1'):
                domain = parts[1]
            elif len(parts) == 1 and '.' in parts[0]:
                domain = parts[0]
            else:
                continue
            
            domain = domain.lower().rstrip('.')
            if is_valid_domain(domain):
                domains.append(domain)
    except Exception:
        pass
    return domains

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true", help="Скачать списки")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Выходной файл")
    parser.add_argument("-f", "--format", choices=['dnsmasq', 'plain'], default='plain')
    args = parser.parse_args()
    
    config = Config()
    processor = DomainProcessor(config.max_domains)
    processor.start(config.workers)
    
    if args.fetch:
        logger.info(f"Загрузка {len(config.sources)} источников...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.fetch_workers) as executor:
            futures = [executor.submit(fetch_url, source) for source in config.sources]
            
            for future in concurrent.futures.as_completed(futures):
                content = future.result()
                if content:
                    domains = parse_hosts(content)
                    if domains:
                        processor.submit_batch(domains)
                        logger.info(f"+{len(domains)} доменов")
    
    processor.wait()
    domains = processor.get_domains()
    stats = processor.get_stats()
    
    if not domains:
        logger.error("Нет доменов!")
        sys.exit(1)
    
    # Сохраняем результат
    output = '\n'.join(sorted(domains)) if args.format == 'plain' else '\n'.join(f"address=/{d}/0.0.0.0" for d in sorted(domains))
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.tmp', delete=False) as f:
        f.write(output)
        temp_path = Path(f.name)
    
    shutil.move(str(temp_path), args.output)
    
    size_mb = args.output.stat().st_size / (1024 * 1024)
    logger.info(f"✅ Готово: {len(domains)} доменов, {size_mb:.1f} МБ")
    logger.info(f"📊 Добавлено: {stats['added']}, Дублей: {stats['duplicates']}")
    
    if size_mb > 25:
        logger.warning(f"⚠️ Список {size_mb:.1f} МБ, следи за лимитами GitHub!")

if __name__ == "__main__":
    main()