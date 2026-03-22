#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - Безопасная версия
Защита от основных угроз без излишеств
"""

import re
import urllib.request
import urllib.error
import json
import os
import sys
import hashlib
import tempfile
import shutil
import fcntl
import resource
import signal
from datetime import datetime, timezone
from time import perf_counter
from typing import Set, Dict, Optional
from pathlib import Path
from urllib.parse import urlparse

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

class Config:
    # Безопасные лимиты
    MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
    MAX_DOMAINS = 500000
    TIMEOUT = 20
    MAX_RETRIES = 2
    
    # Разрешённые источники (только эти домены!)
    ALLOWED_SOURCES = {
        'raw.githubusercontent.com',
        'adaway.org',
        'github.com',
    }
    
    # Защита от опасных паттернов
    DANGEROUS_PATTERNS = [
        r'\.\./',  # path traversal
        r'[\x00-\x1f]',  # control chars
        r'[;&|`$]',  # shell metacharacters
    ]

# ============================================================================
# БЕЗОПАСНЫЙ ЛОГГЕР
# ============================================================================

class Logger:
    def __init__(self):
        self.log_file = "blocklist.log"
        self._setup_logging()
    
    def _setup_logging(self):
        # Очищаем старый лог если слишком большой
        if os.path.exists(self.log_file):
            if os.path.getsize(self.log_file) > 1024 * 1024:  # 1MB
                os.rename(self.log_file, f"{self.log_file}.old")
    
    def _write(self, level: str, msg: str):
        # Очищаем сообщение от опасных символов
        for pattern in Config.DANGEROUS_PATTERNS:
            msg = re.sub(pattern, '?', msg)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {msg[:500]}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(log_entry)
                f.flush()
                os.fsync(f.fileno())
        except:
            pass  # Не критично
    
    def info(self, msg: str):
        self._write("INFO", msg)
        print(f"ℹ️  {msg}")
    
    def warning(self, msg: str):
        self._write("WARNING", msg)
        print(f"⚠️  {msg}")
    
    def error(self, msg: str):
        self._write("ERROR", msg)
        print(f"❌ {msg}")

# ============================================================================
# ВАЛИДАТОР
# ============================================================================

class Validator:
    @staticmethod
    def validate_url(url: str) -> bool:
        """Проверка URL на безопасность"""
        if len(url) > 2000:
            return False
        
        try:
            parsed = urlparse(url)
            
            # Только HTTPS
            if parsed.scheme != 'https':
                return False
            
            # Проверка хоста
            hostname = parsed.hostname
            if not hostname:
                return False
            
            # Проверка в белом списке
            allowed = False
            for allowed_domain in Config.ALLOWED_SOURCES:
                if hostname == allowed_domain or hostname.endswith(f'.{allowed_domain}'):
                    allowed = True
                    break
            
            if not allowed:
                return False
            
            # Проверка path traversal
            if '..' in parsed.path or '//' in parsed.path:
                return False
            
            return True
            
        except:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Проверка домена"""
        if not domain or len(domain) > 253:
            return False
        
        domain = domain.lower().strip()
        
        # Только разрешённые символы
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        # Запрет на опасные символы
        if any(c in domain for c in [';', '|', '&', '$', '`', '(', ')', '<', '>']):
            return False
        
        # Запрет на IP адреса
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # Не может начинаться или заканчиваться на -
        if domain.startswith('-') or domain.endswith('-'):
            return False
        
        # Должен содержать точку
        if '.' not in domain:
            return False
        
        return True

# ============================================================================
# БЕЗОПАСНЫЙ HTTP КЛИЕНТ
# ============================================================================

class SafeHTTPClient:
    def __init__(self, logger: Logger, validator: Validator):
        self.logger = logger
        self.validator = validator
    
    def fetch(self, url: str, cache: Dict) -> tuple:
        """Безопасная загрузка"""
        if not self.validator.validate_url(url):
            self.logger.error(f"Заблокирован небезопасный URL: {url[:100]}")
            return "", False
        
        # Подготовка запроса
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Accept": "text/plain,text/html",
                "Connection": "close"
            }
        )
        
        # Проверка кэша
        cache_entry = cache.get(url, {})
        if "etag" in cache_entry:
            req.add_header("If-None-Match", cache_entry["etag"])
        if "last_modified" in cache_entry:
            req.add_header("If-Modified-Since", cache_entry["last_modified"])
        
        text = ""
        used_cache = False
        new_cache_entry = {}
        
        # Повторные попытки
        for attempt in range(Config.MAX_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT) as resp:
                    # Чтение с ограничением
                    content = resp.read(Config.MAX_FILE_SIZE + 1)
                    if len(content) > Config.MAX_FILE_SIZE:
                        self.logger.error(f"Файл слишком большой: {len(content)} байт")
                        return "", False
                    
                    # Сохраняем метаданные
                    new_cache_entry["etag"] = resp.headers.get("ETag")
                    new_cache_entry["last_modified"] = resp.headers.get("Last-Modified")
                    
                    # Декодируем
                    text = content.decode("utf-8", errors="replace")
                    break
                    
            except urllib.error.HTTPError as e:
                if e.code == 304:  # Not Modified
                    used_cache = True
                    text = cache_entry.get("content", "")
                    new_cache_entry = cache_entry
                    break
                elif attempt < Config.MAX_RETRIES - 1:
                    self.logger.warning(f"HTTP {e.code}, повтор {attempt + 1}")
                    continue
                else:
                    self.logger.error(f"HTTP {e.code} после {Config.MAX_RETRIES} попыток")
                    return "", False
                    
            except Exception as e:
                if attempt < Config.MAX_RETRIES - 1:
                    self.logger.warning(f"Ошибка: {e}, повтор {attempt + 1}")
                    continue
                else:
                    self.logger.error(f"Ошибка: {e}")
                    return "", False
        
        if not used_cache and text:
            new_cache_entry["content"] = text
            new_cache_entry["cached_at"] = datetime.now(timezone.utc).isoformat()
            new_cache_entry["size"] = len(text)
        
        cache[url] = new_cache_entry
        return text, used_cache

# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================

class BlocklistBuilder:
    def __init__(self):
        self.logger = Logger()
        self.validator = Validator()
        self.http = SafeHTTPClient(self.logger, self.validator)
        
        self.cache = {}
        self.all_domains = set()
        self.stats = []
        
        self._setup_security()
    
    def _setup_security(self):
        """Базовые меры безопасности"""
        # Отключаем core dump
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except:
            pass
        
        # Лимит памяти
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        except:
            pass
        
        # Лимит CPU времени
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        except:
            pass
        
        # Обработчики сигналов
        def signal_handler(signum, frame):
            self.logger.warning(f"Получен сигнал {signum}, завершение...")
            self._save_cache()  # Сохраняем кэш
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _load_cache(self):
        """Загрузка кэша"""
        try:
            if os.path.exists(".download_cache.json"):
                with open(".download_cache.json", 'r', encoding='utf-8') as f:
                    # Проверка размера
                    if os.path.getsize(".download_cache.json") < 10 * 1024 * 1024:
                        self.cache = json.load(f)
                    else:
                        self.logger.warning("Кэш слишком большой, игнорирую")
        except Exception as e:
            self.logger.warning(f"Не удалось загрузить кэш: {e}")
            self.cache = {}
    
    def _save_cache(self):
        """Безопасное сохранение кэша"""
        try:
            # Временный файл
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp:
                json.dump(self.cache, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = tmp.name
            
            # Перемещаем
            shutil.move(tmp_path, ".download_cache.json")
            os.chmod(".download_cache.json", 0o644)
            
        except Exception as e:
            self.logger.error(f"Не удалось сохранить кэш: {e}")
    
    def extract_domains(self, text: str) -> Set[str]:
        """Безопасное извлечение доменов"""
        domains = set()
        
        # Безопасное регулярное выражение
        try:
            pattern = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+)", re.MULTILINE | re.IGNORECASE)
            
            for match in pattern.finditer(text):
                if len(domains) >= Config.MAX_DOMAINS:
                    self.logger.warning("Достигнут лимит доменов")
                    break
                
                domain = match.group(1).lower().strip()
                if self.validator.validate_domain(domain):
                    domains.add(domain)
                    
        except Exception as e:
            self.logger.error(f"Ошибка парсинга: {e}")
        
        return domains
    
    def process_source(self, url: str, name: str):
        """Обработка источника"""
        self.logger.info(f"Загрузка {name}...")
        start = perf_counter()
        
        text, used_cache = self.http.fetch(url, self.cache)
        elapsed = perf_counter() - start
        
        if not text:
            self.stats.append({
                'name': name,
                'domains': 0,
                'time': elapsed,
                'cached': used_cache
            })
            return
        
        domains = self.extract_domains(text)
        
        self.stats.append({
            'name': name,
            'domains': len(domains),
            'time': elapsed,
            'cached': used_cache
        })
        
        # Обновляем общий набор
        if len(self.all_domains) + len(domains) > Config.MAX_DOMAINS:
            remaining = Config.MAX_DOMAINS - len(self.all_domains)
            self.all_domains.update(list(domains)[:remaining])
            self.logger.warning("Достигнут лимит доменов")
        else:
            self.all_domains.update(domains)
        
        cache_msg = " (кэш)" if used_cache else ""
        self.logger.info(f"  ✅ {len(domains):,} доменов{cache_msg} [{elapsed:.1f}s]")
    
    def generate_output(self) -> bool:
        """Генерация выходного файла с атомарной записью"""
        now = datetime.now(timezone.utc)
        
        # Подготовка контента
        lines = [
            "# ============================================================",
            "# Dynamic DNS Blocklist",
            f"# Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}",
            f"# Total domains: {len(self.all_domains):,}",
            f"# SHA-256: {hashlib.sha256(str(sorted(self.all_domains)).encode()).hexdigest()[:16]}",
            "# ============================================================",
            "",
        ]
        
        sorted_domains = sorted(self.all_domains)
        lines.extend(f"0.0.0.0 {domain}" for domain in sorted_domains)
        content = "\n".join(lines) + "\n"
        
        # Проверка размера
        if len(content) > Config.MAX_FILE_SIZE:
            self.logger.error("Выходной файл слишком большой!")
            return False
        
        # Атомарная запись
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp:
                tmp.write(content)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = tmp.name
            
            shutil.move(tmp_path, "dynamic-blocklist.txt")
            os.chmod("dynamic-blocklist.txt", 0o644)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка записи: {e}")
            return False
    
    def print_stats(self):
        """Вывод статистики"""
        print("\n" + "=" * 70)
        print("📊 СТАТИСТИКА")
        print("=" * 70)
        
        for stat in self.stats:
            cache_mark = "✓" if stat['cached'] else "✗"
            print(f"{stat['name']:<25} {stat['domains']:>8,} доменов  {stat['time']:>5.1f}s  [{cache_mark}]")
        
        print("-" * 70)
        print(f"{'ИТОГО':<25} {len(self.all_domains):>8,} уникальных доменов")
        print("=" * 70)
    
    def run(self):
        """Запуск"""
        print("\n" + "=" * 70)
        print("🛡️  DNS BLOCKLIST BUILDER (Security Enhanced)")
        print("=" * 70)
        
        self._load_cache()
        
        # Источники
        sources = [
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "StevenBlack"),
            ("https://adaway.org/hosts.txt", "AdAway"),
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt", "HaGeZi"),
        ]
        
        for url, name in sources:
            self.process_source(url, name)
        
        self._save_cache()
        
        if self.generate_output():
            file_size = os.path.getsize("dynamic-blocklist.txt")
            self.print_stats()
            print(f"\n✅ Готово!")
            print(f"📁 dynamic-blocklist.txt ({file_size:,} байт)")
            print(f"🔒 {len(self.all_domains):,} защищённых доменов")
        else:
            self.logger.error("Не удалось создать файл")
            sys.exit(1)

# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == "__main__":
    builder = BlocklistBuilder()
    builder.run()
