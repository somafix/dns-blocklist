#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - Production Ready
Безопасный сборщик блоклистов для personalDNSfilter
"""

import re
import json
import os
import sys
import hashlib
import tempfile
import shutil
import fcntl
import signal
import resource
from datetime import datetime, timezone
from time import perf_counter, sleep
from typing import Set, Dict, Optional
from pathlib import Path
from urllib.parse import urlparse
import urllib.request
import urllib.error

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

class Config:
    """Настройки скрипта"""
    
    # Безопасные лимиты
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_DOMAINS = 300000
    TIMEOUT = 15
    RETRIES = 2
    
    # Только эти домены разрешены
    ALLOWED_SOURCES = {
        'raw.githubusercontent.com',
        'adaway.org',
        'github.com',
    }
    
    # Файлы
    CACHE_FILE = ".download_cache.json"
    OUTPUT_FILE = "dynamic-blocklist.txt"
    LOG_FILE = "blocklist.log"


# ============================================================================
# ЛОГГЕР
# ============================================================================

class Logger:
    """Простое и безопасное логирование"""
    
    def __init__(self):
        self._log_path = Path(Config.LOG_FILE)
        self._rotate_if_needed()
    
    def _rotate_if_needed(self):
        """Ротация лога если слишком большой"""
        if self._log_path.exists() and self._log_path.stat().st_size > 1024 * 1024:
            backup = self._log_path.with_suffix('.log.old')
            self._log_path.rename(backup)
    
    def _write(self, level: str, msg: str):
        """Запись в лог"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {level}: {msg[:500]}\n"
        
        try:
            with open(self._log_path, 'a', encoding='utf-8') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(line)
        except:
            pass  # Логирование не критично
    
    def info(self, msg: str):
        self._write("INFO", msg)
        print(f"ℹ️  {msg}")
    
    def warning(self, msg: str):
        self._write("WARN", msg)
        print(f"⚠️  {msg}")
    
    def error(self, msg: str):
        self._write("ERROR", msg)
        print(f"❌ {msg}")


# ============================================================================
# ВАЛИДАТОР
# ============================================================================

class Validator:
    """Проверка входных данных"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Проверка URL перед загрузкой"""
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
            
            # Белый список
            allowed = False
            for domain in Config.ALLOWED_SOURCES:
                if hostname == domain or hostname.endswith(f'.{domain}'):
                    allowed = True
                    break
            
            if not allowed:
                return False
            
            # Защита от path traversal
            if '..' in parsed.path or '//' in parsed.path:
                return False
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Проверка домена перед добавлением"""
        if not domain or len(domain) > 253:
            return False
        
        domain = domain.lower().strip()
        
        # Только безопасные символы
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        # Запрет на опасные символы
        dangerous = set(';&|$`(){}<>')
        if dangerous.intersection(domain):
            return False
        
        # Запрет на IP-адреса
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
# HTTP КЛИЕНТ
# ============================================================================

class HTTPClient:
    """Безопасная загрузка с кэшированием"""
    
    def __init__(self, logger: Logger, validator: Validator):
        self.logger = logger
        self.validator = validator
    
    def fetch(self, url: str, cache: Dict) -> tuple:
        """Загрузка с поддержкой ETag/Last-Modified"""
        
        if not self.validator.validate_url(url):
            self.logger.error(f"Заблокирован URL: {url[:80]}")
            return "", False
        
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/plain",
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
        new_entry = {}
        
        for attempt in range(Config.RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT) as resp:
                    # Чтение с ограничением
                    content = resp.read(Config.MAX_FILE_SIZE + 1)
                    if len(content) > Config.MAX_FILE_SIZE:
                        self.logger.error(f"Файл слишком большой: {len(content)} байт")
                        return "", False
                    
                    # Сохраняем метаданные
                    new_entry["etag"] = resp.headers.get("ETag")
                    new_entry["last_modified"] = resp.headers.get("Last-Modified")
                    
                    # Декодирование
                    text = content.decode("utf-8", errors="replace")
                    break
                    
            except urllib.error.HTTPError as e:
                if e.code == 304:  # Not Modified
                    used_cache = True
                    text = cache_entry.get("content", "")
                    new_entry = cache_entry
                    break
                elif attempt < Config.RETRIES - 1:
                    self.logger.warning(f"HTTP {e.code}, повтор {attempt + 1}")
                    sleep(1 * (attempt + 1))
                    continue
                else:
                    self.logger.error(f"HTTP {e.code} после {Config.RETRIES} попыток")
                    return "", False
                    
            except Exception as e:
                if attempt < Config.RETRIES - 1:
                    self.logger.warning(f"Ошибка: {e}, повтор {attempt + 1}")
                    sleep(1 * (attempt + 1))
                    continue
                else:
                    self.logger.error(f"Ошибка: {e}")
                    return "", False
        
        if not used_cache and text:
            new_entry["content"] = text
            new_entry["cached_at"] = datetime.now(timezone.utc).isoformat()
        
        cache[url] = new_entry
        return text, used_cache


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================

class BlocklistBuilder:
    """Сборщик блоклистов"""
    
    def __init__(self):
        self.logger = Logger()
        self.validator = Validator()
        self.http = HTTPClient(self.logger, self.validator)
        
        self.cache = {}
        self.domains = set()
        self.stats = []
        
        self._setup_security()
    
    def _setup_security(self):
        """Базовые меры безопасности"""
        # Лимит памяти (256 MB)
        try:
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        except:
            pass
        
        # Лимит CPU (30 секунд)
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        except:
            pass
        
        # Отключаем core dump
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except:
            pass
        
        # Обработка сигналов
        def signal_handler(signum, frame):
            self.logger.warning(f"Получен сигнал {signum}, сохраняю кэш...")
            self._save_cache()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _load_cache(self):
        """Загрузка кэша из файла"""
        cache_path = Path(Config.CACHE_FILE)
        if not cache_path.exists():
            return
        
        # Проверка размера
        if cache_path.stat().st_size > 5 * 1024 * 1024:
            self.logger.warning("Кэш слишком большой, игнорирую")
            return
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                self.cache = json.load(f)
            self.logger.info(f"Загружен кэш: {len(self.cache)} записей")
        except Exception as e:
            self.logger.warning(f"Не удалось загрузить кэш: {e}")
            self.cache = {}
    
    def _save_cache(self):
        """Безопасное сохранение кэша"""
        try:
            # Атомарная запись через временный файл
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                delete=False,
                dir='.'
            ) as tmp:
                json.dump(self.cache, tmp, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = tmp.name
            
            # Замена файла
            shutil.move(tmp_path, Config.CACHE_FILE)
            os.chmod(Config.CACHE_FILE, 0o644)
            
        except Exception as e:
            self.logger.error(f"Не удалось сохранить кэш: {e}")
    
    def extract_domains(self, text: str) -> Set[str]:
        """Извлечение доменов из hosts-файла"""
        domains = set()
        
        # Регулярное выражение для парсинга
        pattern = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+)", re.MULTILINE | re.IGNORECASE)
        
        for match in pattern.finditer(text):
            if len(domains) >= Config.MAX_DOMAINS:
                self.logger.warning(f"Достигнут лимит {Config.MAX_DOMAINS} доменов")
                break
            
            domain = match.group(1).lower().strip()
            if self.validator.validate_domain(domain):
                domains.add(domain)
        
        return domains
    
    def process_source(self, url: str, name: str):
        """Обработка одного источника"""
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
        
        # Извлекаем домены
        new_domains = self.extract_domains(text)
        
        self.stats.append({
            'name': name,
            'domains': len(new_domains),
            'time': elapsed,
            'cached': used_cache
        })
        
        # Добавляем в общий набор
        if len(self.domains) + len(new_domains) > Config.MAX_DOMAINS:
            remaining = Config.MAX_DOMAINS - len(self.domains)
            self.domains.update(list(new_domains)[:remaining])
            self.logger.warning(f"Достигнут лимит {Config.MAX_DOMAINS} доменов")
        else:
            self.domains.update(new_domains)
        
        cache_mark = " (кэш)" if used_cache else ""
        self.logger.info(f"  ✅ {len(new_domains):,} доменов{cache_mark} [{elapsed:.1f}s]")
    
    def generate_output(self) -> bool:
        """Генерация выходного файла"""
        now = datetime.now(timezone.utc)
        
        # Сортировка
        sorted_domains = sorted(self.domains)
        
        # Формирование содержимого
        lines = [
            "# ============================================================",
            "# Dynamic DNS Blocklist for personalDNSfilter",
            f"# Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Total domains: {len(sorted_domains):,}",
            f"# SHA-256: {hashlib.sha256(str(sorted_domains).encode()).hexdigest()[:16]}",
            "# ============================================================",
            ""
        ]
        
        lines.extend(f"0.0.0.0 {domain}" for domain in sorted_domains)
        content = "\n".join(lines) + "\n"
        
        # Проверка размера
        if len(content) > Config.MAX_FILE_SIZE:
            self.logger.error("Выходной файл слишком большой")
            return False
        
        # Атомарная запись
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                delete=False,
                dir='.'
            ) as tmp:
                tmp.write(content)
                tmp.flush()
                os.fsync(tmp.fileno())
                tmp_path = tmp.name
            
            shutil.move(tmp_path, Config.OUTPUT_FILE)
            os.chmod(Config.OUTPUT_FILE, 0o644)
            
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
        print(f"{'ИТОГО':<25} {len(self.domains):>8,} уникальных доменов")
        print("=" * 70)
    
    def run(self):
        """Запуск скрипта"""
        print("\n" + "=" * 70)
        print("🛡️  DNS BLOCKLIST BUILDER (Production Ready)")
        print("=" * 70)
        
        # Загрузка кэша
        self._load_cache()
        
        # Источники
        sources = [
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "StevenBlack"),
            ("https://adaway.org/hosts.txt", "AdAway"),
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt", "HaGeZi"),
        ]
        
        # Обработка
        for url, name in sources:
            self.process_source(url, name)
        
        # Сохранение кэша
        self._save_cache()
        
        # Генерация файла
        if self.generate_output():
            size = os.path.getsize(Config.OUTPUT_FILE)
            self.print_stats()
            print(f"\n✅ Готово!")
            print(f"📁 {Config.OUTPUT_FILE} ({size:,} байт)")
            print(f"🔒 {len(self.domains):,} защищённых доменов")
        else:
            self.logger.error("Не удалось создать файл")
            sys.exit(1)


# ============================================================================
# ЗАПУСК
# ============================================================================

def main():
    """Точка входа"""
    # Проверка Python
    if sys.version_info < (3, 6):
        print("❌ Требуется Python 3.6 или выше")
        sys.exit(1)
    
    # Запуск
    builder = BlocklistBuilder()
    builder.run()


if __name__ == "__main__":
    main()
