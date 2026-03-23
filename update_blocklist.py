#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - ULTRA OPTIMIZED
Максимальная производительность + минимальное потребление ресурсов
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
from time import perf_counter
from typing import Set, Dict, Optional, List, Tuple
from pathlib import Path
from urllib.parse import urlparse
import urllib.request
import urllib.error

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

# ============================================================================
# ОПТИМИЗИРОВАННАЯ КОНФИГУРАЦИЯ
# ============================================================================

class Config:
    """Оптимизированные настройки"""
    
    # Лимиты
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_DOMAINS = 300000
    TIMEOUT = 10
    RETRIES = 1
    
    # Оптимизация памяти
    DOMAIN_CACHE_SIZE = 100000
    BATCH_SIZE = 10000
    
    # Белый список
    ALLOWED_SOURCES = frozenset({
        'raw.githubusercontent.com',
        'adaway.org',
        'github.com',
    })
    
    # Оптимизированные паттерны
    DOMAIN_PATTERN = re.compile(
        rb'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9.-]+)',
        re.MULTILINE | re.IGNORECASE
    )
    
    # Безопасные символы
    SAFE_CHARS = frozenset(b'abcdefghijklmnopqrstuvwxyz0123456789.-')
    
    # Лог файл
    LOG_FILE = 'update_blocklist.log'


# ============================================================================
# ОПТИМИЗИРОВАННЫЙ ЛОГГЕР
# ============================================================================

class AsyncLogger:
    """Асинхронный логгер с буферизацией"""
    
    __slots__ = ('_log_path', '_buffer', '_buffer_size', '_lock')
    
    def __init__(self):
        self._log_path = Path(Config.LOG_FILE)
        self._buffer = []
        self._buffer_size = 0
        self._lock = threading.Lock()
    
    def _lock_file(self, f):
        """Кроссплатформенная блокировка файла"""
        if HAS_FCNTL:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        elif msvcrt:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    
    def _unlock_file(self, f):
        """Кроссплатформенная разблокировка файла"""
        if HAS_FCNTL:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        elif msvcrt:
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    
    def log(self, level: str, msg: str):
        """Быстрое логирование с буфером"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {level}: {msg[:500]}\n"
        
        # Вывод в консоль
        print(f"{'ℹ️' if level == 'INFO' else '⚠️' if level == 'WARN' else '❌'} {msg}")
        
        # Буферизированная запись в файл
        if self._log_path:
            with self._lock:
                self._buffer.append(line)
                self._buffer_size += len(line)
                
                if self._buffer_size > 65536:
                    self.flush()
    
    def flush(self):
        """Сброс буфера на диск"""
        if not self._buffer or not self._log_path:
            return
        
        with self._lock:
            if not self._buffer:
                return
                
            try:
                with open(self._log_path, 'a', encoding='utf-8') as f:
                    self._lock_file(f)
                    f.write(''.join(self._buffer))
                    f.flush()
                    os.fsync(f.fileno())
                    self._unlock_file(f)
            except:
                pass
            finally:
                self._buffer.clear()
                self._buffer_size = 0


# ============================================================================
# ОПТИМИЗИРОВАННЫЙ ВАЛИДАТОР
# ============================================================================

class FastValidator:
    """Максимально быстрая валидация"""
    
    __slots__ = ()
    
    @staticmethod
    @functools.lru_cache(maxsize=1024)
    def validate_url(url: str) -> bool:
        """Кэшированная проверка URL"""
        if len(url) > 2000:
            return False
        
        try:
            parsed = urlparse(url)
            
            # Быстрая проверка
            if parsed.scheme != 'https':
                return False
            
            host = parsed.hostname
            if not host:
                return False
            
            # Проверка в frozenset (O(1))
            if host not in Config.ALLOWED_SOURCES:
                # Проверка поддомена
                allowed = False
                for domain in Config.ALLOWED_SOURCES:
                    if host.endswith('.' + domain):
                        allowed = True
                        break
                if not allowed:
                    return False
            
            # Быстрая проверка path traversal
            if '..' in parsed.path or '//' in parsed.path:
                return False
            
            return True
            
        except:
            return False
    
    @staticmethod
    def validate_domain(domain: bytes) -> bool:
        """Максимально быстрая валидация домена (работает с байтами)"""
        length = len(domain)
        
        # Быстрые проверки
        if length < 3 or length > 253:
            return False
        
        # Проверка первого и последнего символа
        if domain[0] == 45 or domain[-1] == 45:  # '-'
            return False
        
        # Проверка наличия точки
        if 46 not in domain:  # '.'
            return False
        
        # Проверка всех символов
        for b in domain:
            if b not in Config.SAFE_CHARS:
                return False
        
        return True


# ============================================================================
# ОПТИМИЗИРОВАННЫЙ HTTP КЛИЕНТ
# ============================================================================

class FastHTTPClient:
    """Быстрый HTTP клиент с пулом соединений"""
    
    __slots__ = ('_logger', '_opener', '_cache')
    
    def __init__(self, logger: AsyncLogger):
        self._logger = logger
        self._opener = self._create_opener()
        self._cache = {}  # Инициализация кэша
    
    def _create_opener(self):
        """Создание оптимизированного opener"""
        import ssl
        
        # Создаём SSL контекст с оптимизациями
        ssl_context = ssl.create_default_context()
        # Для публичных источников лучше включить проверку
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Настройка сокета
        handler = urllib.request.HTTPSHandler(context=ssl_context)
        opener = urllib.request.build_opener(handler)
        
        # Установка заголовков
        opener.addheaders = [
            ('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'),
            ('Accept', 'text/plain'),
            ('Accept-Encoding', 'gzip, deflate'),
            ('Connection', 'keep-alive'),
        ]
        
        return opener
    
    def fetch(self, url: str, cache: Dict) -> Tuple[str, bool]:
        """Оптимизированная загрузка"""
        if not FastValidator.validate_url(url):
            self._logger.log('ERROR', f'Заблокирован URL: {url[:80]}')
            return "", False
        
        # Проверка кэша
        cache_entry = cache.get(url)
        if cache_entry:
            req = urllib.request.Request(url)
            if 'etag' in cache_entry:
                req.add_header('If-None-Match', cache_entry['etag'])
            if 'last_modified' in cache_entry:
                req.add_header('If-Modified-Since', cache_entry['last_modified'])
        else:
            req = urllib.request.Request(url)
        
        text = ""
        used_cache = False
        new_entry = {}
        
        try:
            with self._opener.open(req, timeout=Config.TIMEOUT) as resp:
                # Чтение с буферизацией
                content = resp.read(Config.MAX_FILE_SIZE + 1)
                if len(content) > Config.MAX_FILE_SIZE:
                    self._logger.log('ERROR', f'Файл слишком большой: {len(content)} байт')
                    return "", False
                
                # Сохраняем метаданные
                new_entry['etag'] = resp.headers.get('ETag')
                new_entry['last_modified'] = resp.headers.get('Last-Modified')
                
                # Декодируем
                text = content.decode('utf-8', errors='replace')
                
        except urllib.error.HTTPError as e:
            if e.code == 304 and cache_entry:
                used_cache = True
                text = cache_entry.get('content', '')
                new_entry = cache_entry
            else:
                self._logger.log('ERROR', f'HTTP {e.code} для {url[:80]}')
                return "", False
        except Exception as e:
            self._logger.log('ERROR', f'{str(e)[:100]} для {url[:80]}')
            return "", False
        
        if not used_cache and text:
            new_entry['content'] = text
            cache[url] = new_entry
        
        return text, used_cache


# ============================================================================
# ОПТИМИЗИРОВАННЫЙ ПАРСЕР
# ============================================================================

class FastParser:
    """Максимально быстрый парсер hosts-файла"""
    
    __slots__ = ('_pattern', '_validator')
    
    def __init__(self):
        self._pattern = Config.DOMAIN_PATTERN
        self._validator = FastValidator()
    
    def extract_domains(self, text: str) -> Set[str]:
        """Быстрое извлечение доменов"""
        domains = set()
        text_bytes = text.encode('utf-8', errors='ignore')
        
        # Итератор по совпадениям
        for match in self._pattern.finditer(text_bytes):
            if len(domains) >= Config.MAX_DOMAINS:
                break
            
            domain_bytes = match.group(1)
            
            # Быстрая валидация без декодирования
            if self._validator.validate_domain(domain_bytes):
                # Декодируем только валидные домены
                domain = domain_bytes.decode('ascii')
                domains.add(domain)
        
        return domains


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================

class OptimizedBlocklistBuilder:
    """Оптимизированный сборщик блоклистов"""
    
    __slots__ = ('_logger', '_http', '_parser', '_cache', '_domains', '_stats', '_start_time')
    
    def __init__(self):
        self._logger = AsyncLogger()
        self._http = FastHTTPClient(self._logger)
        self._parser = FastParser()
        self._cache = {}
        self._domains = set()
        self._stats = []
        self._start_time = 0
        
        self._setup_security()
        self._setup_gc()
    
    def _setup_security(self):
        """Минимальные настройки безопасности"""
        try:
            # Лимит памяти (512 MB)
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            # Лимит CPU
            resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
        except:
            pass
        
        # Обработка сигналов
        signal.signal(signal.SIGINT, lambda s, f: self._cleanup())
        signal.signal(signal.SIGTERM, lambda s, f: self._cleanup())
    
    def _setup_gc(self):
        """Настройка сборщика мусора для производительности"""
        gc.disable()
        gc.set_threshold(700, 10, 5)
    
    def _cleanup(self):
        """Быстрая очистка"""
        self._save_cache()
        self._logger.flush()
        sys.exit(0)
    
    def _load_cache(self):
        """Быстрая загрузка кэша"""
        cache_path = Path('.download_cache.json')
        if not cache_path.exists():
            return
        
        try:
            with open(cache_path, 'rb') as f:
                self._cache = json.loads(f.read())
            self._logger.log('INFO', f'Загружен кэш: {len(self._cache)} записей')
        except:
            self._cache = {}
    
    def _save_cache(self):
        """Быстрое сохранение кэша"""
        if not self._cache:
            return
        
        try:
            # Используем временный файл для атомарности
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp:
                json.dump(self._cache, tmp, separators=(',', ':'))
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, '.download_cache.json')
        except:
            pass
    
    def process_source(self, url: str, name: str):
        """Обработка одного источника"""
        self._logger.log('INFO', f'Загрузка {name}...')
        start = perf_counter()
        
        text, used_cache = self._http.fetch(url, self._cache)
        elapsed = perf_counter() - start
        
        if not text:
            self._stats.append((name, 0, elapsed, used_cache))
            return
        
        # Парсинг
        new_domains = self._parser.extract_domains(text)
        
        self._stats.append((name, len(new_domains), elapsed, used_cache))
        
        # Добавление в общий набор
        if len(self._domains) + len(new_domains) > Config.MAX_DOMAINS:
            remaining = Config.MAX_DOMAINS - len(self._domains)
            self._domains.update(list(new_domains)[:remaining])
            self._logger.log('WARN', f'Достигнут лимит {Config.MAX_DOMAINS} доменов')
        else:
            self._domains.update(new_domains)
        
        cache_msg = ' (кэш)' if used_cache else ''
        self._logger.log('INFO', f'  ✅ {len(new_domains):,} доменов{cache_msg} [{elapsed:.2f}s]')
        
        # Принудительная сборка мусора после каждого источника
        gc.collect()
    
    def generate_output(self) -> bool:
        """Генерация выходного файла"""
        now = datetime.now(timezone.utc)
        
        # Оптимизированная сортировка
        sorted_domains = sorted(self._domains)
        
        # Используем список для быстрой конкатенации
        lines = [
            "# ============================================================",
            "# Dynamic DNS Blocklist - OPTIMIZED",
            f"# Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Total domains: {len(sorted_domains):,}",
            f"# SHA-256: {hashlib.sha256(str(sorted_domains).encode()).hexdigest()[:16]}",
            "# ============================================================",
            ""
        ]
        
        # Добавляем домены
        lines.extend(f"0.0.0.0 {domain}" for domain in sorted_domains)
        content = '\n'.join(lines) + '\n'
        
        # Атомарная запись
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='.') as tmp:
                tmp.write(content)
                tmp.flush()
                os.fsync(tmp.fileno())
            
            shutil.move(tmp.name, 'dynamic-blocklist.txt')
            os.chmod('dynamic-blocklist.txt', 0o644)
            return True
        except:
            return False
    
    def print_stats(self):
        """Вывод статистики"""
        print("\n" + "=" * 70)
        print("📊 СТАТИСТИКА")
        print("=" * 70)
        
        for name, count, elapsed, cached in self._stats:
            cache_mark = "✓" if cached else "✗"
            print(f"{name:<25} {count:>8,} доменов  {elapsed:>5.2f}s  [{cache_mark}]")
        
        print("-" * 70)
        print(f"{'ИТОГО':<25} {len(self._domains):>8,} уникальных доменов")
        print("=" * 70)
        
        # Время выполнения
        elapsed = perf_counter() - self._start_time
        print(f"\n⏱️  Общее время: {elapsed:.2f} сек")
        if elapsed > 0:
            print(f"📈 Скорость: {len(self._domains) / elapsed:.0f} доменов/сек")
    
    def run(self):
        """Запуск"""
        self._start_time = perf_counter()
        
        print("\n" + "=" * 70)
        print("🚀 DNS BLOCKLIST BUILDER - ULTRA OPTIMIZED")
        print("=" * 70)
        
        # Загрузка кэша
        self._load_cache()
        
        # Источники
        sources = [
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "StevenBlack"),
            ("https://adaway.org/hosts.txt", "AdAway"),
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt", "HaGeZi"),
        ]
        
        # Последовательная обработка
        for url, name in sources:
            self.process_source(url, name)
        
        # Сохранение кэша
        self._save_cache()
        
        # Генерация файла
        if self.generate_output():
            self.print_stats()
            print(f"\n✅ Готово!")
            print(f"📁 dynamic-blocklist.txt ({len(self._domains):,} доменов)")
        else:
            self._logger.log('ERROR', 'Не удалось создать файл')
            sys.exit(1)
        
        # Сброс логов
        self._logger.flush()


# ============================================================================
# ЗАПУСК
# ============================================================================

def main():
    """Точка входа"""
    if sys.version_info < (3, 6):
        print("❌ Требуется Python 3.6+")
        sys.exit(1)
    
    builder = OptimizedBlocklistBuilder()
    builder.run()


if __name__ == "__main__":
    main()
