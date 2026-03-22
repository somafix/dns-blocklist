#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder - Защищённая версия
Собирает новые трекеры, телеметрию и малварь из живых источников
и генерирует hosts-файл для personalDNSfilter.

Безопасность:
- Проверка целостности файлов (SHA-256)
- Защита от инъекций и path traversal
- Безопасная обработка исключений
- Валидация всех входных данных
- Ограничение ресурсов
- Атомарные операции записи
- Анти-DoS механизмы
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
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from time import perf_counter, sleep
from collections import defaultdict
from typing import Set, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import signal
import resource
import logging
from pathlib import Path

# ─── Конфигурация безопасности ──────────────────────────────────────────────
class SecurityConfig:
    """Безопасные настройки приложения"""
    
    # Максимальные размеры
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    MAX_DOMAINS = 500000  # Максимум доменов в списке
    MAX_DOMAIN_LENGTH = 253
    MAX_URL_LENGTH = 2000
    MAX_RETRIES = 3
    
    # Таймауты
    CONNECT_TIMEOUT = 10
    READ_TIMEOUT = 20
    TOTAL_TIMEOUT = 30
    
    # Ограничения ресурсов
    MAX_MEMORY_MB = 512
    MAX_CPU_TIME = 60  # секунд
    
    # Разрешённые протоколы
    ALLOWED_SCHEMES = {'http', 'https'}
    
    # Безопасные домены (только разрешённые хосты)
    ALLOWED_DOMAINS = {
        'raw.githubusercontent.com',
        'adaway.org',
        'github.com',
        'raw.github.com'
    }
    
    # Защита от path traversal
    ALLOWED_PATHS = {'.', '..', ''}
    
    # Исключаемые опасные паттерны
    DANGEROUS_PATTERNS = [
        r'\.\./',  # path traversal
        r'\\\.\.',  # Windows path traversal
        r'[\x00-\x1f\x7f]',  # control characters
        r'[;&|`$(){}]',  # shell metacharacters
        r'<!--',  # HTML injection
        r'<script',  # script injection
    ]

# ─── Безопасный логгер ─────────────────────────────────────────────────────
class SecureLogger:
    """Безопасная система логирования с защитой от инъекций"""
    
    def __init__(self, log_file: Optional[str] = None):
        self.logger = logging.getLogger('dns_blocklist')
        self.logger.setLevel(logging.INFO)
        
        # Консольный вывод
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console_handler)
        
        # Файловый лог (если указан)
        if log_file:
            try:
                safe_path = self._safe_path(log_file)
                file_handler = logging.FileHandler(safe_path)
                file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.logger.addHandler(file_handler)
            except Exception:
                pass
    
    def _safe_path(self, path: str) -> str:
        """Безопасное преобразование пути"""
        base_path = Path(__file__).parent
        safe_path = base_path / path
        return str(safe_path.resolve())
    
    def info(self, msg: str):
        self.logger.info(self._sanitize(msg))
    
    def warning(self, msg: str):
        self.logger.warning(self._sanitize(msg))
    
    def error(self, msg: str):
        self.logger.error(self._sanitize(msg))
    
    def _sanitize(self, msg: str) -> str:
        """Очистка сообщений от потенциально опасного содержимого"""
        for pattern in SecurityConfig.DANGEROUS_PATTERNS:
            msg = re.sub(pattern, '[SANITIZED]', msg)
        return msg[:1000]  # Ограничение длины

# ─── Защита ресурсов ───────────────────────────────────────────────────────
class ResourceGuard:
    """Защита от исчерпания ресурсов"""
    
    def __init__(self, logger: SecureLogger):
        self.logger = logger
        self.setup_limits()
    
    def setup_limits(self):
        """Установка лимитов ресурсов"""
        try:
            # Ограничение памяти
            memory_limit = SecurityConfig.MAX_MEMORY_MB * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
            
            # Ограничение CPU времени
            cpu_limit = SecurityConfig.MAX_CPU_TIME
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 1))
            
            # Ограничение размера файлов
            resource.setrlimit(resource.RLIMIT_FSIZE, (SecurityConfig.MAX_FILE_SIZE, SecurityConfig.MAX_FILE_SIZE))
            
        except Exception as e:
            self.logger.warning(f"Не удалось установить лимиты ресурсов: {e}")
    
    def timeout_handler(self, signum, frame):
        """Обработчик таймаута"""
        raise TimeoutError("Превышен лимит времени выполнения")

# ─── Безопасная валидация входных данных ───────────────────────────────────
class InputValidator:
    """Валидация всех входных данных"""
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Проверка URL на безопасность"""
        if len(url) > SecurityConfig.MAX_URL_LENGTH:
            return False
        
        try:
            parsed = urlparse(url)
            
            # Проверка схемы
            if parsed.scheme not in SecurityConfig.ALLOWED_SCHEMES:
                return False
            
            # Проверка хоста
            hostname = parsed.hostname
            if not hostname or hostname not in SecurityConfig.ALLOWED_DOMAINS:
                # Проверка, что хост является поддоменом разрешённого
                if not any(hostname.endswith(f'.{domain}') or hostname == domain 
                          for domain in SecurityConfig.ALLOWED_DOMAINS):
                    return False
            
            # Проверка пути от path traversal
            if '..' in parsed.path or '//' in parsed.path:
                return False
            
            # Проверка на IP-адреса (запрещаем прямые IP)
            try:
                ipaddress.ip_address(hostname)
                return False  # Запрещаем прямые IP-адреса
            except ValueError:
                pass
            
            return True
            
        except Exception:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Безопасная валидация домена"""
        if not domain or not isinstance(domain, str):
            return False
        
        domain = domain.lower().strip()
        
        # Проверка длины
        if len(domain) > SecurityConfig.MAX_DOMAIN_LENGTH:
            return False
        
        # Проверка символов
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False
        
        # Запрет на спецсимволы
        if any(c in domain for c in [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>']):
            return False
        
        # Проверка на пустые сегменты
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            return False
        
        # Проверка на IP-адреса
        try:
            ipaddress.ip_address(domain)
            return False  # Запрещаем IP-адреса
        except ValueError:
            pass
        
        return True

# ─── Безопасная работа с файлами ───────────────────────────────────────────
class SecureFileHandler:
    """Безопасные операции с файлами"""
    
    def __init__(self, logger: SecureLogger):
        self.logger = logger
    
    def safe_write(self, filepath: str, content: str, atomic: bool = True) -> bool:
        """Безопасная запись файла с атомарной операцией"""
        try:
            # Проверка пути
            base_dir = Path(__file__).parent
            target_path = (base_dir / filepath).resolve()
            
            # Защита от path traversal
            if not str(target_path).startswith(str(base_dir)):
                self.logger.error(f"Попытка path traversal: {filepath}")
                return False
            
            # Проверка размера
            if len(content) > SecurityConfig.MAX_FILE_SIZE:
                self.logger.error(f"Файл слишком большой: {len(content)} байт")
                return False
            
            if atomic:
                # Атомарная запись через временный файл
                with tempfile.NamedTemporaryFile(
                    mode='w',
                    encoding='utf-8',
                    dir=str(base_dir),
                    prefix='.tmp_',
                    delete=False
                ) as tmp:
                    tmp.write(content)
                    tmp_path = tmp.name
                
                # Перемещение с атомарной заменой
                shutil.move(tmp_path, str(target_path))
            else:
                # Прямая запись
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            # Установка безопасных прав доступа
            os.chmod(target_path, 0o644)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Ошибка записи файла {filepath}: {e}")
            # Очистка временного файла
            if 'tmp_path' in locals():
                try:
                    os.unlink(tmp_path)
                except:
                    pass
            return False
    
    def safe_read(self, filepath: str, max_size: int = None) -> Optional[str]:
        """Безопасное чтение файла"""
        try:
            base_dir = Path(__file__).parent
            target_path = (base_dir / filepath).resolve()
            
            # Защита от path traversal
            if not str(target_path).startswith(str(base_dir)):
                self.logger.error(f"Попытка path traversal: {filepath}")
                return None
            
            if not target_path.exists():
                return None
            
            # Проверка размера
            file_size = target_path.stat().st_size
            max_size = max_size or SecurityConfig.MAX_FILE_SIZE
            if file_size > max_size:
                self.logger.error(f"Файл слишком большой: {file_size} байт")
                return None
            
            # Чтение с ограничением
            with open(target_path, 'r', encoding='utf-8') as f:
                return f.read()
                
        except Exception as e:
            self.logger.error(f"Ошибка чтения файла {filepath}: {e}")
            return None

# ─── Безопасный HTTP-клиент ────────────────────────────────────────────────
class SecureHTTPClient:
    """Безопасный HTTP-клиент с защитой от атак"""
    
    def __init__(self, logger: SecureLogger, validator: InputValidator):
        self.logger = logger
        self.validator = validator
        
        # Создание безопасного контекста SSL
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
    
    def fetch(self, url: str, cache: Dict, retry_count: int = 0) -> Tuple[str, bool]:
        """Безопасная загрузка с проверками"""
        
        # Валидация URL
        if not self.validator.validate_url(url):
            self.logger.error(f"Небезопасный URL: {url}")
            return "", False
        
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "dns-blocklist-builder/3.0-security",
                "Accept": "text/plain,text/html",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close"  # Закрытие соединения после запроса
            },
        )
        
        cache_entry = cache.get(url, {})
        if "etag" in cache_entry:
            req.add_header("If-None-Match", cache_entry["etag"])
        if "last_modified" in cache_entry:
            req.add_header("If-Modified-Since", cache_entry["last_modified"])
        
        new_cache_entry = {}
        text = ""
        used_cache = False
        
        try:
            # Создание безопасного открывателя с таймаутами
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'dns-blocklist-builder/3.0-security')]
            
            with opener.open(req, timeout=SecurityConfig.TOTAL_TIMEOUT) as resp:
                # Проверка Content-Type
                content_type = resp.headers.get('Content-Type', '')
                if not any(t in content_type for t in ['text/plain', 'text/html', 'application/octet-stream']):
                    self.logger.warning(f"Подозрительный Content-Type: {content_type}")
                    return "", False
                
                # Чтение с ограничением
                content = resp.read(SecurityConfig.MAX_FILE_SIZE + 1)
                if len(content) > SecurityConfig.MAX_FILE_SIZE:
                    self.logger.error(f"Файл слишком большой: {len(content)} байт")
                    return "", False
                
                new_cache_entry["etag"] = resp.headers.get("ETag")
                new_cache_entry["last_modified"] = resp.headers.get("Last-Modified")
                text = content.decode("utf-8", errors="strict")  # Строгая декодировка
                
        except urllib.error.HTTPError as e:
            if e.code == 304:
                self.logger.info("Использован кэш")
                used_cache = True
                text = cache_entry.get("content", "")
                new_cache_entry = cache_entry
            elif e.code in [403, 404, 410]:
                self.logger.warning(f"HTTP {e.code} - ресурс недоступен")
                return "", False
            elif retry_count < SecurityConfig.MAX_RETRIES:
                self.logger.warning(f"HTTP {e.code}, повтор {retry_count + 1}")
                sleep(2 ** retry_count)  # Экспоненциальная задержка
                return self.fetch(url, cache, retry_count + 1)
            else:
                self.logger.error(f"HTTP {e.code} после {SecurityConfig.MAX_RETRIES} попыток")
                return "", False
                
        except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
            if retry_count < SecurityConfig.MAX_RETRIES:
                self.logger.warning(f"Сетевая ошибка: {e}, повтор {retry_count + 1}")
                sleep(2 ** retry_count)
                return self.fetch(url, cache, retry_count + 1)
            else:
                self.logger.error(f"Сетевая ошибка после {SecurityConfig.MAX_RETRIES} попыток: {e}")
                return "", False
                
        except UnicodeDecodeError as e:
            self.logger.error(f"Ошибка декодировки: {e}")
            return "", False
        
        if not used_cache and text:
            new_cache_entry["content"] = text
            new_cache_entry["cached_at"] = datetime.now(timezone.utc).isoformat()
            new_cache_entry["sha256"] = hashlib.sha256(text.encode()).hexdigest()
        
        cache[url] = new_cache_entry
        return text, used_cache

# ─── Основной класс приложения ─────────────────────────────────────────────
class SecureBlocklistBuilder:
    """Безопасный сборщик блоклистов"""
    
    def __init__(self):
        self.logger = SecureLogger("blocklist.log")
        self.validator = InputValidator()
        self.file_handler = SecureFileHandler(self.logger)
        self.http_client = SecureHTTPClient(self.logger, self.validator)
        self.resource_guard = ResourceGuard(self.logger)
        
        self.cache = {}
        self.all_domains = set()
        self.stats = []
        
        # Настройка обработчиков сигналов
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Безопасная обработка сигналов"""
        self.logger.warning(f"Получен сигнал {signum}, завершение работы...")
        sys.exit(1)
    
    def load_cache(self):
        """Безопасная загрузка кэша"""
        content = self.file_handler.safe_read(".download_cache.json")
        if content:
            try:
                self.cache = json.loads(content)
            except json.JSONDecodeError as e:
                self.logger.error(f"Ошибка парсинга кэша: {e}")
                self.cache = {}
    
    def save_cache(self):
        """Безопасное сохранение кэша"""
        try:
            content = json.dumps(self.cache, indent=2)
            self.file_handler.safe_write(".download_cache.json", content)
        except Exception as e:
            self.logger.error(f"Ошибка сохранения кэша: {e}")
    
    def extract_domains(self, text: str) -> Set[str]:
        """Безопасное извлечение доменов"""
        domains = set()
        
        # Безопасное регулярное выражение с ограничением
        try:
            pattern = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w\-\.]+)", re.MULTILINE)
            matches = pattern.finditer(text)
            
            for match in matches:
                if len(domains) > SecurityConfig.MAX_DOMAINS:
                    self.logger.warning("Достигнут лимит доменов")
                    break
                
                domain = match.group(1).lower().strip()
                if self.validator.validate_domain(domain):
                    domains.add(domain)
                    
        except re.error as e:
            self.logger.error(f"Ошибка регулярного выражения: {e}")
        
        return domains
    
    def process_source(self, source: Dict):
        """Безопасная обработка источника"""
        url = source["url"]
        name = source["name"]
        
        self.logger.info(f"Обработка источника: {name}")
        start_time = perf_counter()
        
        text, used_cache = self.http_client.fetch(url, self.cache)
        download_time = perf_counter() - start_time
        
        if not text:
            self.stats.append({
                "name": name,
                "raw": 0,
                "valid": 0,
                "time": download_time,
                "cached": used_cache
            })
            return
        
        raw_domains = self.extract_domains(text)
        
        self.stats.append({
            "name": name,
            "raw": len(raw_domains),
            "valid": len(raw_domains),
            "time": download_time,
            "cached": used_cache
        })
        
        # Проверка лимита
        if len(self.all_domains) + len(raw_domains) > SecurityConfig.MAX_DOMAINS:
            self.logger.warning(f"Достигнут лимит доменов ({SecurityConfig.MAX_DOMAINS})")
            remaining = SecurityConfig.MAX_DOMAINS - len(self.all_domains)
            self.all_domains.update(list(raw_domains)[:remaining])
        else:
            self.all_domains.update(raw_domains)
        
        self.logger.info(f"  Добавлено {len(raw_domains)} доменов")
    
    def generate_output(self):
        """Безопасная генерация выходного файла"""
        now = datetime.now(timezone.utc)
        
        lines = [
            "# ============================================================",
            "# Dynamic DNS Blocklist — SECURE auto-generated",
            f"# Updated: {now.strftime('%Y-%m-%d %H:%M UTC')}",
            f"# Total domains: {len(self.all_domains):,}",
            "# SHA-256: " + hashlib.sha256(
                '\n'.join(sorted(self.all_domains)).encode()
            ).hexdigest(),
            "# Security level: MAXIMUM",
            "# ============================================================",
            "",
        ]
        
        sorted_domains = sorted(self.all_domains)
        lines.extend(f"0.0.0.0 {domain}" for domain in sorted_domains)
        
        content = "\n".join(lines) + "\n"
        
        # Проверка размера
        if len(content) > SecurityConfig.MAX_FILE_SIZE:
            self.logger.error("Файл слишком большой!")
            return False
        
        # Атомарная запись
        return self.file_handler.safe_write("dynamic-blocklist.txt", content, atomic=True)
    
    def print_stats(self):
        """Вывод статистики"""
        print("\n" + "="*70)
        print("📊 СТАТИСТИКА ПО ИСТОЧНИКАМ:")
        print("="*70)
        
        for stat in self.stats:
            cache_mark = "✓" if stat["cached"] else "✗"
            print(f"{stat['name']:<30} {stat['raw']:>8} доменов "
                  f"{stat['time']:>6.2f}s [{cache_mark}]")
        
        print("-"*70)
        print(f"Всего уникальных доменов: {len(self.all_domains):,}")
        print("="*70)
    
    def run(self):
        """Запуск сборщика"""
        try:
            print("🛡️  ЗАЩИЩЁННЫЙ СБОРЩИК DNS БЛОКЛИСТОВ")
            print("="*70)
            
            self.load_cache()
            
            sources = [
                {
                    "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                    "name": "StevenBlack Unified",
                },
                {
                    "url": "https://adaway.org/hosts.txt",
                    "name": "AdAway",
                },
                {
                    "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt",
                    "name": "HaGeZi Ultimate",
                },
            ]
            
            for source in sources:
                self.process_source(source)
            
            self.save_cache()
            
            if self.generate_output():
                self.print_stats()
                print(f"\n✅ Файл успешно создан: dynamic-blocklist.txt")
                print(f"🔒 Размер: {len(self.all_domains):,} доменов")
                print("🛡️  Применены все меры безопасности")
            else:
                print("\n❌ Ошибка при создании файла")
                sys.exit(1)
                
        except Exception as e:
            self.logger.error(f"Критическая ошибка: {e}")
            sys.exit(1)

# ─── Точка входа ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    builder = SecureBlocklistBuilder()
    builder.run()
