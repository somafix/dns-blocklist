#!/usr/bin/env python3
"""
Dynamic DNS Blocklist Builder
Собирает новые трекеры, телеметрию и малварь из живых источников
и генерирует hosts-файл для personalDNSfilter.

Источники обновляются каждые 30 минут через GitHub Actions.
"""

import re
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ─── Источники угроз (обновляются несколько раз в сутки) ───────────────────
SOURCES = [
    # Малварь и C2 в реальном времени
    {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "name": "URLhaus (abuse.ch)",
    },
    # Фишинг в реальном времени
    {
        "url": "https://openphish.com/feed.txt",
        "name": "OpenPhish",
        "is_url_list": True,  # содержит URL, надо извлечь домены
    },
    # Malware IOC от abuse.ch
    {
        "url": "https://threatfox.abuse.ch/downloads/hostfile/",
        "name": "ThreatFox (abuse.ch)",
    },
    # CERT Польша (актуально для UA/EU)
    {
        "url": "https://hole.cert.pl/domains/domains_hosts.txt",
        "name": "CERT.PL",
    },
    # Новые трекеры и реклама (HaGeZi обновляет 1-2 раза в сутки)
    {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt",
        "name": "HaGeZi Pro++",
    },
]

# ─── Вайтлист — домены которые никогда не блокируем ────────────────────────
WHITELIST = {
    "localhost",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
}

DOMAIN_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([\w\-\.]+)", re.MULTILINE
)
URL_DOMAIN_RE = re.compile(r"https?://([^/\s:]+)")


def fetch(url: str) -> str:
    """Загружает текст по URL с таймаутом."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "dns-blocklist-builder/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  ⚠️  Ошибка загрузки {url}: {e}")
        return ""


def extract_domains(text: str, is_url_list: bool = False) -> set[str]:
    """Извлекает домены из hosts-файла или списка URL."""
    domains = set()
    if is_url_list:
        for match in URL_DOMAIN_RE.finditer(text):
            domain = match.group(1).lower().strip()
            if domain and "." in domain:
                domains.add(domain)
    else:
        for match in DOMAIN_RE.finditer(text):
            domain = match.group(1).lower().strip()
            if domain and "." in domain:
                domains.add(domain)
    return domains


def is_valid_domain(domain: str) -> bool:
    """Базовая валидация домена."""
    if domain in WHITELIST:
        return False
    if len(domain) > 253:
        return False
    if domain.startswith("-") or domain.endswith("-"):
        return False
    # Должна быть хотя бы одна точка (не просто hostname)
    if "." not in domain:
        return False
    return True


def main():
    print(f"🚀 Запуск сборщика блок-листа: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)

    all_domains: set[str] = set()

    for source in SOURCES:
        print(f"\n📥 Загружаю: {source['name']}")
        text = fetch(source["url"])
        if not text:
            continue
        is_url_list = source.get("is_url_list", False)
        domains = extract_domains(text, is_url_list)
        valid = {d for d in domains if is_valid_domain(d)}
        print(f"   ✅ Найдено доменов: {len(valid)}")
        all_domains.update(valid)

    print(f"\n{'=' * 60}")
    print(f"📊 Итого уникальных доменов: {len(all_domains)}")

    # Генерируем hosts-файл
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# ============================================================",
        "# Dynamic DNS Blocklist — auto-generated",
        f"# Updated: {now}",
        f"# Total domains: {len(all_domains)}",
        "# Sources: URLhaus, OpenPhish, ThreatFox, CERT.PL, HaGeZi Pro++",
        "# ============================================================",
        "",
    ]
    for domain in sorted(all_domains):
        lines.append(f"0.0.0.0 {domain}")

    output = "\n".join(lines) + "\n"

    with open("dynamic-blocklist.txt", "w", encoding="utf-8") as f:
        f.write(output)

    print(f"💾 Файл сохранён: dynamic-blocklist.txt ({len(output)} байт)")


if __name__ == "__main__":
    main()
