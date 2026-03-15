Dynamic DNS Blocklist Builder

"Python" (https://img.shields.io/badge/python-3.8%2B-blue)
"License" (https://img.shields.io/badge/license-MIT-green)
"Security" (https://img.shields.io/badge/focus-threat%20intelligence-red)
"Blocklist" (https://img.shields.io/badge/type-dns%20blocklist-black)
"Automation" (https://img.shields.io/badge/automation-github%20actions-blue)

Dynamic DNS Blocklist Builder — это инструмент агрегации threat-intelligence, который автоматически собирает домены вредоносных сайтов, фишинга, трекеров и рекламы из нескольких публичных источников и генерирует единый "hosts"-блоклист.

Проект предназначен для использования с:

- DNS фильтрами
- сетевыми фильтрами
- Pi-hole
- personalDNSfilter
- AdGuard
- системными "hosts" файлами

---

Основные возможности

Threat Intelligence Aggregation

Сбор доменов из нескольких источников угроз.

Smart HTTP Caching

Поддержка:

- "ETag"
- "Last-Modified"

Позволяет не скачивать списки повторно, если они не изменились.

Duplicate Analysis

Автоматический анализ пересечений между источниками.

Performance Metrics

Показывает:

- время загрузки каждого источника
- статистику доменов
- итоговую производительность.

Automatic Git Hygiene

Скрипт автоматически создаёт ".gitignore" для кэша.

---

Архитектура

                ┌────────────────────┐
                │ Threat Sources     │
                │                    │
                │ URLhaus            │
                │ OpenPhish          │
                │ ThreatFox          │
                │ CERT.PL            │
                │ HaGeZi DNS lists   │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ HTTP Fetch Layer   │
                │                    │
                │ ETag caching       │
                │ Last-Modified      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Domain Extraction  │
                │                    │
                │ URL parsing        │
                │ hosts parsing      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Validation Engine  │
                │                    │
                │ domain checks      │
                │ whitelist filter   │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Deduplication      │
                │ & Analytics        │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Blocklist Output   │
                │ dynamic-blocklist  │
                └────────────────────┘

---

Источники Threat Intelligence

Проект агрегирует данные из публичных threat-intel проектов:

Source| Тип
URLhaus| Malware / C2
OpenPhish| Phishing
ThreatFox| Malware infrastructure
CERT.PL| Malware domains
HaGeZi| Ads / Tracking

Эти источники регулярно публикуют списки вредоносных доменов.

---

Установка

Клонировать репозиторий:

git clone https://github.com/yourname/dynamic-dns-blocklist-builder.git
cd dynamic-dns-blocklist-builder

---

Требования

Python:

3.8+

Скрипт использует только стандартную библиотеку Python.

---

Запуск

python3 blocklist_builder.py

После выполнения создаётся файл:

dynamic-blocklist.txt

Пример строки:

0.0.0.0 malicious-domain.com

---

GitHub Actions (автообновление блоклиста)

Создай файл:

.github/workflows/update-blocklist.yml

Содержимое:

name: Update DNS Blocklist

on:
  schedule:
    - cron: "0 */12 * * *"
  workflow_dispatch:

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Run builder
        run: python3 blocklist_builder.py

      - name: Commit blocklist
        run: |
          git config --global user.name "github-actions"
          git config --global user.email "actions@github.com"
          git add dynamic-blocklist.txt
          git commit -m "auto update blocklist" || echo "no changes"
          git push

Теперь GitHub будет обновлять блоклист автоматически каждые 12 часов.

---

Пример вывода

🚀 Blocklist build started

Source: URLhaus
Domains: 4320

Source: OpenPhish
Domains: 1103

Source: ThreatFox
Domains: 2480

Total unique domains: 7693

---

Использование

Подходит для:

- Pi-hole
- personalDNSfilter
- AdGuard
- системного "hosts"
- локальных DNS серверов

---

Безопасность

Проект:

- не выполняет удалённый код
- не передает пользовательские данные
- использует только публичные threat-intel источники

Но возможны false positives.

---

Лицензия

MIT License

Свободно используйте, модифицируйте и распространяйте.

---

Contribution

Pull requests приветствуются.

Если вы нашли новый источник threat-intel — создайте issue.
