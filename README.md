# 🛡️ Dynamic DNS Blocklist Builder

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=github&logoColor=white)](https://github.com/yourname/dynamic-dns-blocklist-builder)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-blue?style=for-the-badge&logo=heartbeat&logoColor=white)](https://github.com/yourname/dynamic-dns-blocklist-builder/commits/main)
[![Type](https://img.shields.io/badge/Type-Utility-orange?style=for-the-badge&logo=tools&logoColor=white)](#)
[![Updates](https://img.shields.io/badge/Updates-Every%206h-blueviolet?style=for-the-badge&logo=clock&logoColor=white)](#⚙️-автоматическое-обновление)

---

**Единственная Python-утилита, которая автоматически обновляет блоклист угроз на GitHub**

Скрипт запускается по расписанию, собирает свежие данные о вредоносных доменах из авторитетных источников, генерирует актуальный blocklist и выкладывает его в репозиторий. DNS-фильтры (Pi-hole, AdGuard, personalDNSfilter и т.д.) автоматически подтягивают обновленный список — никаких ручных проверок не нужно.

</div>

---

<div align="center">

| 🔍 | 🚀 | 📊 | ✨ |
|----|----|----|-----|
| **Источники** | **Автоматизация** | **Статистика** | **Валидация** |
| 5 авторитетных источников угроз | GitHub Actions каждые 6ч | Анализ пересечений | Проверка синтаксиса |

</div>

## 📌 Что это делает?

```
🔄 Каждые 6 часов:

URLhaus   ─┐
OpenPhish ─┼─→ 🔗 Собрать свежие данные
ThreatFox ─┤
CERT.PL   ─┤
HaGeZi    ─┘
              ↓
         🔍 Валидировать домены
              ↓
         📄 Генерировать blocklist
              ↓
         📤 Выложить на GitHub
              ↓
         ✅ DNS-фильтры загружают автоматически
```

**Результат:** Ваш DNS-фильтр всегда имеет актуальный список блокировок без ручных обновлений.

---

## 🚀 Установка

```bash
# Клонируем репозиторий
git clone https://github.com/yourname/dynamic-dns-blocklist-builder.git
cd dynamic-dns-blocklist-builder

# Запускаем один раз
python3 blocklist_builder.py
```

Всё. Больше ничего не нужно. Скрипт создаст:
- `dynamic-blocklist.txt` — готовый список для DNS-фильтров
- `.download_cache.json` — кэш для оптимизации загрузок
- `.gitignore` — игнорирование кэша в Git

---

## 🔌 Подключение к DNS-фильтрам

### 📱 personalDNSfilter (Android)

```
Settings → Custom hosts → Paste or Import URL

https://raw.githubusercontent.com/yourname/dynamic-dns-blocklist-builder/main/dynamic-blocklist.txt
```

### 🏠 Pi-hole

```
Admin Dashboard → Adlists → Add new adlist

https://raw.githubusercontent.com/yourname/dynamic-dns-blocklist-builder/main/dynamic-blocklist.txt
```

### 🛡️ AdGuard Home

```
Settings → Filters → DNS blocklists → Add blocklist

https://raw.githubusercontent.com/yourname/dynamic-dns-blocklist-builder/main/dynamic-blocklist.txt
```

### 💻 Локальный hosts (Linux/macOS)

```bash
sudo cat dynamic-blocklist.txt >> /etc/hosts
sudo systemctl restart systemd-resolved
```

---

## ⚙️ Автоматическое обновление

### GitHub Actions (каждые 6 часов)

Создайте файл `.github/workflows/update-blocklist.yml`:

```yaml
name: 🔄 Update Blocklist

on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - run: python3 blocklist_builder.py
      
      - run: |
          git config user.name "github-actions"
          git config user.email "actions@github.com"
          git add dynamic-blocklist.txt
          git diff --quiet && git diff --staged --quiet || (git commit -m "🔄 Update blocklist $(date -u +'%Y-%m-%d %H:%M UTC')" && git push)
```

**Готово.** GitHub будет автоматически обновлять блоклист каждые 6 часов, а ваши DNS-фильтры загружают его без вашего участия.

---

## 📊 Источники данных

| Источник | Тип | Обновление |
|----------|-----|-----------|
| **URLhaus** | Malware / C2 | Daily |
| **OpenPhish** | Phishing | Real-time |
| **ThreatFox** | Malware Infrastructure | Daily |
| **CERT.PL** | Malware Domains | Daily |
| **HaGeZi Pro++** | Ads / Tracking | Weekly |

---

## 🔧 Конфигурация

### Добавить новый источник

```python
SOURCES = [
    {
        "url": "https://example.com/list.txt",
        "name": "My Source",
        "category": "malware",
        "is_url_list": False
    },
    # ... остальные источники
]
```

### Исключить домены (вайтлист)

```python
WHITELIST = {
    "localhost", "local",
    "mycompany.com",      # Доверенный домен
    "trusted-service.com",
}
```

### Изменить параметры

```python
TIMEOUT = 30              # Таймаут загрузки (сек)
OUTPUT_FILE = "dynamic-blocklist.txt"
CACHE_FILE = ".download_cache.json"
```

---

## 📈 Как это работает

1. **Загрузка** — скрипт подключается к источникам (с HTTP-кэшированием)
2. **Парсинг** — извлекает домены из разных форматов
3. **Валидация** — проверяет синтаксис, удаляет дубликаты
4. **Анализ** — показывает статистику и пересечения
5. **Генерация** — создаёт `dynamic-blocklist.txt`
6. **Git** — автоматически коммитит в репозиторий (GitHub Actions)
7. **Распространение** — DNS-фильтры подтягивают список автоматически

---

## 🔒 Безопасность

✅ Не требует привилегий администратора  
✅ Не модифицирует системные файлы  
✅ Открытый исходный код — проверяйте сами  
✅ Только HTTPS загрузки  
✅ Использует только встроенные Python библиотеки  

---

## 📋 Требования

- **Python 3.8+**
- Интернет-соединение
- GitHub аккаунт (для автоматизации через Actions)

---

## 📝 Лицензия

MIT License © 2024

Свободно используйте, модифицируйте и распространяйте.

---

<div align="center">

**Всегда актуальный блоклист без ручных обновлений** 🚀

[⬆ Наверх](#-dynamic-dns-blocklist-builder)

</div>
