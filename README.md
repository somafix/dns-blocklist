# 🛡️ personalDNSfilter — Оптимизированная конфигурация + Динамический блок-лист

Готовая конфигурация для приложения [personalDNSfilter](https://www.zenz-solutions.de/personaldnsfilter-wp/) с автоматически обновляемым блок-листом трекеров, рекламы и малвари в реальном времени.

---

## 🔥 Что это даёт

- **Блокировка рекламы и трекеров** — 17 источников фильтров включая HaGeZi, OISD, AdAway, StevenBlack
- **Защита от малвари и фишинга** — URLhaus, ThreatFox, OpenPhish, CERT.PL
- **Перехват hardcoded DNS** — приложения вроде Facebook, Instagram которые игнорируют системный DNS и обращаются напрямую к Google/Cloudflare — теперь тоже фильтруются
- **Автообновление каждый час** — новые трекеры и угрозы попадают в блок-лист автоматически через GitHub Actions
- **Совместимость** — работает на любых Android устройствах включая MIUI, One UI, ColorOS

---

## 📁 Файлы репозитория

| Файл | Описание |
|---|---|
| `personalDNSfilter_FINAL.conf` | Готовый конфиг для приложения на телефоне |
| `update_blocklist.py` | Python скрипт сборки динамического блок-листа |
| `.github/workflows/update-blocklist.yml` | GitHub Actions — запускает скрипт каждый час |
| `dynamic-blocklist.txt` | Готовый блок-лист (генерируется автоматически) |

---

## 🚀 Установка

### Шаг 1 — Установи приложение

Скачай [personalDNSfilter](https://play.google.com/store/apps/details?id=dnsfilter.android) из Google Play.

### Шаг 2 — Загрузи конфиг

1. Скачай файл `personalDNSfilter_FINAL.conf` из этого репозитория
2. Помести его в папку на телефоне:
```
/storage/emulated/0/Android/media/dnsfilter.android/
```
3. Открой приложение → **Advanced settings** → **Edit configuration** → загрузи файл

### Шаг 3 — Готово

Запусти приложение — оно автоматически скачает все фильтры при первом старте.

---

## 📋 Источники фильтров

| Источник | Тип | Обновление |
|---|---|---|
| [HaGeZi Pro++](https://github.com/hagezi/dns-blocklists) | Реклама / трекеры | 1-2 раза в сутки |
| [HaGeZi Ultimate](https://github.com/hagezi/dns-blocklists) | Максимальная блокировка | 1-2 раза в сутки |
| [OISD Big](https://oisd.nl) | Реклама / трекеры | Ежедневно |
| [AdAway](https://adaway.org) | Реклама | Ежедневно |
| [StevenBlack](https://github.com/StevenBlack/hosts) | Реклама / малварь | Ежедневно |
| [URLhaus](https://urlhaus.abuse.ch) | Малварь / C2 серверы | Каждые минуты |
| [ThreatFox](https://threatfox.abuse.ch) | IOC / малварь | Каждые минуты |
| [OpenPhish](https://openphish.com) | Фишинг | Каждые часы |
| [CERT.PL](https://hole.cert.pl) | Угрозы UA/EU | Несколько раз в сутки |
| HaGeZi Native (Amazon, Apple, Samsung, Xiaomi, Windows) | Телеметрия производителей | 1-2 раза в сутки |
| [Peter Lowe](https://pgl.yoyo.org) | Реклама | Ежедневно |
| [GoodbyeAds](https://github.com/jerryn70/GoodbyeAds) | Реклама | Ежедневно |

---

## ⚙️ Ключевые настройки конфига

| Параметр | Значение | Описание |
|---|---|---|
| `fallbackDNS` | Cloudflare 1.1.1.2 + Quad9 9953 | Cloudflare с блокировкой малвари, Quad9 на альтернативном порту |
| `ipVersionSupport` | `46` | Поддержка IPv4 и IPv6 |
| `routeIPs` | Google + Cloudflare + Quad9 | Перехват hardcoded DNS в приложениях |
| `routeUnderlyingDNS` | `true` | Перехват DNS браузеров (Chrome и др.) |
| `androidKeepAwake` | `true` | Защита от убийства сервиса в фоне |
| `dnsRequestTimeout` | `5000` | Увеличен таймаут для медленных устройств |
| `reloadIntervalDays` | `1` | Обновление фильтров каждые сутки |

---

## 🤖 Как работает автообновление

```
GitHub Actions (каждый час)
        ↓
update_blocklist.py
        ↓
Скачивает свежие данные из URLhaus, ThreatFox, OpenPhish, CERT.PL, HaGeZi
        ↓
Генерирует dynamic-blocklist.txt
        ↓
Пушит в репозиторий
        ↓
personalDNSfilter на телефоне скачивает обновление раз в сутки
```

---

## ❓ Частые вопросы

**Что-то перестало работать после установки конфига?**
Убедись что в настройках Android отключён **Private DNS** (Настройки → Сеть → Дополнительно → Private DNS → Выключить). Иначе система обходит personalDNSfilter.

**Приложение останавливается в фоне?**
Добавь personalDNSfilter в исключения оптимизации батареи (Настройки → Батарея → Оптимизация → personalDNSfilter → Не оптимизировать).

**Блокируется нужный сайт?**
В приложении нажми на заблокированный домен в логе → **Whitelist** — он больше не будет блокироваться.

---

## 📄 Лицензия

MIT — используй свободно.
