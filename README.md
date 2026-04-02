# 🛡️ DNS Security Blocklist Builder 

### **Next-Gen Threat Intelligence & AI/ML Domain Filtering**
**Version 17.2.1** • *High-Concurrency Async Engine* • *Production Ready*

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic-V2-E92063?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge&logo=shield-check)](#)

---

## 🎯 Обзор проекта

**DNS Security Blocklist Builder** — это высокопроизводительный агрегатор данных об угрозах (Threat Intelligence), который собирает, валидирует и классифицирует домены в единый манифест безопасности. 

Версия **v17.2.1** полностью переработана для обеспечения максимальной чистоты данных: из списков исключены IP-адреса, локальные хосты и синтаксический мусор, специфичный для AdBlock-форматов.

> [!IMPORTANT]
> **Что нового в 17.2.1:** 
> * Добавлена интеграция **GoodbyeAds-YouTube** и **GoodbyeAds Ultimate**.
> * Исправлен парсинг: теперь движок корректно обрабатывает префиксы `||`, `@@` и `0.0.0.0`.
> * Строгая валидация регулярными выражениями для исключения битых доменов.

---

## 🔥 Ключевые возможности

### 🛠 Умная фильтрация и очистка
В отличие от стандартных скриптов, этот движок выполняет глубокую проверку каждой строки:
* **Anti-IP Filter:** Автоматический пропуск IPv4/IPv6 адресов, которые не должны быть в DNS-списках.
* **Format Normalization:** Приведение доменов к нижнему регистру, удаление мусорных символов и комментариев.
* **Localhost Shield:** Защита от блокировки критических локальных имен (localhost, broadcasthost и др.).

### 🤖 AI/ML Smart Categorization
Встроенный эвристический анализ идентифицирует инфраструктуру Искусственного Интеллекта. Движок автоматически помечает домены **OpenAI, Anthropic, Gemini, Midjourney** и других сервисов тегом `AI_ML`, позволяя гибко управлять доступом к AI-инструментам в корпоративной сети.

### ⚡ Async Processing Engine
Использование `AsyncIO` и `aiohttp` позволяет обрабатывать миллионы доменов за считанные секунды. 
* **Smart Caching:** Система кэширования с поддержкой `ETag` и `Gzip` позволяет не скачивать данные повторно, если они не изменились на сервере.
* **Low Memory Footprint:** Оптимизация через Python slots и эффективные хэш-сеты для дедупликации.

---

## 📂 Структура выходного файла

Генерируемый файл `blocklist.txt` полностью совместим с **Pi-hole**, **AdGuard Home**, **pfSense**, **Unbound** и **Mikrotik**.

```text
# DNS Security Blocklist - v17.2.1 FIXED
# Total unique domains: 1,842,901
# Stats: 🤖 AI_ML: 1.2k | 💀 MALWARE: 84k | 👁️ TRACKING: 210k

0.0.0.0 api.openai.com # AI_ML
0.0.0.0 doubleclick.net # ADS
0.0.0.0 track.analytics-data.io # TRACKING
0.0.0.0 malware-site.biz # MALWARE
