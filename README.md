# 🛡️ Dynamic DNS Blocklist Builder

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=github&logoColor=white)]()
[![Build](https://img.shields.io/github/actions/workflow/status/somafix/dns-blocklist/update.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Auto%20Update)](https://github.com/somafix/dns-blocklist/actions)
[![Last Updated](https://img.shields.io/badge/dynamic/json?url=https://api.github.com/repos/somafix/dns-blocklist/commits/main&query=$[0].commit.committer.date&style=for-the-badge&logo=clock&logoColor=white&label=Last%20Update)](https://github.com/somafix/dns-blocklist/commits/main)

---

**Автоматическая агрегация блоклистов угроз с обновлением каждые 6 часов**

Агрегирует проверенные источники угроз, дедуплицирует и публикует в форматах для популярных DNS-фильтров. Просто добавьте URL — обновления придут автоматически.

</div>

---

## 📋 Быстрые ссылки

| Фильтр | Формат | URL для импорта | Размер |
|--------|--------|----------------|--------|
| **AdGuard Home** | Plain text | `https://raw.githubusercontent.com/somafix/dns-blocklist/main/dynamic-blocklist.txt` | ~2.5 MB |
| **Pi-hole** | Plain text | `https://raw.githubusercontent.com/somafix/dns-blocklist/main/dynamic-blocklist.txt` | ~2.5 MB |
| **personalDNSfilter** | hosts | `https://raw.githubusercontent.com/somafix/dns-blocklist/main/personalDNSfilter_FINAL.conf` | ~2.4 MB |

**~62,000 уникальных доменов** после дедупликации и валидации

---

## 🚀 Как использовать

### 🛡️ AdGuard Home

1. **Filters → DNS blocklists → Add blocklist**
2. Вставьте URL:
