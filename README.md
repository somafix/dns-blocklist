# 🛡️ Dynamic DNS Blocklist Builder

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge&logo=github&logoColor=white)]()
[![Updates](https://img.shields.io/badge/Updates-Every%206h-blueviolet?style=for-the-badge&logo=clock&logoColor=white)]()

---

**Единственная Python-утилита, которая автоматически обновляет списки блокировки без участия человека**

Скрипт работает по расписанию, загружает актуальные данные об угрозах и обновляет список на GitHub. Просто скопируйте конфиг или список в ваш DNS-фильтр — и всё!

</div>

---

## 🚀 Как использовать

### 📱 personalDNSfilter (Android)

1. Откройте приложение
2. **Settings → Custom hosts → Import URL**
3. Вставьте:
   ```
   https://raw.githubusercontent.com/somafix/dns-blocklist/main/personalDNSfilter_FINAL.conf
   ```
4. Готово! Обновляется автоматически

---

### 🛡️ AdGuard Home

1. **Settings → Filters → DNS blocklists**
2. **Add blocklist**
3. Вставьте:
   ```
   https://raw.githubusercontent.com/somafix/dns-blocklist/main/dynamic-blocklist.txt
   ```
4. Готово!

---

### 🏠 Pi-hole

1. **Admin Dashboard → Adlists**
2. **Add new adlist**
3. Вставьте:
   ```
   https://raw.githubusercontent.com/somafix/dns-blocklist/main/dynamic-blocklist.txt
   ```
4. Готово!

---

### 💻 Локально

```bash
# Linux/macOS
sudo cp /etc/hosts /etc/hosts.backup
sudo cat dynamic-blocklist.txt >> /etc/hosts
sudo systemctl restart systemd-resolved
```

---

## 📊 Что входит

| Файл | Для кого | Размер |
|------|----------|--------|
| `personalDNSfilter_FINAL.conf` | 📱 personalDNSfilter | 2.4 MB |
| `dynamic-blocklist.txt` | 🛡️ AdGuard, Pi-hole | 2.5 MB |

**62,000+ уникальных опасных доменов**

---

## 🔄 Как это работает

```
📅 Каждые 6 часов:
GitHub Actions → Загружает данные → Обновляет файлы на GitHub
                                    ↓
                            Ваш DNS-фильтр
                         загружает сам!
```

Никакого ручного вмешательства не требуется.

---

## 📥 Установка (опционально)

```bash
git clone https://github.com/somafix/dns-blocklist.git
cd dns-blocklist
python3 update_blocklist.py
```

---

## 📋 Требования

- **Python 3.8+** (если запускаете локально)
- Интернет-соединение
- Один из поддерживаемых DNS-фильтров

---

## 🔒 Безопасность

✅ Не требует администратора  
✅ Открытый исходный код  
✅ Только HTTPS загрузки  
✅ Встроенные библиотеки Python  

---

## 📝 Лицензия

MIT License © 2024

---

<div align="center">

**Всегда актуальная защита. Без ручных обновлений.** 🚀

[GitHub](https://github.com/somafix/dns-blocklist)

</div>
