# 🛡️ personalDNSfilter — Linux Installation Guide

<div align="center">

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Linux](https://img.shields.io/badge/OS-Linux-FCC624?logo=linux&logoColor=black)
![Java](https://img.shields.io/badge/Java-11+-orange?logo=java)
![Status](https://img.shields.io/badge/Status-Active-success)

**Повна українська інструкція для установки personalDNSfilter на Linux з автоматичним запуском**

[English](#english-version) • [Українська](#українська-версія)

</div>

---

## 📋 Зміст

- [Українська версія](#українська-версія)
- [Швидкий старт](#швидкий-старт)
- [Детальна інструкція](#детальна-інструкція)
- [Розв'язання помилок](#розвязання-помилок)
- [Дистанційне керування](#дистанційне-керування)
- [Зупинка сервісу](#зупинка-сервісу)
- [FAQ](#faq)

---

## 🇺🇦 Українська версія

### Що таке personalDNSfilter?

**personalDNSfilter** (pDNSf) — це потужний DNS-фільтр на рівні системи, який блокує рекламу, малвер і трекери на всіх пристроях у вашій мережі.

### ✨ Переваги

✅ Блокування реклами на рівні DNS  
✅ Захист від малвера і трекерів  
✅ Низьке споживання ресурсів  
✅ Дистанційне керування з Android  
✅ Настроювані списки блокування  
✅ Легкий в установці на Linux  

---

## 🚀 Швидкий старт

### Мінімальна конфігурація (5 хвилин)

```bash
# 1. Встановіть Java
sudo apt-get update && sudo apt-get install -y openjdk-11-jre-headless

# 2. Завантажте personalDNSfilter
cd ~ && wget https://www.zenz-solutions.de/personaldnsfilter/personalDNSfilter.zip
unzip personalDNSfilter.zip

# 3. Тестуйте запуск
cd personalDNSfilter
sudo java -cp ./personalDNSfilter.jar dnsfilter.DNSFilterProxy
```

Якщо все добре — **Ctrl+C** і переходьте до розділу [Запуск при старті](#запуск-при-старті-системи).

---

## 📖 Детальна інструкція

### Крок 1️⃣: Установка Java Runtime

personalDNSfilter вимагає Java 11 або новішої версії.

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install openjdk-11-jre-headless
```

#### Fedora/RHEL:
```bash
sudo dnf install java-11-openjdk-headless
```

#### Arch:
```bash
sudo pacman -S jre11-openjdk-headless
```

**Перевірка:**
```bash
java -version
```

Має вивести щось на кшталт:
```
openjdk version "11.0.x"
```

---

### Крок 2️⃣: Завантаження personalDNSfilter

Завантажте офіційний пакет:

```bash
# Метод 1: Прямо з офіційного сайту
cd ~
wget https://www.zenz-solutions.de/personaldnsfilter/personalDNSfilter.zip

# Метод 2: З GitHub (якщо доступний)
wget https://github.com/IngoZenz/personaldnsfilter/releases/download/latest/personalDNSfilter.zip
```

---

### Крок 3️⃣: Розпакування

```bash
unzip personalDNSfilter.zip -d ~/
cd ~/personalDNSfilter
ls -la
```

Повинні бути файли:
- `personalDNSfilter.jar`
- `dnsfilter.conf`
- інші конфіг-файли

---

### Крок 4️⃣: Тестування запуску

```bash
sudo java -cp ./personalDNSfilter.jar dnsfilter.DNSFilterProxy
```

**Очікуваний вивід:**
```
Initializing PersonalDNSFilter Version 1504100!
Using Directory: /home/username/personalDNSfilter
DNS detection not supported for this device
DNS detection not supported - Using fallback!
DNS: 8.8.8.8
DNS: 8.8.4.4
DNSFilterProxy running on port 53!
```

Якщо нема помилок — ✅ готово! Натисніть **Ctrl+C** для вихода.

> ⚠️ **Якщо виникла помилка** — див. розділ [Розв'язання помилок](#розвязання-помилок).

---

## ⚙️ Конфігурація

### Спосіб 1: Прямо редагувати конфіг

```bash
nano ~/personalDNSfilter/dnsfilter.conf
```

Важливі параметри:
```ini
# DNS порт (якщо 53 зайнятий, використовуйте інший)
dnsProxyPortNonAndroid = 53

# Ваші пользувальницькі списки блокування
filterurl1 = https://adaway.org/hosts.txt
filterurl2 = https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
filterurl3 = https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock.txt
```

Збережіть (**Ctrl+O**, потім **Enter**, потім **Ctrl+X**).

### Спосіб 2: Синхронізація з Android

Якщо у вас вже є налаштований personalDNSfilter на телефоні:

```bash
# На телефоні: поділіться папкою personalDNSfilter
# На ПК: скопіюйте конфіг
adb pull /data/data/dnsfilter/files/dnsfilter.conf ~/personalDNSfilter/
```

---

## 🔧 Запуск при старті системи

Це найскладніша, але найважливіша частина.

### Кроки:

#### 1️⃣ Створіть bash скрипт `~/start_pdnsf.sh`

```bash
cat > ~/start_pdnsf.sh << 'EOF'
#!/bin/bash

# Чистимо попередні правила
sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null
sudo iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:5300 2>/dev/null

# Додаємо нові правила
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -I OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:5300

# Запускаємо personalDNSfilter
cd ~/personalDNSfilter
sudo java -cp ./personalDNSfilter.jar dnsfilter.DNSFilterProxy
EOF
```

Зробіть його виконавчим:
```bash
chmod +x ~/start_pdnsf.sh
```

**Тестуйте запуск:**
```bash
~/start_pdnsf.sh
```

#### 2️⃣ Налаштуйте sudo без пароля

Щоб iptables працював без пароля:

```bash
sudo visudo
```

Додайте в кінець:
```
# personalDNSfilter
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/iptables
%sudo ALL=(ALL) NOPASSWD: /usr/bin/java
```

Збережіть (**Ctrl+O**, потім **Enter**, потім **Ctrl+X**).

#### 3️⃣ Створіть systemd сервіс

```bash
sudo nano /etc/systemd/system/pdnsf.service
```

Вставте:
```ini
[Unit]
Description=personalDNSfilter DNS Proxy
After=network.target

[Service]
Type=simple
User=root
ExecStart=/home/USERNAME/start_pdnsf.sh
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

> **Замініть USERNAME на ваше ім'я користувача!**

Активуйте сервіс:
```bash
sudo systemctl daemon-reload
sudo systemctl enable pdnsf.service
sudo systemctl start pdnsf.service
```

**Перевірка статусу:**
```bash
sudo systemctl status pdnsf.service
```

---

## 🔐 Дистанційне керування

Керуйте personalDNSfilter з Android телефону, поки він працює на ПК.

### На ПК (сервер):

```bash
nano ~/personalDNSfilter/dnsfilter.conf
```

Знайдіть і змініть:
```ini
# Пароль для підключення з телефону (змініть!)
server_remote_ctrl_keyphrase = YourSecurePassword123

# Порт для дистанційного керування (використовуйте вільний)
server_remote_ctrl_port = 3333
```

### На телефоні (клієнт):

Відредагуйте `personalDNSfilter/dnsfilter.conf`:

```ini
# IP адреса вашого ПК у локальній мережі
client_remote_ctrl_host = 192.168.1.100

# Той же пароль, що на ПК
client_remote_ctrl_keyphrase = YourSecurePassword123

# Той же порт, що на ПК
client_remote_ctrl_port = 3333
```

Перезапустіть додаток на телефоні → натисніть іконку підключення → готово! ✅

---

## 🛑 Зупинка сервісу

### Постійна зупинка:
```bash
sudo systemctl stop pdnsf.service
sudo systemctl disable pdnsf.service
```

### Тимчасова зупинка (очистка маршрутизації):
```bash
sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -D OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:5300
```

### Перезапуск:
```bash
sudo systemctl restart pdnsf.service
```

---

## ❌ Розв'язання помилок

### ❌ Помилка: "Cannot open DNS port 53"

**Причина:** Порт 53 уже займає інший сервіс (systemd-resolved).

**Розв'язок:**

```bash
# 1. Перевірте, який процес займає порт 53
sudo lsof -i :53

# 2. Відредагуйте конфіг
nano ~/personalDNSfilter/dnsfilter.conf
```

Змініть:
```ini
# Було:
dnsProxyPortNonAndroid = 53

# Стало:
dnsProxyPortNonAndroid = 5300
```

```bash
# 3. Оновіть скрипт start_pdnsf.sh
# Змініть всі посилання з :5300 на :5300 (вже зроблено в прикладі вище)

# 4. Перезапустіть
sudo systemctl restart pdnsf.service
```

### ❌ Помилка: "Java not found"

```bash
java -version
# Якщо не знайдено:
sudo apt-get install openjdk-11-jre-headless
```

### ❌ Помилка: "Permission denied"

```bash
# Зробіть скрипт виконавчим:
chmod +x ~/start_pdnsf.sh

# Переконайтесь, що sudo налаштований без пароля (див. крок 2️⃣)
```

### ❌ personalDNSfilter не запускається при старті

```bash
# Перевірте логи сервісу:
sudo journalctl -u pdnsf.service -n 50

# Або запустіть вручну для отримання детальної помилки:
~/start_pdnsf.sh
```

---

## 📊 Моніторинг

### Перевіра стану сервісу:
```bash
sudo systemctl status pdnsf.service
```

### Логи в реальному часі:
```bash
sudo journalctl -u pdnsf.service -f
```

### Статистика фільтрації:
```bash
# Якщо налаштована веб-консоль, відкрийте:
# http://localhost:8080
```

---

## 🌐 Рекомендовані списки блокування

Додайте в `dnsfilter.conf`:

```ini
# Реклама
filterurl1 = https://adaway.org/hosts.txt
filterurl2 = https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

# Малвер і трекери
filterurl3 = https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock.txt
filterurl4 = https://threatfox-api.abuse.ch/downloads/urlhaus-filter-domains.txt

# Українські оновлення
filterurl5 = https://raw.githubusercontent.com/noads-ai/blocklist/main/domains.txt
```

---

## ❓ FAQ

**P: Чи отримаю я повільніший інтернет?**  
A: Ні. personalDNSfilter дуже легкий та працює на рівні DNS, впливу на швидкість мінімальний.

**P: Чи буде працювати з VPN?**  
A: Залежить від налаштувань VPN. Рекомендується налаштувати personalDNSfilter вище за VPN у стеку.

**P: Чи потрібна інтернет-з'єднання?**  
A: Так, для завантаження списків блокування. Сам фільтр працює локально.

**P: Як оновити списки блокування?**  
A: personalDNSfilter оновлює списки автоматично згідно з налаштуваннями в `dnsfilter.conf`.

**P: Чи можу я використовувати на роутері?**  
A: Так, якщо роутер працює на Linux (OpenWrt, DD-WRT тощо).

---

## 🔗 Посилання

- 🌐 [Офіційний сайт](https://www.zenz-solutions.de/personaldnsfilter/)
- 📝 [GitHub](https://github.com/IngoZenz/personaldnsfilter)
- 📚 [Wiki](https://github.com/IngoZenz/personaldnsfilter/wiki)

---

## 📝 Ліцензія

Questo progetto segue la licenza dell'autore originale Ingo Zenz.

---

## 🤝 Допомога

Якщо у вас виникли проблеми:

1. Перевірте [Розв'язання помилок](#розвязання-помилок)
2. Перегляньте логи: `sudo journalctl -u pdnsf.service`
3. Відкрийте Issue на GitHub

---

<div align="center">

Made with ❤️ for Ukrainian Linux users

![visitors](https://visitor-badge.laobi.icu/badge?page_id=github.personalDNSfilter.guide)

</div>

---

## English Version

> [Full English guide in separate section...]

### Quick Start (English)

```bash
# Install Java
sudo apt-get update && sudo apt-get install -y openjdk-11-jre-headless

# Download personalDNSfilter
cd ~ && wget https://www.zenz-solutions.de/personaldnsfilter/personalDNSfilter.zip
unzip personalDNSfilter.zip && cd personalDNSfilter

# Test run
sudo java -cp ./personalDNSfilter.jar dnsfilter.DNSFilterProxy
```

For full English instructions, follow the same steps as Ukrainian section above.

---

**Last Updated:** 2026 | **Linux Support:** Ubuntu, Debian, Fedora, Arch, CentOS
