#!/usr/bin/env python3

import asyncio
import aiohttp
import os
import sys
import shutil
import re
import logging
import logging.handlers
import atexit
from datetime import datetime
from typing import Set, Optional
from pathlib import Path

__version__ = "6.0.0"

CONFIG = {
    "urls": {
        "hagezi": {
            "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
            "enabled": True,
        },
        "adguard": {
            "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
            "enabled": True,
        },
    },
    "timeout": 30,
    "max_retries": 3,
    "retry_delay": 5,
    "user_agent": f"DNS-Blocklist-Manager/{__version__}",
}

FILES = {
    "output_domains": Path("domains.txt"),
    "output_adguard": Path("adguard_list.txt"),
    "output_hosts": Path("hosts.txt"),
    "backup_dir": Path("backup"),
    "whitelist": Path("lists/whitelist.txt"),
    "blacklist": Path("lists/blacklist.txt"),
    "log": Path("logs/dns_blocker.log"),
    "pid_file": Path("/tmp/dns_blocker.pid"),
}

for file in FILES.values():
    if isinstance(file, Path) and file.suffix:
        file.parent.mkdir(parents=True, exist_ok=True)


class Logger:
    def __init__(self, log_file: Path):
        self.logger = logging.getLogger("DNSBlocklistManager")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()

        handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        )
        self.logger.addHandler(handler)

        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(console)

    def info(self, msg):
        self.logger.info(msg)

    def error(self, msg):
        self.logger.error(msg)

    def warning(self, msg):
        self.logger.warning(msg)


class DomainValidator:
    @staticmethod
    def clean(line: str) -> Optional[str]:
        if not line:
            return None

        if "#" in line:
            line = line[: line.index("#")]

        line = line.strip().lower()

        prefixes = ["0.0.0.0 ", "127.0.0.1 ", "::1 ", "||", "https://", "http://"]
        for prefix in prefixes:
            if line.startswith(prefix):
                line = line[len(prefix):]

        if line.endswith("^") or line.endswith("/"):
            line = line[:-1]

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            return None

        if line and line.count(".") >= 1 and len(line) < 253:
            return line

        return None


class NetworkFetcher:
    def __init__(self, logger: Logger):
        self.logger = logger

    async def fetch(self, url: str, name: str) -> Optional[str]:
        for attempt in range(CONFIG["max_retries"]):
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {"User-Agent": CONFIG["user_agent"]}
                    async with session.get(
                        url, headers=headers, timeout=CONFIG["timeout"]
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            self.logger.info(f"✓ {name}: {len(text):,} bytes")
                            return text
                        self.logger.warning(f"{name}: HTTP {resp.status}")
            except Exception as e:
                self.logger.warning(f"{name}: {e}")

            if attempt < CONFIG["max_retries"] - 1:
                await asyncio.sleep(CONFIG["retry_delay"])

        self.logger.error(f"✗ {name}: FAILED after {CONFIG['max_retries']} attempts")
        return None


class BlocklistManager:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.fetcher = NetworkFetcher(logger)
        self.domains: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self._load_custom_lists()

    def _load_custom_lists(self):
        if FILES["whitelist"].exists():
            with open(FILES["whitelist"]) as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        self.whitelist.add(domain)
            self.logger.info(f"Whitelist: {len(self.whitelist)} domains")

        if FILES["blacklist"].exists():
            with open(FILES["blacklist"]) as f:
                for line in f:
                    domain = DomainValidator.clean(line)
                    if domain:
                        self.blacklist.add(domain)
            self.logger.info(f"Blacklist: {len(self.blacklist)} domains")

    async def fetch_all(self):
        tasks = []
        for name, src in CONFIG["urls"].items():
            if src.get("enabled", True):
                tasks.append(self._fetch_and_parse(src["url"], name))

        results = await asyncio.gather(*tasks)
        for domains_set in results:
            if domains_set:
                self.domains.update(domains_set)

        self.logger.info(f"Total unique domains: {len(self.domains):,}")

    async def _fetch_and_parse(self, url: str, name: str) -> Set[str]:
        content = await self.fetcher.fetch(url, name)
        if not content:
            return set()

        domains = set()
        for line in content.splitlines():
            domain = DomainValidator.clean(line)
            if domain:
                domains.add(domain)

        self.logger.info(f"  {name}: {len(domains):,} valid domains")
        return domains

    def apply_filters(self) -> Set[str]:
        result = set()
        stats = {"whitelisted": 0, "blacklisted": 0, "normal": 0}

        for domain in self.domains:
            if domain in self.whitelist:
                stats["whitelisted"] += 1
                continue
            if domain in self.blacklist:
                result.add(domain)
                stats["blacklisted"] += 1
                continue
            result.add(domain)
            stats["normal"] += 1

        self.logger.info("Filter results:")
        self.logger.info(f"  • Input: {len(self.domains):,}")
        self.logger.info(f"  • Output: {len(result):,}")
        self.logger.info(f"  • Whitelisted: {stats['whitelisted']}")
        self.logger.info(f"  • Blacklisted: {stats['blacklisted']}")

        return result


class Exporter:
    @staticmethod
    def backup():
        backup_dir = FILES["backup_dir"]
        backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for name in ["output_domains", "output_adguard", "output_hosts"]:
            src = FILES[name]
            if src.exists():
                dst = backup_dir / f"{src.stem}_{timestamp}{src.suffix}"
                shutil.copy2(src, dst)

    @staticmethod
    def export_domain_list(domains: Set[str], path: Path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# DNS Blocklist Manager v{__version__}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"# Total domains: {len(domains):,}\n")
            f.write("# ==========================================\n\n")
            for domain in sorted(domains):
                f.write(f"{domain}\n")

    @staticmethod
    def export_adguard_format(domains: Set[str], path: Path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("! Title: DNS Blocklist\n")
            f.write(f"! Version: {__version__}\n")
            f.write(f"! Last modified: {datetime.now().strftime('%c')}\n")
            f.write(f"! Total entries: {len(domains):,}\n")
            f.write("! ---------------------------------\n\n")
            for domain in sorted(domains):
                f.write(f"||{domain}^\n")

    @staticmethod
    def export_hosts_format(domains: Set[str], path: Path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# DNS Blocklist Manager v{__version__}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"# Total: {len(domains):,}\n")
            f.write("# ==========================================\n\n")
            for domain in sorted(domains):
                f.write(f"0.0.0.0 {domain}\n")


class PIDManager:
    def __init__(self, pid_file: Path):
        self.pid_file = pid_file
        self.pid = os.getpid()

    def check(self) -> bool:
        if self.pid_file.exists():
            try:
                old_pid = int(self.pid_file.read_text().strip())
                try:
                    os.kill(old_pid, 0)
                    print(f"❌ Process already running (PID {old_pid})")
                    return False
                except OSError:
                    self.pid_file.unlink()
            except (ValueError, FileNotFoundError):
                self.pid_file.unlink()

        self.pid_file.write_text(str(self.pid))
        return True

    def cleanup(self):
        try:
            if self.pid_file.exists():
                current = int(self.pid_file.read_text().strip())
                if current == self.pid:
                    self.pid_file.unlink()
        except (OSError, ValueError, FileNotFoundError):
            pass


async def main():
    pid_manager = PIDManager(FILES["pid_file"])
    if not pid_manager.check():
        return 1
    atexit.register(pid_manager.cleanup)

    logger = Logger(FILES["log"])
    logger.info(f"DNS Blocklist Manager v{__version__} started")

    print(f"\n🚀 DNS Blocklist Manager v{__version__}")
    print("✅ MODERNIZED VERSION - NO FAKE AI\n")

    try:
        manager = BlocklistManager(logger)
        exporter = Exporter()

        print("[1/4] 💾 Creating backup...")
        exporter.backup()

        print("[2/4] 📥 Downloading blocklists...")
        await manager.fetch_all()

        print("[3/4] 🔍 Applying whitelist/blacklist...")
        filtered_domains = manager.apply_filters()

        print("[4/4] 💾 Exporting to formats...")
        exporter.export_domain_list(filtered_domains, FILES["output_domains"])
        exporter.export_adguard_format(filtered_domains, FILES["output_adguard"])
        exporter.export_hosts_format(filtered_domains, FILES["output_hosts"])

        print("\n" + "=" * 50)
        print("✅ BUILD SUCCESSFUL")
        print("=" * 50)
        print(f"Total blocked domains: {len(filtered_domains):,}")
        print("\nFiles created:")

        for name, path in [
            ("Domain list", FILES["output_domains"]),
            ("AdGuard format", FILES["output_adguard"]),
            ("Hosts format", FILES["output_hosts"]),
        ]:
            if path.exists():
                size_mb = path.stat().st_size / 1024 / 1024
                print(f"  • {name}: {size_mb:.2f} MB")

        print("=" * 50)

        logger.info(f"Build completed: {len(filtered_domains):,} domains")
        return 0

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"\n❌ BUILD FAILED: {e}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
        sys.exit(130)