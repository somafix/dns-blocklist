#!/usr/bin/env python3

import urllib.request
import re
from datetime import datetime, timezone
from typing import Set
import subprocess
import sys
import os


URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; HostsFetcher/1.0)"}
TIMEOUT = 30
OUTPUT = "hosts.txt"


def fetch(url: str) -> str:
    """Fetch content from URL with error handling."""
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except urllib.error.URLError as e:
        print(f"FAIL {url}: {e}")
        return ""
    except Exception as e:
        print(f"FAIL {url}: Unexpected error: {e}")
        return ""


def extract_hosts(raw: str) -> Set[str]:
    """Extract valid hosts from blocklist content."""
    hosts: Set[str] = set()
    
    ip_domain_pattern = re.compile(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")
    domain_pattern = re.compile(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")
    
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        ip_domain_match = ip_domain_pattern.match(line)
        if ip_domain_match:
            hosts.add(f"0.0.0.0 {ip_domain_match.group(2)}")
            continue

        domain_match = domain_pattern.match(line)
        if domain_match:
            hosts.add(f"0.0.0.0 {domain_match.group(1)}")

    return hosts


def save(hosts: Set[str]) -> None:
    """Save hosts to output file with header."""
    sorted_hosts = sorted(hosts)
    
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("# HaGeZi Multi Normal\n")
        f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Total: {len(sorted_hosts)}\n")
        f.write("# \n")
        f.write("127.0.0.1 localhost\n")
        f.write("127.0.0.1 localhost.localdomain\n")
        f.write("::1 localhost\n\n")
        
        for line in sorted_hosts:
            f.write(f"{line}\n")


def git_safe_push() -> None:
    """Handle git push with proper merge strategy for CI/CD."""
    try:
        # Stash any local changes
        subprocess.run(["git", "stash", "--include-untracked"], 
                      capture_output=True, check=False)
        
        # Pull with rebase to avoid merge commits
        subprocess.run(["git", "pull", "--rebase", "--autostash"], 
                      capture_output=True, check=False)
        
        # Add the modified file
        subprocess.run(["git", "add", OUTPUT], check=True)
        
        # Check if there are changes to commit
        result = subprocess.run(["git", "diff", "--cached", "--quiet"], 
                               capture_output=True, check=False)
        
        if result.returncode != 0:
            # Commit changes
            date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            subprocess.run(["git", "commit", "-m", f"Daily update {date_str}"], 
                         check=True)
            
            # Pull again before push (in case of race condition)
            subprocess.run(["git", "pull", "--rebase", "--autostash"], 
                         capture_output=True, check=False)
            
            # Push changes
            push_result = subprocess.run(["git", "push"], capture_output=True, text=True)
            
            if push_result.returncode != 0:
                print(f"Push failed: {push_result.stderr}")
                # Try force push only if it's a fast-forward issue
                if "rejected" in push_result.stderr and "fetch first" in push_result.stderr:
                    print("Attempting force push after rebase...")
                    subprocess.run(["git", "push", "--force-with-lease"], check=False)
        else:
            print("No changes to commit")
            
    except subprocess.CalledProcessError as e:
        print(f"Git operation failed: {e}")
        # Don't exit with error in CI - allow workflow to continue
    except Exception as e:
        print(f"Unexpected git error: {e}")


def main() -> None:
    """Main execution function."""
    print("> fetching hosts from HaGeZi blocklist...")
    raw = fetch(URLS[0])
    
    if not raw:
        print("ERROR: Empty response received")
        sys.exit(1)

    hosts = extract_hosts(raw)
    
    if not hosts:
        print("ERROR: No valid hosts extracted")
        sys.exit(1)
        
    # Save to temporary file first to verify content
    temp_output = f"{OUTPUT}.tmp"
    sorted_hosts = sorted(hosts)
    
    with open(temp_output, "w", encoding="utf-8") as f:
        f.write("# HaGeZi Multi Normal\n")
        f.write(f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        f.write(f"# Total: {len(sorted_hosts)}\n")
        f.write("# \n")
        f.write("127.0.0.1 localhost\n")
        f.write("127.0.0.1 localhost.localdomain\n")
        f.write("::1 localhost\n\n")
        
        for line in sorted_hosts:
            f.write(f"{line}\n")
    
    # Check if content actually changed
    changed = True
    if os.path.exists(OUTPUT):
        with open(OUTPUT, "r", encoding="utf-8") as old, \
             open(temp_output, "r", encoding="utf-8") as new:
            changed = old.read() != new.read()
    
    # Replace the file if changed
    if changed:
        os.replace(temp_output, OUTPUT)
        print(f"> Success: {len(hosts)} entries saved to {OUTPUT}")
        
        # Handle git operations only if in CI environment or .git exists
        if os.path.exists(".git") and os.getenv("GITHUB_ACTIONS") == "true":
            git_safe_push()
        elif os.path.exists(".git"):
            print("Git repository detected but not in CI - skipping auto-push")
    else:
        os.remove(temp_output)
        print(f"> No changes detected - {len(hosts)} entries unchanged")
    
    # Verify output file exists and has content
    if not os.path.exists(OUTPUT) or os.path.getsize(OUTPUT) == 0:
        print("ERROR: Output file is missing or empty")
        sys.exit(1)


if __name__ == "__main__":
    main()
