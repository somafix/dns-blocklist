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


def git_safe_commit_and_push() -> None:
    """Handle git commit and push with proper merge strategy."""
    try:
        # Configure git user if not set
        if not subprocess.run(["git", "config", "user.name"], capture_output=True, text=True).stdout.strip():
            subprocess.run(["git", "config", "user.name", "GitHub Actions"], check=False)
        if not subprocess.run(["git", "config", "user.email"], capture_output=True, text=True).stdout.strip():
            subprocess.run(["git", "config", "user.email", "actions@github.com"], check=False)
        
        # Fetch latest changes
        subprocess.run(["git", "fetch", "origin"], capture_output=True, check=False)
        
        # Check if we need to merge
        local_commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        remote_commit = subprocess.run(["git", "rev-parse", "origin/main"], capture_output=True, text=True).stdout.strip()
        
        if local_commit != remote_commit and remote_commit:
            # Reset to remote and reapply local changes
            subprocess.run(["git", "reset", "--soft", "origin/main"], check=False)
        
        # Add the modified file
        add_result = subprocess.run(["git", "add", OUTPUT], capture_output=True, check=False)
        if add_result.returncode != 0:
            print(f"Failed to add file: {add_result.stderr}")
            return
        
        # Check if there are changes to commit
        diff_result = subprocess.run(["git", "diff", "--cached", "--quiet"], capture_output=True, check=False)
        
        if diff_result.returncode != 0:
            # Commit changes
            date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
            commit_result = subprocess.run(["git", "commit", "-m", f"Daily update {date_str}"], 
                                         capture_output=True, text=True)
            
            if commit_result.returncode != 0:
                print(f"Commit failed: {commit_result.stderr}")
                return
            
            print(f"Committed: {commit_result.stdout}")
            
            # Push with force lease to handle race conditions
            push_result = subprocess.run(["git", "push", "--force-with-lease", "origin", "main"], 
                                       capture_output=True, text=True)
            
            if push_result.returncode != 0:
                print(f"Push failed: {push_result.stderr}")
                # Try regular push as fallback
                fallback_push = subprocess.run(["git", "push", "origin", "main"], 
                                            capture_output=True, text=True)
                if fallback_push.returncode != 0:
                    print(f"Fallback push also failed: {fallback_push.stderr}")
            else:
                print(f"Push successful: {push_result.stdout}")
        else:
            print("No changes to commit")
            
    except subprocess.CalledProcessError as e:
        print(f"Git operation failed: {e}")
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
        
    # Check if file changed before writing
    changed = True
    if os.path.exists(OUTPUT):
        with open(OUTPUT, "r", encoding="utf-8") as old:
            old_content = old.read()
            # Create new content in memory for comparison
            sorted_hosts = sorted(hosts)
            new_lines = [
                "# HaGeZi Multi Normal\n",
                f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n",
                f"# Total: {len(sorted_hosts)}\n",
                "# \n",
                "127.0.0.1 localhost\n",
                "127.0.0.1 localhost.localdomain\n",
                "::1 localhost\n\n"
            ]
            new_lines.extend(f"{line}\n" for line in sorted_hosts)
            new_content = "".join(new_lines)
            changed = old_content != new_content
    
    if changed:
        save(hosts)
        print(f"> Success: {len(hosts)} entries saved to {OUTPUT}")
        
        # Handle git operations if in CI environment
        if os.getenv("GITHUB_ACTIONS") == "true":
            git_safe_commit_and_push()
        elif os.path.exists(".git"):
            print("Git repository detected but not in CI - skipping auto-push")
    else:
        print(f"> No changes detected - {len(hosts)} entries unchanged")
    
    # Verify output file exists
    if not os.path.exists(OUTPUT):
        print("ERROR: Output file is missing")
        sys.exit(1)


if __name__ == "__main__":
    main()