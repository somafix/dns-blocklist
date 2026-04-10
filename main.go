package main

import (
    "bufio"
    "fmt"
    "net/http"
    "os"
    "regexp"
    "sort"
    "strings"
    "time"
)

var sources = []string{
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
}

func fetch(url string) ([]string, error) {
    client := http.Client{Timeout: 30 * time.Second}
    resp, err := client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var domains []string
    scanner := bufio.NewScanner(resp.Body)
    domainRegex := regexp.MustCompile(`^[a-z0-9.-]+$`)

    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        parts := strings.Fields(line)
        var domain string

        if len(parts) >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
            domain = strings.ToLower(strings.TrimSuffix(parts[1], "."))
        } else if len(parts) == 1 && strings.Contains(parts[0], ".") {
            domain = strings.ToLower(strings.TrimSuffix(parts[0], "."))
        }

        if domain != "" && len(domain) < 253 && !strings.Contains(domain, "..") {
            if domainRegex.MatchString(domain) {
                domains = append(domains, domain)
            }
        }
    }
    return domains, nil
}

func main() {
    fmt.Println("🚀 Fetching blocklists...")

    domainMap := make(map[string]bool)

    for _, url := range sources {
        domains, err := fetch(url)
        if err != nil {
            fmt.Printf("✗ %s: %v\n", url, err)
            continue
        }
        for _, d := range domains {
            domainMap[d] = true
        }
        fmt.Printf("  ✓ %d domains from %s\n", len(domains), url[strings.LastIndex(url, "/")+1:])
    }

    // Сортируем
    allDomains := make([]string, 0, len(domainMap))
    for d := range domainMap {
        allDomains = append(allDomains, d)
    }
    sort.Strings(allDomains)

    // Сохраняем
    output := strings.Join(allDomains, "\n")
    os.WriteFile("blocklist.txt", []byte(output), 0644)

    sizeMB := float64(len(output)) / (1024 * 1024)
    fmt.Printf("\n✅ Done: %d domains, %.1f MB\n", len(allDomains), sizeMB)
}
