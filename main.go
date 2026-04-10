package main

import (
    "bufio"
    "context"
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

// fetch с контекстом (чтобы можно было прервать)
func fetch(ctx context.Context, url string) ([]string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }

    client := http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
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
    return domains, scanner.Err()
}

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
    defer cancel()

    fmt.Println("🚀 Fetching blocklists...")

    domainMap := make(map[string]struct{}) // Экономим память: struct{} весит 0 байт

    for _, url := range sources {
        domains, err := fetch(ctx, url)
        if err != nil {
            fmt.Printf("✗ %s: %v\n", url, err)
            continue
        }
        for _, d := range domains {
            domainMap[d] = struct{}{}
        }
        fmt.Printf("  ✓ %d domains from %s\n", len(domains), url[strings.LastIndex(url, "/")+1:])
    }

    // Сортируем ключи мапы
    allDomains := make([]string, 0, len(domainMap))
    for d := range domainMap {
        allDomains = append(allDomains, d)
    }
    sort.Strings(allDomains)

    // Записываем сразу в файл, без буфера в памяти
    file, err := os.Create("blocklist.txt")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    writer := bufio.NewWriter(file)
    for _, d := range allDomains {
        writer.WriteString(d)
        writer.WriteByte('\n')
    }
    writer.Flush()

    // Считаем размер через stat, не читая файл обратно
    info, _ := file.Stat()
    sizeMB := float64(info.Size()) / (1024 * 1024)

    fmt.Printf("\n✅ Done: %d domains, %.1f MB\n", len(allDomains), sizeMB)
}
