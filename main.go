package main

import (
    "bufio"
    "context"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "sort"
    "strings"
    "sync"
    "time"
)

var sources = []string{
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
}

const (
    maxResponseSize = 50 * 1024 * 1024 // 50 MB
    maxDomainLength = 253
    requestTimeout  = 30 * time.Second
    totalTimeout    = 3 * time.Minute
    rateLimitDelay  = 500 * time.Millisecond
)

type fetchResult struct {
    source  string
    domains []string
    err     error
}

// validateDomain - усиленная валидация доменов
func validateDomain(domain string) bool {
    if len(domain) == 0 || len(domain) > maxDomainLength {
        return false
    }
    
    // Запрещаем wildcard
    if strings.Contains(domain, "*") {
        return false
    }
    
    // Запрещаем IDN без преобразования (безопаснее пропустить)
    for _, r := range domain {
        if r > 0x7F {
            return false
        }
    }
    
    // Запрещаем локальные домены и IP
    if strings.HasSuffix(domain, ".local") ||
       strings.HasSuffix(domain, ".localhost") ||
       strings.HasSuffix(domain, ".lan") ||
       strings.HasSuffix(domain, ".internal") {
        return false
    }
    
    // Проверка формата
    domainRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
    return domainRegex.MatchString(domain)
}

// fetchWithLimit - загрузка с ограничением размера
func fetchWithLimit(ctx context.Context, sourceURL string) ([]string, error) {
    // Проверка схемы URL (защита от SSRF)
    parsedURL, err := url.Parse(sourceURL)
    if err != nil {
        return nil, fmt.Errorf("invalid URL: %w", err)
    }
    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        return nil, fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
    }
    
    req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", "blocklist-fetcher/1.0")
    
    client := http.Client{
        Timeout: requestTimeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 5 {
                return fmt.Errorf("too many redirects")
            }
            return nil
        },
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
    }
    
    // Лимит на размер ответа
    limitedReader := io.LimitReader(resp.Body, maxResponseSize)
    
    var domains []string
    scanner := bufio.NewScanner(limitedReader)
    
    // Настройка буфера для scanner (по умолчанию 64KB)
    const maxScanTokenSize = 1024 * 1024 // 1 MB
    buf := make([]byte, maxScanTokenSize)
    scanner.Buffer(buf, maxScanTokenSize)
    
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        parts := strings.Fields(line)
        var domain string
        
        // Стандартные hosts форматы
        if len(parts) >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
            domain = strings.ToLower(strings.TrimSuffix(parts[1], "."))
        } else if len(parts) == 1 && strings.Contains(parts[0], ".") && !strings.Contains(parts[0], "/") {
            domain = strings.ToLower(strings.TrimSuffix(parts[0], "."))
        }
        
        // Дополнительная проверка на зарезервированные имена
        if domain != "" && !strings.Contains(domain, "..") && !strings.HasPrefix(domain, "-") && !strings.HasSuffix(domain, "-") {
            if validateDomain(domain) {
                domains = append(domains, domain)
            }
        }
    }
    
    if err := scanner.Err(); err != nil {
        return domains, fmt.Errorf("scan error: %w", err)
    }
    
    return domains, nil
}

func fetchWorker(ctx context.Context, sourceURL string, results chan<- fetchResult) {
    // Rate limiting для предотвращения DoS источников
    time.Sleep(rateLimitDelay)
    
    domains, err := fetchWithLimit(ctx, sourceURL)
    results <- fetchResult{
        source:  sourceURL,
        domains: domains,
        err:     err,
    }
}

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
    defer cancel()
    
    fmt.Println("🚀 Fetching blocklists...")
    
    // Канал для результатов
    results := make(chan fetchResult, len(sources))
    var wg sync.WaitGroup
    
    // Конкурентная загрузка
    for _, src := range sources {
        wg.Add(1)
        go func(source string) {
            defer wg.Done()
            fetchWorker(ctx, source, results)
        }(src)
    }
    
    // Закрываем канал после завершения всех горутин
    go func() {
        wg.Wait()
        close(results)
    }()
    
    // Сбор результатов
    domainMap := make(map[string]struct{})
    var fetchErrors []string
    
    for res := range results {
        if res.err != nil {
            fetchErrors = append(fetchErrors, fmt.Sprintf("✗ %s: %v", res.source[strings.LastIndex(res.source, "/")+1:], res.err))
            continue
        }
        
        for _, domain := range res.domains {
            domainMap[domain] = struct{}{}
        }
        fmt.Printf("  ✓ %d domains from %s\n", len(res.domains), res.source[strings.LastIndex(res.source, "/")+1:])
    }
    
    // Вывод ошибок
    for _, errMsg := range fetchErrors {
        fmt.Println(errMsg)
    }
    
    if len(domainMap) == 0 {
        fmt.Println("❌ No domains fetched. Exiting.")
        os.Exit(1)
    }
    
    // Сортировка доменов
    allDomains := make([]string, 0, len(domainMap))
    for d := range domainMap {
        allDomains = append(allDomains, d)
    }
    sort.Strings(allDomains)
    
    // Запись в файл с буферизацией
    file, err := os.Create("blocklist.txt")
    if err != nil {
        panic(err)
    }
    defer file.Close()
    
    writer := bufio.NewWriterSize(file, 64*1024) // 64KB буфер
    for _, d := range allDomains {
        if _, err := writer.WriteString(d); err != nil {
            panic(fmt.Errorf("write error: %w", err))
        }
        if err := writer.WriteByte('\n'); err != nil {
            panic(fmt.Errorf("write error: %w", err))
        }
    }
    
    if err := writer.Flush(); err != nil {
        panic(fmt.Errorf("flush error: %w", err))
    }
    
    // Синхронизация с диском
    if err := file.Sync(); err != nil {
        fmt.Printf("Warning: sync error: %v\n", err)
    }
    
    // Статистика
    info, _ := file.Stat()
    sizeMB := float64(info.Size()) / (1024 * 1024)
    
    fmt.Printf("\n✅ Done: %d unique domains, %.2f MB\n", len(allDomains), sizeMB)
}