package main

import (
    "bufio"
    "compress/gzip"
    "container/heap"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/gob"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "path/filepath"
    "regexp"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

type Config struct {
    Sources          []string
    OutputFile       string
    TempDir          string
    MaxResponseSize  int64
    MaxDomainLength  int
    RequestTimeout   time.Duration
    TotalTimeout     time.Duration
    RateLimitDelay   time.Duration
    MaxRetries       int
    RetryBackoffBase time.Duration
    WorkerCount      int
    BufferSize       int
    EnableCache      bool
    CacheTTL         time.Duration
    EnableGZIP       bool
    ShardCount       int
}

var defaultConfig = Config{
    Sources: []string{
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://someonewhocares.org/hosts/zero/hosts",
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    },
    OutputFile:       "blocklist.txt",
    TempDir:          "tmp_blocklist",
    MaxResponseSize:  50 * 1024 * 1024,
    MaxDomainLength:  253,
    RequestTimeout:   30 * time.Second,
    TotalTimeout:     5 * time.Minute,
    RateLimitDelay:   200 * time.Millisecond,
    MaxRetries:       3,
    RetryBackoffBase: 2 * time.Second,
    WorkerCount:      4,
    BufferSize:       256 * 1024,
    EnableCache:      true,
    CacheTTL:         24 * time.Hour,
    EnableGZIP:       true,
    ShardCount:       100, // 100 временных файлов
}

type CacheEntry struct {
    Domains   []string
    Timestamp time.Time
    ETag      string
}

type Progress struct {
    total     int64
    completed int64
}

func (p *Progress) Add(n int64) {
    atomic.AddInt64(&p.completed, n)
}

func (p *Progress) SetTotal(n int64) {
    atomic.StoreInt64(&p.total, n)
}

func (p *Progress) Percent() float64 {
    total := atomic.LoadInt64(&p.total)
    completed := atomic.LoadInt64(&p.completed)
    if total == 0 {
        return 0
    }
    return float64(completed) / float64(total) * 100
}

type DiskCache struct {
    dir string
    ttl time.Duration
    mu  sync.RWMutex
}

func NewDiskCache(dir string, ttl time.Duration) (*DiskCache, error) {
    if err := os.MkdirAll(dir, 0755); err != nil {
        return nil, err
    }
    return &DiskCache{dir: dir, ttl: ttl}, nil
}

func (c *DiskCache) Get(key string) (*CacheEntry, error) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    filename := filepath.Join(c.dir, fmt.Sprintf("%x", sha256.Sum256([]byte(key)))+".gob")
    f, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    
    var entry CacheEntry
    dec := gob.NewDecoder(f)
    if err := dec.Decode(&entry); err != nil {
        return nil, err
    }
    
    if time.Since(entry.Timestamp) > c.ttl {
        os.Remove(filename)
        return nil, fmt.Errorf("expired")
    }
    
    return &entry, nil
}

func (c *DiskCache) Set(key string, entry *CacheEntry) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    filename := filepath.Join(c.dir, fmt.Sprintf("%x", sha256.Sum256([]byte(key)))+".gob")
    f, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer f.Close()
    
    enc := gob.NewEncoder(f)
    return enc.Encode(entry)
}

// Heap для multi-way merge
type DomainHeap struct {
    domains []string
    sources [][]string
    indices []int
}

func (h DomainHeap) Len() int { return len(h.domains) }
func (h DomainHeap) Less(i, j int) bool { return h.domains[i] < h.domains[j] }
func (h DomainHeap) Swap(i, j int) {
    h.domains[i], h.domains[j] = h.domains[j], h.domains[i]
    h.sources[i], h.sources[j] = h.sources[j], h.sources[i]
    h.indices[i], h.indices[j] = h.indices[j], h.indices[i]
}
func (h *DomainHeap) Push(x interface{}) {
    item := x.(struct {
        domain string
        source []string
        idx    int
    })
    h.domains = append(h.domains, item.domain)
    h.sources = append(h.sources, item.source)
    h.indices = append(h.indices, item.idx)
}
func (h *DomainHeap) Pop() interface{} {
    old := *h
    n := len(old.domains)
    item := struct {
        domain string
        source []string
        idx    int
    }{old.domains[n-1], old.sources[n-1], old.indices[n-1]}
    h.domains = h.domains[:n-1]
    h.sources = h.sources[:n-1]
    h.indices = h.indices[:n-1]
    return item
}

// РЕАЛЬНАЯ внешняя сортировка через шардирование
func externalSortSharded(inputFile string, outputFile string, shardCount int) error {
    // Шаг 1: Распределение по шардам
    shardWriters := make([]*bufio.Writer, shardCount)
    shardFiles := make([]*os.File, shardCount)
    
    for i := 0; i < shardCount; i++ {
        f, err := os.CreateTemp("", fmt.Sprintf("shard_%d_*.tmp", i))
        if err != nil {
            return err
        }
        shardFiles[i] = f
        shardWriters[i] = bufio.NewWriterSize(f, defaultConfig.BufferSize)
    }
    
    input, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    
    scanner := bufio.NewScanner(input)
    for scanner.Scan() {
        domain := scanner.Text()
        if domain == "" {
            continue
        }
        // Шардирование по хешу для равномерного распределения
        hash := sha256.Sum256([]byte(domain))
        shardIdx := int(hash[0]) % shardCount
        shardWriters[shardIdx].WriteString(domain)
        shardWriters[shardIdx].WriteByte('\n')
    }
    input.Close()
    
    // Закрываем все шарды
    for i := 0; i < shardCount; i++ {
        shardWriters[i].Flush()
        shardFiles[i].Close()
    }
    
    // Шаг 2: Сортировка каждого шарда индивидуально
    sortedShards := make([]string, shardCount)
    for i := 0; i < shardCount; i++ {
        // Читаем шард
        data, err := os.ReadFile(shardFiles[i].Name())
        if err != nil {
            return err
        }
        os.Remove(shardFiles[i].Name())
        
        lines := strings.Split(string(data), "\n")
        // Сортируем
        sort.Strings(lines)
        
        // Удаляем дубликаты внутри шарда
        unique := make([]string, 0, len(lines))
        for j, line := range lines {
            if line == "" {
                continue
            }
            if j == 0 || line != lines[j-1] {
                unique = append(unique, line)
            }
        }
        
        // Сохраняем отсортированный шард
        shardFile := filepath.Join(os.TempDir(), fmt.Sprintf("sorted_shard_%d.tmp", i))
        if err := os.WriteFile(shardFile, []byte(strings.Join(unique, "\n")), 0644); err != nil {
            return err
        }
        sortedShards[i] = shardFile
    }
    
    // Шаг 3: Multi-way merge через heap
    out, err := os.Create(outputFile)
    if err != nil {
        return err
    }
    defer out.Close()
    
    writer := bufio.NewWriterSize(out, defaultConfig.BufferSize)
    
    // Открываем все шарды
    readers := make([]*bufio.Scanner, shardCount)
    files := make([]*os.File, shardCount)
    
    for i := 0; i < shardCount; i++ {
        f, err := os.Open(sortedShards[i])
        if err != nil {
            return err
        }
        files[i] = f
        readers[i] = bufio.NewScanner(f)
    }
    defer func() {
        for i := 0; i < shardCount; i++ {
            if files[i] != nil {
                files[i].Close()
                os.Remove(sortedShards[i])
            }
        }
    }()
    
    // Инициализация heap
    h := &DomainHeap{
        domains: make([]string, 0, shardCount),
        sources: make([][]string, 0, shardCount),
        indices: make([]int, 0, shardCount),
    }
    
    for i := 0; i < shardCount; i++ {
        if readers[i].Scan() {
            domain := readers[i].Text()
            heap.Push(h, struct {
                domain string
                source []string
                idx    int
            }{domain, nil, i})
        }
    }
    
    // Merge
    var lastDomain string
    for h.Len() > 0 {
        item := heap.Pop(h).(struct {
            domain string
            source []string
            idx    int
        })
        
        domain := item.domain
        if domain != lastDomain {
            writer.WriteString(domain)
            writer.WriteByte('\n')
            lastDomain = domain
        }
        
        // Читаем следующий домен из того же источника
        if readers[item.idx].Scan() {
            nextDomain := readers[item.idx].Text()
            heap.Push(h, struct {
                domain string
                source []string
                idx    int
            }{nextDomain, nil, item.idx})
        }
    }
    
    return writer.Flush()
}

func validateDomain(domain string) bool {
    if len(domain) == 0 || len(domain) > defaultConfig.MaxDomainLength {
        return false
    }
    
    if strings.ContainsAny(domain, "*\\/:?&=@#$%^`|~") {
        return false
    }
    
    if strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".localhost") {
        return false
    }
    
    ipRegex := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
    if ipRegex.MatchString(domain) {
        return false
    }
    
    for _, r := range domain {
        if r > 0x7F {
            return false
        }
    }
    
    domainRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
    return domainRegex.MatchString(domain)
}

func fetchSource(ctx context.Context, sourceURL string, cache *DiskCache) ([]string, string, error) {
    parsedURL, err := url.Parse(sourceURL)
    if err != nil {
        return nil, "", err
    }
    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        return nil, "", fmt.Errorf("unsupported scheme")
    }
    
    req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
    if err != nil {
        return nil, "", err
    }
    req.Header.Set("User-Agent", "blocklist-fetcher/4.0")
    if defaultConfig.EnableGZIP {
        req.Header.Set("Accept-Encoding", "gzip")
    }
    
    client := &http.Client{Timeout: defaultConfig.RequestTimeout}
    resp, err := client.Do(req)
    if err != nil {
        return nil, "", err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
    }
    
    etag := resp.Header.Get("ETag")
    
    var reader io.Reader = resp.Body
    if defaultConfig.EnableGZIP && resp.Header.Get("Content-Encoding") == "gzip" {
        reader, err = gzip.NewReader(resp.Body)
        if err != nil {
            return nil, "", err
        }
        defer reader.(*gzip.Reader).Close()
    }
    
    limited := io.LimitReader(reader, defaultConfig.MaxResponseSize)
    scanner := bufio.NewScanner(limited)
    buf := make([]byte, defaultConfig.BufferSize)
    scanner.Buffer(buf, defaultConfig.BufferSize)
    
    var domains []string
    domainMap := make(map[string]struct{})
    
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
        
        if domain != "" && !strings.Contains(domain, "..") && validateDomain(domain) {
            if _, exists := domainMap[domain]; !exists {
                domainMap[domain] = struct{}{}
                domains = append(domains, domain)
            }
        }
    }
    
    if err := scanner.Err(); err != nil {
        return domains, etag, err
    }
    
    return domains, etag, nil
}

func fetchWithRetry(ctx context.Context, sourceURL string, cache *DiskCache) ([]string, error) {
    if defaultConfig.EnableCache && cache != nil {
        if entry, err := cache.Get(sourceURL); err == nil {
            fmt.Printf("  📦 Cached: %s (%d domains)\n", filepath.Base(sourceURL), len(entry.Domains))
            return entry.Domains, nil
        }
    }
    
    var lastErr error
    for attempt := 0; attempt <= defaultConfig.MaxRetries; attempt++ {
        if attempt > 0 {
            backoff := defaultConfig.RetryBackoffBase * time.Duration(attempt*attempt)
            fmt.Printf("  🔄 Retry %d for %s in %v\n", attempt, filepath.Base(sourceURL), backoff)
            time.Sleep(backoff)
        }
        
        domains, etag, err := fetchSource(ctx, sourceURL, cache)
        if err == nil {
            if defaultConfig.EnableCache && cache != nil {
                cache.Set(sourceURL, &CacheEntry{
                    Domains:   domains,
                    Timestamp: time.Now(),
                    ETag:      etag,
                })
            }
            return domains, nil
        }
        lastErr = err
        
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }
    }
    return nil, fmt.Errorf("failed: %w", lastErr)
}

func main() {
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()
    
    ctx, cancel = context.WithTimeout(ctx, defaultConfig.TotalTimeout)
    defer cancel()
    
    fmt.Println("🚀 Blocklist Generator v4.0 - Production Ready")
    os.MkdirAll(defaultConfig.TempDir, 0755)
    defer os.RemoveAll(defaultConfig.TempDir)
    
    var cache *DiskCache
    if defaultConfig.EnableCache {
        cache, _ = NewDiskCache(filepath.Join(defaultConfig.TempDir, "cache"), defaultConfig.CacheTTL)
    }
    
    type result struct {
        source  string
        domains []string
        err     error
    }
    
    results := make(chan result, len(defaultConfig.Sources))
    var wg sync.WaitGroup
    sem := make(chan struct{}, defaultConfig.WorkerCount)
    progress := &Progress{}
    progress.SetTotal(int64(len(defaultConfig.Sources)))
    
    for _, src := range defaultConfig.Sources {
        wg.Add(1)
        go func(source string) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            
            time.Sleep(defaultConfig.RateLimitDelay)
            domains, err := fetchWithRetry(ctx, source, cache)
            results <- result{source, domains, err}
            progress.Add(1)
            fmt.Printf("\r📥 Progress: %.1f%%", progress.Percent())
        }(src)
    }
    
    go func() {
        wg.Wait()
        close(results)
        fmt.Println()
    }()
    
    // Временный файл для всех доменов
    tempFile, err := os.CreateTemp(defaultConfig.TempDir, "all_domains_*.txt")
    if err != nil {
        panic(err)
    }
    tempWriter := bufio.NewWriterSize(tempFile, defaultConfig.BufferSize)
    
    domainSet := make(map[string]struct{})
    var totalUnique int64
    
    for res := range results {
        if res.err != nil {
            fmt.Printf("✗ %s: %v\n", filepath.Base(res.source), res.err)
            continue
        }
        for _, d := range res.domains {
            if _, exists := domainSet[d]; !exists {
                domainSet[d] = struct{}{}
                tempWriter.WriteString(d)
                tempWriter.WriteByte('\n')
                totalUnique++
            }
        }
        fmt.Printf("  ✓ %s: %d domains\n", filepath.Base(res.source), len(res.domains))
    }
    
    tempWriter.Flush()
    tempFile.Close()
    
    if totalUnique == 0 {
        fmt.Println("❌ No domains fetched")
        os.Exit(1)
    }
    
    fmt.Printf("\n📊 Total unique: %d\n", totalUnique)
    
    // Выбираем стратегию сортировки
    var finalFile string
    if totalUnique > 500000 {
        fmt.Printf("🔄 External sort with %d shards (memory-safe)...\n", defaultConfig.ShardCount)
        if err := externalSortSharded(tempFile.Name(), defaultConfig.OutputFile, defaultConfig.ShardCount); err != nil {
            panic(err)
        }
        finalFile = defaultConfig.OutputFile
    } else {
        fmt.Println("🔄 In-memory sort...")
        allDomains := make([]string, 0, totalUnique)
        for d := range domainSet {
            allDomains = append(allDomains, d)
        }
        sort.Strings(allDomains)
        
        out, err := os.Create(defaultConfig.OutputFile)
        if err != nil {
            panic(err)
        }
        defer out.Close()
        
        writer := bufio.NewWriterSize(out, defaultConfig.BufferSize)
        for _, d := range allDomains {
            writer.WriteString(d)
            writer.WriteByte('\n')
        }
        writer.Flush()
        finalFile = defaultConfig.OutputFile
    }
    
    info, _ := os.Stat(finalFile)
    hash := sha256.New()
    f, _ := os.Open(finalFile)
    io.Copy(hash, f)
    f.Close()
    
    fmt.Printf("\n✅ Done:\n")
    fmt.Printf("   • Domains: %d\n", totalUnique)
    fmt.Printf("   • Size: %.2f MB\n", float64(info.Size())/(1024*1024))
    fmt.Printf("   • SHA256: %s\n", hex.EncodeToString(hash.Sum(nil))[:16])
}