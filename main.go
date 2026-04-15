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
    "runtime"
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
    ChunkSize        int // Для потоковой сортировки
}

var defaultConfig = Config{
    Sources: []string{
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://someonewhocares.org/hosts/zero/hosts",
        "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
    },
    OutputFile:       "blocklist.txt",
    TempDir:          "",
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
    ShardCount:       100,
    ChunkSize:        500_000,
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

// Исправленная реализация heap.Interface (все методы на указателе)
type domainItem struct {
    domain string
    idx    int
}

type DomainHeap struct {
    items []domainItem
}

func (h *DomainHeap) Len() int           { return len(h.items) }
func (h *DomainHeap) Less(i, j int) bool { return h.items[i].domain < h.items[j].domain }
func (h *DomainHeap) Swap(i, j int)      { h.items[i], h.items[j] = h.items[j], h.items[i] }

func (h *DomainHeap) Push(x interface{}) {
    h.items = append(h.items, x.(domainItem))
}

func (h *DomainHeap) Pop() interface{} {
    old := h.items
    n := len(old)
    item := old[n-1]
    h.items = old[:n-1]
    return item
}

// Безопасное множество для concurrent доступа
type SafeSet struct {
    mu  sync.RWMutex
    set map[string]struct{}
}

func NewSafeSet() *SafeSet {
    return &SafeSet{
        set: make(map[string]struct{}),
    }
}

func (s *SafeSet) Add(key string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, ok := s.set[key]; ok {
        return false
    }
    s.set[key] = struct{}{}
    return true
}

func (s *SafeSet) Len() int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return len(s.set)
}

func (s *SafeSet) ToSlice() []string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    result := make([]string, 0, len(s.set))
    for k := range s.set {
        result = append(result, k)
    }
    return result
}

// Потоковая внешняя сортировка через шардирование
func externalSortSharded(inputFile, outputFile string, shardCount, chunkSize int) error {
    tempDir, err := os.MkdirTemp("", "shards_*")
    if err != nil {
        return err
    }
    defer os.RemoveAll(tempDir)

    // Шаг 1: Распределение по шардам
    shardWriters := make([]*bufio.Writer, shardCount)
    shardFiles := make([]*os.File, shardCount)
    shardPaths := make([]string, shardCount)

    for i := 0; i < shardCount; i++ {
        f, err := os.CreateTemp(tempDir, fmt.Sprintf("shard_%d_*.tmp", i))
        if err != nil {
            return err
        }
        shardFiles[i] = f
        shardPaths[i] = f.Name()
        shardWriters[i] = bufio.NewWriterSize(f, defaultConfig.BufferSize)
    }

    input, err := os.Open(inputFile)
    if err != nil {
        return err
    }
    defer input.Close()
    defer os.Remove(inputFile)

    scanner := bufio.NewScanner(input)
    for scanner.Scan() {
        domain := scanner.Text()
        if domain == "" {
            continue
        }
        hash := sha256.Sum256([]byte(domain))
        shardIdx := int(hash[0]) % shardCount
        shardWriters[shardIdx].WriteString(domain)
        shardWriters[shardIdx].WriteByte('\n')
    }

    for i := 0; i < shardCount; i++ {
        shardWriters[i].Flush()
        shardFiles[i].Close()
    }

    // Шаг 2: Потоковая сортировка каждого шарда
    var wg sync.WaitGroup
    errCh := make(chan error, shardCount)
    sortedPaths := make([]string, shardCount)

    for i := 0; i < shardCount; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            sortedPath, err := sortShardStreaming(shardPaths[idx], tempDir, idx, chunkSize)
            if err != nil {
                errCh <- err
                return
            }
            sortedPaths[idx] = sortedPath
            os.Remove(shardPaths[idx])
        }(i)
    }

    wg.Wait()
    close(errCh)

    if err := <-errCh; err != nil {
        return err
    }

    // Шаг 3: Multi-way merge через heap
    return mergeShards(sortedPaths, outputFile, tempDir)
}

// Потоковая сортировка шарда чанками
func sortShardStreaming(inputPath, tempDir string, shardIdx, chunkSize int) (string, error) {
    f, err := os.Open(inputPath)
    if err != nil {
        return "", err
    }
    defer f.Close()

    var chunks [][]string
    scanner := bufio.NewScanner(f)
    chunk := make([]string, 0, chunkSize)
    lineCount := 0

    for scanner.Scan() {
        line := scanner.Text()
        if line == "" {
            continue
        }
        chunk = append(chunk, line)
        lineCount++

        if len(chunk) >= chunkSize {
            sort.Strings(chunk)
            chunks = append(chunks, chunk)
            chunk = make([]string, 0, chunkSize)
        }
    }

    if len(chunk) > 0 {
        sort.Strings(chunk)
        chunks = append(chunks, chunk)
    }

    if len(chunks) == 0 {
        // Пустой шард
        emptyPath := filepath.Join(tempDir, fmt.Sprintf("empty_%d.tmp", shardIdx))
        return emptyPath, os.WriteFile(emptyPath, []byte{}, 0644)
    }

    // Если только один чанк - сразу пишем
    if len(chunks) == 1 {
        outputPath := filepath.Join(tempDir, fmt.Sprintf("sorted_%d.tmp", shardIdx))
        data := strings.Join(chunks[0], "\n")
        if err := os.WriteFile(outputPath, []byte(data), 0644); err != nil {
            return "", err
        }
        return outputPath, nil
    }

    // Иначе merge чанков через heap
    outputPath := filepath.Join(tempDir, fmt.Sprintf("sorted_%d.tmp", shardIdx))
    out, err := os.Create(outputPath)
    if err != nil {
        return "", err
    }
    defer out.Close()

    writer := bufio.NewWriterSize(out, defaultConfig.BufferSize)

    h := &DomainHeap{items: make([]domainItem, 0, len(chunks))}
    indices := make([]int, len(chunks))

    for i, c := range chunks {
        if len(c) > 0 {
            heap.Push(h, domainItem{domain: c[0], idx: i})
            indices[i] = 1
        }
    }

    var lastDomain string
    for h.Len() > 0 {
        item := heap.Pop(h).(domainItem)

        if item.domain != lastDomain {
            writer.WriteString(item.domain)
            writer.WriteByte('\n')
            lastDomain = item.domain
        }

        if indices[item.idx] < len(chunks[item.idx]) {
            nextDomain := chunks[item.idx][indices[item.idx]]
            heap.Push(h, domainItem{domain: nextDomain, idx: item.idx})
            indices[item.idx]++
        }
    }

    if err := writer.Flush(); err != nil {
        return "", err
    }

    return outputPath, nil
}

// Merge отсортированных шардов
func mergeShards(sortedPaths []string, outputFile, tempDir string) error {
    validPaths := make([]string, 0)
    for _, p := range sortedPaths {
        info, err := os.Stat(p)
        if err == nil && info.Size() > 0 {
            validPaths = append(validPaths, p)
        }
    }

    if len(validPaths) == 0 {
        return fmt.Errorf("no data to merge")
    }

    readers := make([]*bufio.Scanner, len(validPaths))
    files := make([]*os.File, len(validPaths))

    for i, p := range validPaths {
        f, err := os.Open(p)
        if err != nil {
            return err
        }
        files[i] = f
        readers[i] = bufio.NewScanner(f)
    }

    defer func() {
        for _, f := range files {
            if f != nil {
                f.Close()
            }
        }
        for _, p := range validPaths {
            os.Remove(p)
        }
    }()

    out, err := os.Create(outputFile)
    if err != nil {
        return err
    }
    defer out.Close()

    writer := bufio.NewWriterSize(out, defaultConfig.BufferSize)
    h := &DomainHeap{items: make([]domainItem, 0, len(validPaths))}

    for i, r := range readers {
        if r.Scan() {
            heap.Push(h, domainItem{domain: r.Text(), idx: i})
        }
    }

    var lastDomain string
    for h.Len() > 0 {
        item := heap.Pop(h).(domainItem)

        if item.domain != lastDomain {
            writer.WriteString(item.domain)
            writer.WriteByte('\n')
            lastDomain = item.domain
        }

        if readers[item.idx].Scan() {
            heap.Push(h, domainItem{domain: readers[item.idx].Text(), idx: item.idx})
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
    req.Header.Set("User-Agent", "blocklist-fetcher/5.0")
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

    // Исправлено: лимит применяется после gzip
    if defaultConfig.EnableGZIP && resp.Header.Get("Content-Encoding") == "gzip" {
        gzReader, err := gzip.NewReader(resp.Body)
        if err != nil {
            return nil, "", err
        }
        defer gzReader.Close()
        reader = gzReader
    }

    limited := io.LimitReader(reader, defaultConfig.MaxResponseSize)
    scanner := bufio.NewScanner(limited)
    buf := make([]byte, defaultConfig.BufferSize)
    scanner.Buffer(buf, defaultConfig.BufferSize)

    var domains []string
    domainMap := make(map[string]struct{})

    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return domains, etag, ctx.Err()
        default:
        }

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
            select {
            case <-ctx.Done():
                return nil, ctx.Err()
            default:
            }

            backoff := defaultConfig.RetryBackoffBase * time.Duration(attempt*attempt)
            fmt.Printf("  🔄 Retry %d for %s in %v\n", attempt, filepath.Base(sourceURL), backoff)

            timer := time.NewTimer(backoff)
            select {
            case <-ctx.Done():
                timer.Stop()
                return nil, ctx.Err()
            case <-timer.C:
            }
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
    }
    return nil, fmt.Errorf("failed after %d retries: %w", defaultConfig.MaxRetries, lastErr)
}

func printMemStats() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    fmt.Printf("  💾 Memory: %.2f MB allocated, %.2f MB system\n",
        float64(m.Alloc)/1024/1024,
        float64(m.Sys)/1024/1024)
}

func main() {
    startTime := time.Now()

    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    ctx, cancel = context.WithTimeout(ctx, defaultConfig.TotalTimeout)
    defer cancel()

    fmt.Println("🚀 Blocklist Generator v5.0 - Production Ready")

    if defaultConfig.TempDir == "" {
        defaultConfig.TempDir, _ = os.MkdirTemp("", "blocklist_*")
    }
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

    // Исправлено: проверка ctx.Done() в воркерах
    for _, src := range defaultConfig.Sources {
        select {
        case <-ctx.Done():
            fmt.Println("\n⚠️  Shutdown signal received")
            break
        default:
        }

        wg.Add(1)
        go func(source string) {
            defer wg.Done()

            select {
            case sem <- struct{}{}:
                defer func() { <-sem }()
            case <-ctx.Done():
                return
            }

            time.Sleep(defaultConfig.RateLimitDelay)

            fetchCtx, fetchCancel := context.WithTimeout(ctx, defaultConfig.RequestTimeout*2)
            defer fetchCancel()

            domains, err := fetchWithRetry(fetchCtx, source, cache)
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

    tempFile, err := os.CreateTemp(defaultConfig.TempDir, "all_domains_*.txt")
    if err != nil {
        panic(err)
    }
    tempPath := tempFile.Name()
    tempWriter := bufio.NewWriterSize(tempFile, defaultConfig.BufferSize)

    domainSet := NewSafeSet()

    for res := range results {
        if res.err != nil {
            fmt.Printf("✗ %s: %v\n", filepath.Base(res.source), res.err)
            continue
        }

        added := 0
        for _, d := range res.domains {
            if domainSet.Add(d) {
                tempWriter.WriteString(d)
                tempWriter.WriteByte('\n')
                added++
            }
        }
        fmt.Printf("  ✓ %s: %d domains (%d new)\n", filepath.Base(res.source), len(res.domains), added)
    }

    tempWriter.Flush()
    tempFile.Close()

    totalUnique := domainSet.Len()
    if totalUnique == 0 {
        fmt.Println("❌ No domains fetched")
        os.Exit(1)
    }

    fmt.Printf("\n📊 Total unique: %d\n", totalUnique)
    printMemStats()

    // Выбор стратегии сортировки
    if totalUnique > 500_000 {
        fmt.Printf("🔄 External sort with %d shards (chunk size: %d)...\n",
            defaultConfig.ShardCount, defaultConfig.ChunkSize)

        if err := externalSortSharded(tempPath, defaultConfig.OutputFile,
            defaultConfig.ShardCount, defaultConfig.ChunkSize); err != nil {
            panic(err)
        }
    } else {
        fmt.Println("🔄 In-memory sort...")
        allDomains := domainSet.ToSlice()
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
    }

    info, _ := os.Stat(defaultConfig.OutputFile)
    hash := sha256.New()
    f, _ := os.Open(defaultConfig.OutputFile)
    io.Copy(hash, f)
    f.Close()

    elapsed := time.Since(startTime)

    fmt.Printf("\n✅ Done in %v:\n", elapsed.Round(time.Millisecond))
    fmt.Printf("   • Domains: %d\n", totalUnique)
    fmt.Printf("   • Size: %.2f MB\n", float64(info.Size())/(1024*1024))
    fmt.Printf("   • SHA256: %s\n", hex.EncodeToString(hash.Sum(nil))[:16])
    printMemStats()
}
