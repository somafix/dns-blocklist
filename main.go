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
    ChunkSize        int
}

type DomainSet struct {
    mu    sync.RWMutex
    items map[string]struct{}
}

func NewDomainSet() *DomainSet {
    return &DomainSet{items: make(map[string]struct{})}
}

func (s *DomainSet) Add(domain string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    if _, exists := s.items[domain]; exists {
        return false
    }
    s.items[domain] = struct{}{}
    return true
}

func (s *DomainSet) Size() int {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return len(s.items)
}

func (s *DomainSet) Slice() []string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    result := make([]string, 0, len(s.items))
    for domain := range s.items {
        result = append(result, domain)
    }
    return result
}

type CacheEntry struct {
    Domains   []string
    Timestamp time.Time
    ETag      string
}

type DiskCache struct {
    dir string
    ttl time.Duration
    mu  sync.Mutex
}

func NewDiskCache(dir string, ttl time.Duration) (*DiskCache, error) {
    if err := os.MkdirAll(dir, 0700); err != nil {
        return nil, fmt.Errorf("create cache dir: %w", err)
    }
    return &DiskCache{dir: dir, ttl: ttl}, nil
}

func (c *DiskCache) keyPath(key string) string {
    hash := sha256.Sum256([]byte(key))
    return filepath.Join(c.dir, hex.EncodeToString(hash[:])+".gob")
}

func (c *DiskCache) Get(key string) (*CacheEntry, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    path := c.keyPath(key)
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var entry CacheEntry
    if err := gob.NewDecoder(f).Decode(&entry); err != nil {
        return nil, err
    }

    if time.Since(entry.Timestamp) > c.ttl {
        os.Remove(path)
        return nil, fmt.Errorf("cache expired")
    }

    return &entry, nil
}

func (c *DiskCache) Set(key string, entry *CacheEntry) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    path := c.keyPath(key)
    f, err := os.Create(path)
    if err != nil {
        return err
    }
    defer f.Close()

    return gob.NewEncoder(f).Encode(entry)
}

type domainHeap struct {
    items []string
}

func (h domainHeap) Len() int           { return len(h.items) }
func (h domainHeap) Less(i, j int) bool { return h.items[i] < h.items[j] }
func (h domainHeap) Swap(i, j int)      { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *domainHeap) Push(x interface{}) { h.items = append(h.items, x.(string)) }
func (h *domainHeap) Pop() interface{} {
    old := h.items
    n := len(old)
    item := old[n-1]
    h.items = old[:n-1]
    return item
}

type FetchResult struct {
    Source  string
    Domains []string
    Err     error
}

type Fetcher struct {
    config Config
    cache  *DiskCache
    client *http.Client
}

func NewFetcher(config Config, cache *DiskCache) *Fetcher {
    return &Fetcher{
        config: config,
        cache:  cache,
        client: &http.Client{
            Timeout: config.RequestTimeout,
            Transport: &http.Transport{
                MaxIdleConns:    100,
                IdleConnTimeout: 90 * time.Second,
            },
        },
    }
}

func (f *Fetcher) Fetch(ctx context.Context, sourceURL string) ([]string, error) {
    if f.config.EnableCache && f.cache != nil {
        if entry, err := f.cache.Get(sourceURL); err == nil {
            return entry.Domains, nil
        }
    }

    var lastErr error
    for attempt := 0; attempt <= f.config.MaxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return nil, ctx.Err()
            default:
            }

            backoff := f.config.RetryBackoffBase * time.Duration(attempt*attempt)
            timer := time.NewTimer(backoff)
            select {
            case <-ctx.Done():
                timer.Stop()
                return nil, ctx.Err()
            case <-timer.C:
            }
        }

        domains, etag, err := f.fetchSource(ctx, sourceURL)
        if err == nil {
            if f.config.EnableCache && f.cache != nil {
                f.cache.Set(sourceURL, &CacheEntry{
                    Domains:   domains,
                    Timestamp: time.Now(),
                    ETag:      etag,
                })
            }
            return domains, nil
        }
        lastErr = err
    }

    return nil, fmt.Errorf("failed after %d retries: %w", f.config.MaxRetries, lastErr)
}

func (f *Fetcher) fetchSource(ctx context.Context, sourceURL string) ([]string, string, error) {
    parsedURL, err := url.Parse(sourceURL)
    if err != nil {
        return nil, "", err
    }

    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        return nil, "", fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
    }

    req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
    if err != nil {
        return nil, "", err
    }

    req.Header.Set("User-Agent", "blocklist-generator/5.0")
    if f.config.EnableGZIP {
        req.Header.Set("Accept-Encoding", "gzip")
    }

    resp, err := f.client.Do(req)
    if err != nil {
        return nil, "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, "", fmt.Errorf("HTTP %d", resp.StatusCode)
    }

    reader := io.Reader(resp.Body)
    if f.config.EnableGZIP && resp.Header.Get("Content-Encoding") == "gzip" {
        gzReader, err := gzip.NewReader(resp.Body)
        if err != nil {
            return nil, "", err
        }
        defer gzReader.Close()
        reader = gzReader
    }

    limited := io.LimitReader(reader, f.config.MaxResponseSize)
    scanner := bufio.NewScanner(limited)
    buf := make([]byte, f.config.BufferSize)
    scanner.Buffer(buf, f.config.BufferSize)

    domains := make([]string, 0, 10000)
    seen := make(map[string]struct{})

    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return domains, "", ctx.Err()
        default:
        }

        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }

        domain := extractDomain(line)
        if domain == "" {
            continue
        }

        if !isValidDomain(domain, f.config.MaxDomainLength) {
            continue
        }

        if _, exists := seen[domain]; !exists {
            seen[domain] = struct{}{}
            domains = append(domains, domain)
        }
    }

    if err := scanner.Err(); err != nil {
        return domains, "", err
    }

    return domains, resp.Header.Get("ETag"), nil
}

func extractDomain(line string) string {
    fields := strings.Fields(line)
    if len(fields) == 0 {
        return ""
    }

    var domain string
    if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
        domain = fields[1]
    } else if len(fields) == 1 && strings.Contains(fields[0], ".") {
        domain = fields[0]
    } else {
        return ""
    }

    domain = strings.ToLower(strings.TrimSuffix(domain, "."))
    if strings.Contains(domain, "..") {
        return ""
    }

    return domain
}

func isValidDomain(domain string, maxLen int) bool {
    if len(domain) == 0 || len(domain) > maxLen {
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

    domainRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
    return domainRegex.MatchString(domain)
}

type Sorter struct {
    config Config
}

func NewSorter(config Config) *Sorter {
    return &Sorter{config: config}
}

func (s *Sorter) Sort(domains []string, outputPath string) error {
    if len(domains) == 0 {
        return fmt.Errorf("no domains to sort")
    }

    if len(domains) > 500000 {
        return s.externalSort(domains, outputPath)
    }

    return s.inMemorySort(domains, outputPath)
}

func (s *Sorter) inMemorySort(domains []string, outputPath string) error {
    sort.Strings(domains)

    out, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer out.Close()

    writer := bufio.NewWriterSize(out, s.config.BufferSize)
    defer writer.Flush()

    var last string
    for _, domain := range domains {
        if domain != last {
            if _, err := writer.WriteString(domain); err != nil {
                return err
            }
            if err := writer.WriteByte('\n'); err != nil {
                return err
            }
            last = domain
        }
    }

    return nil
}

func (s *Sorter) externalSort(domains []string, outputPath string) error {
    tempDir, err := os.MkdirTemp("", "sort_*")
    if err != nil {
        return err
    }
    defer os.RemoveAll(tempDir)

    shards := make([]string, s.config.ShardCount)
    shardWriters := make([]*bufio.Writer, s.config.ShardCount)
    shardFiles := make([]*os.File, s.config.ShardCount)

    for i := 0; i < s.config.ShardCount; i++ {
        f, err := os.CreateTemp(tempDir, fmt.Sprintf("shard_%d_*.tmp", i))
        if err != nil {
            return err
        }
        shardFiles[i] = f
        shards[i] = f.Name()
        shardWriters[i] = bufio.NewWriterSize(f, s.config.BufferSize)
    }

    for _, domain := range domains {
        hash := sha256.Sum256([]byte(domain))
        idx := int(hash[0]) % s.config.ShardCount
        shardWriters[idx].WriteString(domain)
        shardWriters[idx].WriteByte('\n')
    }

    for i := 0; i < s.config.ShardCount; i++ {
        shardWriters[i].Flush()
        shardFiles[i].Close()
    }

    sortedShards := make([]string, s.config.ShardCount)
    var wg sync.WaitGroup
    errChan := make(chan error, s.config.ShardCount)

    for i := 0; i < s.config.ShardCount; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            sorted, err := s.sortShard(shards[idx], tempDir, idx)
            if err != nil {
                errChan <- err
                return
            }
            sortedShards[idx] = sorted
        }(i)
    }

    wg.Wait()
    close(errChan)

    for err := range errChan {
        if err != nil {
            return err
        }
    }

    return s.mergeShards(sortedShards, outputPath)
}

func (s *Sorter) sortShard(inputPath, tempDir string, shardIdx int) (string, error) {
    f, err := os.Open(inputPath)
    if err != nil {
        return "", err
    }
    defer f.Close()
    defer os.Remove(inputPath)

    chunks := make([][]string, 0)
    scanner := bufio.NewScanner(f)
    chunk := make([]string, 0, s.config.ChunkSize)

    for scanner.Scan() {
        domain := scanner.Text()
        if domain == "" {
            continue
        }
        chunk = append(chunk, domain)

        if len(chunk) >= s.config.ChunkSize {
            sort.Strings(chunk)
            chunks = append(chunks, chunk)
            chunk = make([]string, 0, s.config.ChunkSize)
        }
    }

    if len(chunk) > 0 {
        sort.Strings(chunk)
        chunks = append(chunks, chunk)
    }

    if len(chunks) == 0 {
        outputPath := filepath.Join(tempDir, fmt.Sprintf("empty_%d.tmp", shardIdx))
        if err := os.WriteFile(outputPath, []byte{}, 0644); err != nil {
            return "", err
        }
        return outputPath, nil
    }

    if len(chunks) == 1 {
        outputPath := filepath.Join(tempDir, fmt.Sprintf("sorted_%d.tmp", shardIdx))
        data := strings.Join(chunks[0], "\n")
        if err := os.WriteFile(outputPath, []byte(data), 0644); err != nil {
            return "", err
        }
        return outputPath, nil
    }

    outputPath := filepath.Join(tempDir, fmt.Sprintf("sorted_%d.tmp", shardIdx))
    out, err := os.Create(outputPath)
    if err != nil {
        return "", err
    }
    defer out.Close()

    writer := bufio.NewWriterSize(out, s.config.BufferSize)
    defer writer.Flush()

    h := &domainHeap{}
    indices := make([]int, len(chunks))

    for i, c := range chunks {
        if len(c) > 0 {
            heap.Push(h, c[0])
            indices[i] = 1
        }
    }

    var last string
    for h.Len() > 0 {
        current := heap.Pop(h).(string)

        if current != last {
            writer.WriteString(current)
            writer.WriteByte('\n')
            last = current
        }

        for i := 0; i < len(chunks); i++ {
            if indices[i] < len(chunks[i]) && chunks[i][indices[i]-1] == current {
                if indices[i] < len(chunks[i]) {
                    heap.Push(h, chunks[i][indices[i]])
                    indices[i]++
                }
                break
            }
        }
    }

    return outputPath, nil
}

func (s *Sorter) mergeShards(shardPaths []string, outputPath string) error {
    validPaths := make([]string, 0)
    for _, path := range shardPaths {
        info, err := os.Stat(path)
        if err == nil && info.Size() > 0 {
            validPaths = append(validPaths, path)
        }
    }

    if len(validPaths) == 0 {
        return fmt.Errorf("no data to merge")
    }

    files := make([]*os.File, len(validPaths))
    scanners := make([]*bufio.Scanner, len(validPaths))

    for i, path := range validPaths {
        f, err := os.Open(path)
        if err != nil {
            return err
        }
        files[i] = f
        scanners[i] = bufio.NewScanner(f)
    }

    defer func() {
        for _, f := range files {
            if f != nil {
                f.Close()
            }
        }
        for _, path := range validPaths {
            os.Remove(path)
        }
    }()

    out, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer out.Close()

    writer := bufio.NewWriterSize(out, s.config.BufferSize)
    defer writer.Flush()

    h := &domainHeap{}
    for i, scanner := range scanners {
        if scanner.Scan() {
            heap.Push(h, struct {
                domain string
                idx    int
            }{scanner.Text(), i})
        }
    }

    var last string
    for h.Len() > 0 {
        item := heap.Pop(h).(struct {
            domain string
            idx    int
        })

        if item.domain != last {
            writer.WriteString(item.domain)
            writer.WriteByte('\n')
            last = item.domain
        }

        if scanners[item.idx].Scan() {
            heap.Push(h, struct {
                domain string
                idx    int
            }{scanners[item.idx].Text(), item.idx})
        }
    }

    return nil
}

type ProgressTracker struct {
    total     int64
    completed int64
}

func (p *ProgressTracker) SetTotal(n int64) {
    atomic.StoreInt64(&p.total, n)
}

func (p *ProgressTracker) Add(n int64) {
    atomic.AddInt64(&p.completed, n)
}

func (p *ProgressTracker) Percent() float64 {
    total := atomic.LoadInt64(&p.total)
    completed := atomic.LoadInt64(&p.completed)
    if total == 0 {
        return 0
    }
    return float64(completed) / float64(total) * 100
}

func printMemStats() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    fmt.Printf("  💾 Memory: %.2f MB allocated, %.2f MB system\n",
        float64(m.Alloc)/1024/1024,
        float64(m.Sys)/1024/1024)
}

func run() error {
    config := Config{
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
        ChunkSize:        500000,
    }

    if config.TempDir == "" {
        tempDir, err := os.MkdirTemp("", "blocklist_*")
        if err != nil {
            return err
        }
        config.TempDir = tempDir
    }

    if err := os.MkdirAll(config.TempDir, 0700); err != nil {
        return err
    }
    defer os.RemoveAll(config.TempDir)

    var cache *DiskCache
    if config.EnableCache {
        cache, _ = NewDiskCache(filepath.Join(config.TempDir, "cache"), config.CacheTTL)
    }

    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    ctx, cancel = context.WithTimeout(ctx, config.TotalTimeout)
    defer cancel()

    fmt.Println("🚀 Blocklist Generator v5.0")

    fetcher := NewFetcher(config, cache)
    results := make(chan FetchResult, len(config.Sources))

    var wg sync.WaitGroup
    sem := make(chan struct{}, config.WorkerCount)
    progress := &ProgressTracker{}
    progress.SetTotal(int64(len(config.Sources)))

    for _, src := range config.Sources {
        wg.Add(1)
        go func(source string) {
            defer wg.Done()

            select {
            case sem <- struct{}{}:
                defer func() { <-sem }()
            case <-ctx.Done():
                results <- FetchResult{Source: source, Err: ctx.Err()}
                return
            }

            timer := time.NewTimer(config.RateLimitDelay)
            select {
            case <-timer.C:
            case <-ctx.Done():
                timer.Stop()
                results <- FetchResult{Source: source, Err: ctx.Err()}
                return
            }

            domains, err := fetcher.Fetch(ctx, source)
            results <- FetchResult{Source: source, Domains: domains, Err: err}
            progress.Add(1)
            fmt.Printf("\r📥 Progress: %.1f%%", progress.Percent())
        }(src)
    }

    go func() {
        wg.Wait()
        close(results)
        fmt.Println()
    }()

    tempFile, err := os.CreateTemp(config.TempDir, "domains_*.txt")
    if err != nil {
        return err
    }
    defer tempFile.Close()
    defer os.Remove(tempFile.Name())

    writer := bufio.NewWriterSize(tempFile, config.BufferSize)
    domainSet := NewDomainSet()

    for res := range results {
        if res.Err != nil {
            fmt.Printf("✗ %s: %v\n", filepath.Base(res.Source), res.Err)
            continue
        }

        added := 0
        for _, domain := range res.Domains {
            if domainSet.Add(domain) {
                writer.WriteString(domain)
                writer.WriteByte('\n')
                added++
            }
        }
        fmt.Printf("  ✓ %s: %d domains (%d new)\n", filepath.Base(res.Source), len(res.Domains), added)
    }

    if err := writer.Flush(); err != nil {
        return err
    }

    totalUnique := domainSet.Size()
    if totalUnique == 0 {
        return fmt.Errorf("no domains fetched")
    }

    fmt.Printf("\n📊 Total unique: %d\n", totalUnique)
    printMemStats()

    sorter := NewSorter(config)
    if err := sorter.Sort(domainSet.Slice(), config.OutputFile); err != nil {
        return err
    }

    info, err := os.Stat(config.OutputFile)
    if err != nil {
        return err
    }

    f, err := os.Open(config.OutputFile)
    if err != nil {
        return err
    }
    defer f.Close()

    hash := sha256.New()
    if _, err := io.Copy(hash, f); err != nil {
        return err
    }

    fmt.Printf("\n✅ Done\n")
    fmt.Printf("   • Domains: %d\n", totalUnique)
    fmt.Printf("   • Size: %.2f MB\n", float64(info.Size())/(1024*1024))
    fmt.Printf("   • SHA256: %s\n", hex.EncodeToString(hash.Sum(nil))[:16])
    printMemStats()

    return nil
}

func main() {
    start := time.Now()
    if err := run(); err != nil {
        fmt.Fprintf(os.Stderr, "❌ Error: %v\n", err)
        os.Exit(1)
    }
    fmt.Printf("\n⏱️  Time: %v\n", time.Since(start).Round(time.Millisecond))
}