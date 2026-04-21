package main

import (
    "bufio"
    "compress/gzip"
    "container/heap"
    "context"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
    "encoding/gob"
    "fmt"
    "hash/fnv"
    "io"
    "log/slog"
    "math/rand"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/signal"
    "path/filepath"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"
)

// ============================================================================
// БЛОКЛИСТ ГЕНЕРАТОР v6.1 - БЕЗ ВНЕШНИХ ЗАВИСИМОСТЕЙ
// ============================================================================
// ЗАПУСК:
//   1. Сохраните код как main.go
//   2. go build -o blocklist main.go
//   3. ./blocklist
//
// ИЛИ ПРЯМОЙ ЗАПУСК:
//   go run main.go
// ============================================================================

const (
    defaultBufferSize          = 256 * 1024
    externalSortThreshold      = 500000
    defaultChunkSize           = 500000
    maxDecompressedSize        = 200 * 1024 * 1024
    gracefulShutdownTimeout    = 30 * time.Second
    defaultShardCount          = 100
    defaultMaxResponseSize     = 50 * 1024 * 1024
    defaultMaxDomainLength     = 253
    defaultRequestTimeout      = 30 * time.Second
    defaultTotalTimeout        = 5 * time.Minute
    defaultRateLimitDelay      = 200 * time.Millisecond
    defaultMaxRetries          = 3
    defaultRetryBackoffBase    = 2 * time.Second
    defaultWorkerCount         = 4
    defaultCacheTTL            = 24 * time.Hour
    defaultMaxIdleConns        = 100
    defaultMaxConnsPerHost     = 10
    defaultIdleConnTimeout     = 90 * time.Second
    defaultTempDirPattern      = "blocklist_*"
    defaultSortTempPattern     = "sort_*"
    defaultShardPattern        = "shard_%d_*.tmp"
    defaultSortedShardPattern  = "sorted_%d.tmp"
    maxOpenFilesPerMerge       = 50
)

var (
    domainRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
    ipPattern    = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
    privateIPBlocks []*net.IPNet
)

func init() {
    // Private IP ranges для защиты от SSRF
    for _, cidr := range []string{
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    } {
        _, block, _ := net.ParseCIDR(cidr)
        privateIPBlocks = append(privateIPBlocks, block)
    }
}

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
    return filepath.Join(c.dir, hex.EncodeToString(hash[:]) + ".gob")
}

func (c *DiskCache) Get(key string) (*CacheEntry, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    path := c.keyPath(key)
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var entry CacheEntry
    if err := gob.NewDecoder(file).Decode(&entry); err != nil {
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
    file, err := os.Create(path)
    if err != nil {
        return err
    }
    defer file.Close()
    
    if err := os.Chmod(path, 0600); err != nil {
        return err
    }

    return gob.NewEncoder(file).Encode(entry)
}

type mergeItem struct {
    domain string
    source int
}

type mergeHeap []mergeItem

func (h mergeHeap) Len() int           { return len(h) }
func (h mergeHeap) Less(i, j int) bool { return h[i].domain < h[j].domain }
func (h mergeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(x interface{}) { *h = append(*h, x.(mergeItem)) }
func (h *mergeHeap) Pop() interface{} {
    old := *h
    n := len(old)
    item := old[n-1]
    *h = old[:n-1]
    return item
}

type sortedChunk struct {
    items   []string
    indices []int
}

type chunkHeap []sortedChunk

func (h chunkHeap) Len() int { return len(h) }
func (h chunkHeap) Less(i, j int) bool {
    if len(h[i].items) == 0 || len(h[i].indices) == 0 || h[i].indices[0] >= len(h[i].items) {
        return false
    }
    if len(h[j].items) == 0 || len(h[j].indices) == 0 || h[j].indices[0] >= len(h[j].items) {
        return true
    }
    return h[i].items[h[i].indices[0]] < h[j].items[h[j].indices[0]]
}
func (h chunkHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *chunkHeap) Push(x interface{}) { *h = append(*h, x.(sortedChunk)) }
func (h *chunkHeap) Pop() interface{} {
    old := *h
    n := len(old)
    item := old[n-1]
    *h = old[:n-1]
    return item
}

type FetchResult struct {
    Source  string
    Domains []string
    Err     error
}

type Fetcher struct {
    config  Config
    cache   *DiskCache
    client  *http.Client
    logger  *slog.Logger
    metrics Metrics
}

type Metrics interface {
    RecordDuration(name string, duration time.Duration, labels ...string)
    RecordCounter(name string, value int64, labels ...string)
    RecordGauge(name string, value int64, labels ...string)
}

type noopMetrics struct{}

func (noopMetrics) RecordDuration(string, time.Duration, ...string) {}
func (noopMetrics) RecordCounter(string, int64, ...string)          {}
func (noopMetrics) RecordGauge(string, int64, ...string)            {}

func NewFetcher(config Config, cache *DiskCache, logger *slog.Logger, metrics Metrics) *Fetcher {
    if metrics == nil {
        metrics = noopMetrics{}
    }
    
    transport := &http.Transport{
        MaxIdleConns:        defaultMaxIdleConns,
        MaxConnsPerHost:     defaultMaxConnsPerHost,
        MaxIdleConnsPerHost: defaultMaxConnsPerHost / 2,
        IdleConnTimeout:     defaultIdleConnTimeout,
        TLSClientConfig: &tls.Config{
            MinVersion: tls.VersionTLS12,
        },
    }
    
    client := &http.Client{
        Timeout:   config.RequestTimeout,
        Transport: transport,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 10 {
                return fmt.Errorf("too many redirects")
            }
            if err := isSafeURL(req.URL.String()); err != nil {
                return err
            }
            return nil
        },
    }
    
    return &Fetcher{
        config:  config,
        cache:   cache,
        logger:  logger,
        metrics: metrics,
        client:  client,
    }
}

func isSafeURL(rawURL string) error {
    parsed, err := url.Parse(rawURL)
    if err != nil {
        return err
    }
    
    if parsed.Scheme != "http" && parsed.Scheme != "https" {
        return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
    }
    
    host := parsed.Hostname()
    ips, err := net.LookupIP(host)
    if err != nil {
        return fmt.Errorf("failed to resolve host: %w", err)
    }
    
    for _, ip := range ips {
        for _, block := range privateIPBlocks {
            if block.Contains(ip) {
                return fmt.Errorf("private IP address not allowed: %s", ip)
            }
        }
    }
    
    return nil
}

func normalizeDomain(domain string) (string, error) {
    domain = strings.ToLower(strings.TrimSuffix(domain, "."))
    
    // Проверка на не-ASCII символы (IDN protection)
    for _, r := range domain {
        if r > 127 {
            return "", fmt.Errorf("non-ASCII domain rejected: %s", domain)
        }
    }
    
    // Защита от path traversal
    if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
        return "", fmt.Errorf("invalid domain path: %s", domain)
    }
    
    return domain, nil
}

func (f *Fetcher) Fetch(ctx context.Context, sourceURL string) ([]string, error) {
    if err := isSafeURL(sourceURL); err != nil {
        return nil, err
    }

    if f.config.EnableCache && f.cache != nil {
        if entry, err := f.cache.Get(sourceURL); err == nil {
            f.logger.DebugContext(ctx, "cache hit", "url", sourceURL)
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
            jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
            backoff += jitter

            timer := time.NewTimer(backoff)
            select {
            case <-ctx.Done():
                timer.Stop()
                return nil, ctx.Err()
            case <-timer.C:
            }
        }

        start := time.Now()
        domains, etag, err := f.fetchSource(ctx, sourceURL)
        f.metrics.RecordDuration("fetch", time.Since(start), "url", sourceURL)

        if err == nil {
            if f.config.EnableCache && f.cache != nil {
                if err := f.cache.Set(sourceURL, &CacheEntry{
                    Domains:   domains,
                    Timestamp: time.Now(),
                    ETag:      etag,
                }); err != nil {
                    f.logger.ErrorContext(ctx, "failed to cache", "error", err, "url", sourceURL)
                }
            }
            f.metrics.RecordCounter("fetch_success", 1, "url", sourceURL)
            f.metrics.RecordGauge("domains_fetched", int64(len(domains)), "url", sourceURL)
            return domains, nil
        }

        lastErr = err
        f.metrics.RecordCounter("fetch_errors", 1, "url", sourceURL, "attempt", strconv.Itoa(attempt))
        f.logger.ErrorContext(ctx, "fetch attempt failed", "error", err, "url", sourceURL, "attempt", attempt)
    }

    return nil, fmt.Errorf("failed after %d retries: %w", f.config.MaxRetries, lastErr)
}

func (f *Fetcher) fetchSource(ctx context.Context, sourceURL string) ([]string, string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
    if err != nil {
        return nil, "", err
    }

    req.Header.Set("User-Agent", "blocklist-generator/6.1")
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

    var reader io.Reader
    reader = io.LimitReader(resp.Body, f.config.MaxResponseSize)
    
    if f.config.EnableGZIP && resp.Header.Get("Content-Encoding") == "gzip" {
        gzReader, err := gzip.NewReader(reader)
        if err != nil {
            return nil, "", err
        }
        defer gzReader.Close()
        reader = io.LimitReader(gzReader, maxDecompressedSize)
    }

    scanner := bufio.NewScanner(reader)
    buffer := make([]byte, f.config.BufferSize)
    scanner.Buffer(buffer, f.config.BufferSize)

    domains := make([]string, 0, 10000)
    seen := make(map[string]struct{}, 10000)

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

        normalized, err := normalizeDomain(domain)
        if err != nil {
            continue
        }

        if !isValidDomain(normalized, f.config.MaxDomainLength) {
            continue
        }

        if _, exists := seen[normalized]; !exists {
            seen[normalized] = struct{}{}
            domains = append(domains, normalized)
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
    } else if len(fields) == 1 && strings.Contains(fields[0], ".") && !ipPattern.MatchString(fields[0]) {
        domain = fields[0]
    } else {
        return ""
    }

    domain = strings.TrimSuffix(domain, ".")
    
    if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
        return ""
    }

    return domain
}

func isValidDomain(domain string, maxLength int) bool {
    if len(domain) == 0 || len(domain) > maxLength {
        return false
    }

    if strings.ContainsAny(domain, "*\\/:?&=@#$%^`|~") {
        return false
    }

    if strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".localhost") {
        return false
    }

    if ipPattern.MatchString(domain) {
        return false
    }

    return domainRegexp.MatchString(domain)
}

type Sorter struct {
    config  Config
    logger  *slog.Logger
    metrics Metrics
    ctx     context.Context
}

func NewSorter(config Config, logger *slog.Logger, metrics Metrics) *Sorter {
    if metrics == nil {
        metrics = noopMetrics{}
    }
    return &Sorter{config: config, logger: logger, metrics: metrics}
}

func (s *Sorter) Sort(ctx context.Context, domains []string, outputPath string) error {
    s.ctx = ctx
    if len(domains) == 0 {
        return fmt.Errorf("no domains to sort")
    }

    start := time.Now()
    defer func() {
        s.metrics.RecordDuration("sort", time.Since(start), "domains", strconv.Itoa(len(domains)))
    }()

    if len(domains) > externalSortThreshold {
        s.logger.DebugContext(ctx, "using external sort", "domains", len(domains))
        return s.externalSort(domains, outputPath)
    }

    return s.inMemorySort(domains, outputPath)
}

func (s *Sorter) inMemorySort(domains []string, outputPath string) error {
    sort.Strings(domains)

    outputFile, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    
    if err := os.Chmod(outputPath, 0644); err != nil {
        return err
    }

    writer := bufio.NewWriterSize(outputFile, s.config.BufferSize)
    defer writer.Flush()

    var previousDomain string
    for _, domain := range domains {
        select {
        case <-s.ctx.Done():
            return s.ctx.Err()
        default:
        }
        
        if domain != previousDomain {
            if _, err := writer.WriteString(domain); err != nil {
                return err
            }
            if err := writer.WriteByte('\n'); err != nil {
                return err
            }
            previousDomain = domain
        }
    }

    return nil
}

func (s *Sorter) externalSort(domains []string, outputPath string) error {
    tempDir, err := os.MkdirTemp("", defaultSortTempPattern)
    if err != nil {
        return err
    }
    defer os.RemoveAll(tempDir)

    shardPaths, err := s.writeShards(domains, tempDir)
    if err != nil {
        return err
    }

    sortedShards, err := s.sortShardsConcurrently(shardPaths, tempDir)
    if err != nil {
        return err
    }

    return s.mergeShards(sortedShards, outputPath)
}

func (s *Sorter) writeShards(domains []string, tempDir string) ([]string, error) {
    shardWriters := make([]*bufio.Writer, s.config.ShardCount)
    shardPaths := make([]string, s.config.ShardCount)
    shardFiles := make([]*os.File, s.config.ShardCount)

    for i := 0; i < s.config.ShardCount; i++ {
        file, err := os.CreateTemp(tempDir, fmt.Sprintf(defaultShardPattern, i))
        if err != nil {
            return nil, fmt.Errorf("create shard %d: %w", i, err)
        }
        if err := os.Chmod(file.Name(), 0600); err != nil {
            return nil, err
        }
        shardFiles[i] = file
        shardPaths[i] = file.Name()
        shardWriters[i] = bufio.NewWriterSize(file, s.config.BufferSize)
    }

    for _, domain := range domains {
        select {
        case <-s.ctx.Done():
            return nil, s.ctx.Err()
        default:
        }
        
        hasher := fnv.New32a()
        hasher.Write([]byte(domain))
        shardIdx := int(hasher.Sum32()) % s.config.ShardCount
        if _, err := shardWriters[shardIdx].WriteString(domain); err != nil {
            return nil, err
        }
        if err := shardWriters[shardIdx].WriteByte('\n'); err != nil {
            return nil, err
        }
    }

    for i := 0; i < s.config.ShardCount; i++ {
        if err := shardWriters[i].Flush(); err != nil {
            return nil, err
        }
        if err := shardFiles[i].Close(); err != nil {
            return nil, err
        }
    }

    return shardPaths, nil
}

func (s *Sorter) sortShardsConcurrently(shardPaths []string, tempDir string) ([]string, error) {
    sortedShards := make([]string, s.config.ShardCount)
    errCh := make(chan error, s.config.ShardCount)
    var wg sync.WaitGroup

    for i := 0; i < s.config.ShardCount; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            sortedPath, err := s.sortShard(shardPaths[idx], tempDir, idx)
            if err != nil {
                select {
                case errCh <- err:
                default:
                }
                return
            }
            sortedShards[idx] = sortedPath
        }(i)
    }

    go func() {
        wg.Wait()
        close(errCh)
    }()

    for err := range errCh {
        if err != nil {
            return nil, err
        }
    }

    return sortedShards, nil
}

func (s *Sorter) sortShard(inputPath, tempDir string, shardIdx int) (string, error) {
    inputFile, err := os.Open(inputPath)
    if err != nil {
        return "", err
    }
    defer inputFile.Close()
    defer os.Remove(inputPath)

    chunks, err := s.loadAndSortChunks(inputFile)
    if err != nil {
        return "", err
    }

    if len(chunks) == 0 {
        return s.writeEmptyShard(tempDir, shardIdx)
    }

    if len(chunks) == 1 {
        return s.writeSingleChunk(chunks[0], tempDir, shardIdx)
    }

    return s.mergeChunks(chunks, tempDir, shardIdx)
}

func (s *Sorter) loadAndSortChunks(inputFile *os.File) ([][]string, error) {
    var chunks [][]string
    scanner := bufio.NewScanner(inputFile)
    currentChunk := make([]string, 0, s.config.ChunkSize)

    for scanner.Scan() {
        select {
        case <-s.ctx.Done():
            return nil, s.ctx.Err()
        default:
        }
        
        domain := scanner.Text()
        if domain == "" {
            continue
        }
        currentChunk = append(currentChunk, domain)

        if len(currentChunk) >= s.config.ChunkSize {
            sort.Strings(currentChunk)
            chunks = append(chunks, currentChunk)
            currentChunk = make([]string, 0, s.config.ChunkSize)
        }
    }

    if len(currentChunk) > 0 {
        sort.Strings(currentChunk)
        chunks = append(chunks, currentChunk)
    }

    return chunks, scanner.Err()
}

func (s *Sorter) writeEmptyShard(tempDir string, shardIdx int) (string, error) {
    outputPath := filepath.Join(tempDir, fmt.Sprintf("empty_%d.tmp", shardIdx))
    if err := os.WriteFile(outputPath, []byte{}, 0600); err != nil {
        return "", err
    }
    return outputPath, nil
}

func (s *Sorter) writeSingleChunk(chunk []string, tempDir string, shardIdx int) (string, error) {
    outputPath := filepath.Join(tempDir, fmt.Sprintf(defaultSortedShardPattern, shardIdx))
    data := strings.Join(chunk, "\n")
    if err := os.WriteFile(outputPath, []byte(data), 0600); err != nil {
        return "", err
    }
    return outputPath, nil
}

func (s *Sorter) mergeChunks(chunks [][]string, tempDir string, shardIdx int) (string, error) {
    outputPath := filepath.Join(tempDir, fmt.Sprintf(defaultSortedShardPattern, shardIdx))
    outputFile, err := os.Create(outputPath)
    if err != nil {
        return "", err
    }
    defer outputFile.Close()
    
    if err := os.Chmod(outputPath, 0600); err != nil {
        return "", err
    }

    writer := bufio.NewWriterSize(outputFile, s.config.BufferSize)
    defer writer.Flush()

    h := &chunkHeap{}
    for _, chunk := range chunks {
        if len(chunk) > 0 {
            heap.Push(h, sortedChunk{items: chunk, indices: []int{0}})
        }
    }

    var previousDomain string
    for h.Len() > 0 {
        select {
        case <-s.ctx.Done():
            return "", s.ctx.Err()
        default:
        }
        
        current := heap.Pop(h).(sortedChunk)
        currentDomain := current.items[current.indices[0]]

        if currentDomain != previousDomain {
            if _, err := writer.WriteString(currentDomain); err != nil {
                return "", err
            }
            if err := writer.WriteByte('\n'); err != nil {
                return "", err
            }
            previousDomain = currentDomain
        }

        current.indices[0]++
        if current.indices[0] < len(current.items) {
            heap.Push(h, current)
        }
    }

    return outputPath, nil
}

func (s *Sorter) mergeShards(shardPaths []string, outputPath string) error {
    var validPaths []string
    for _, path := range shardPaths {
        info, err := os.Stat(path)
        if err == nil && info.Size() > 0 {
            validPaths = append(validPaths, path)
        }
    }

    if len(validPaths) == 0 {
        return fmt.Errorf("no data to merge")
    }

    outputFile, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer outputFile.Close()
    
    if err := os.Chmod(outputPath, 0644); err != nil {
        return err
    }
    
    writer := bufio.NewWriterSize(outputFile, s.config.BufferSize)
    defer writer.Flush()
    
    allDomains := make([]string, 0)
    for _, path := range validPaths {
        file, err := os.Open(path)
        if err != nil {
            return err
        }
        
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            select {
            case <-s.ctx.Done():
                file.Close()
                return s.ctx.Err()
            default:
            }
            allDomains = append(allDomains, scanner.Text())
        }
        file.Close()
        os.Remove(path)
        
        if err := scanner.Err(); err != nil {
            return err
        }
    }
    
    sort.Strings(allDomains)
    
    var previous string
    for _, domain := range allDomains {
        if domain != previous {
            if _, err := writer.WriteString(domain); err != nil {
                return err
            }
            if err := writer.WriteByte('\n'); err != nil {
                return err
            }
            previous = domain
        }
    }
    
    return nil
}

func loadConfigFromEnv() Config {
    config := Config{
        Sources: []string{
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://someonewhocares.org/hosts/zero/hosts",
            "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
            "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        },
        OutputFile:       "blocklist.txt",
        TempDir:          "",
        MaxResponseSize:  defaultMaxResponseSize,
        MaxDomainLength:  defaultMaxDomainLength,
        RequestTimeout:   defaultRequestTimeout,
        TotalTimeout:     defaultTotalTimeout,
        RateLimitDelay:   defaultRateLimitDelay,
        MaxRetries:       defaultMaxRetries,
        RetryBackoffBase: defaultRetryBackoffBase,
        WorkerCount:      defaultWorkerCount,
        BufferSize:       defaultBufferSize,
        EnableCache:      true,
        CacheTTL:         defaultCacheTTL,
        EnableGZIP:       true,
        ShardCount:       defaultShardCount,
        ChunkSize:        defaultChunkSize,
    }

    if v := os.Getenv("BLOCKLIST_OUTPUT"); v != "" {
        config.OutputFile = v
    }
    if v := os.Getenv("BLOCKLIST_TEMP_DIR"); v != "" {
        config.TempDir = v
    }
    if v := os.Getenv("BLOCKLIST_WORKERS"); v != "" {
        if count, err := strconv.Atoi(v); err == nil && count > 0 {
            config.WorkerCount = count
        }
    }
    if v := os.Getenv("BLOCKLIST_SHARDS"); v != "" {
        if count, err := strconv.Atoi(v); err == nil && count > 0 && count <= 1000 {
            config.ShardCount = count
        }
    }
    if v := os.Getenv("BLOCKLIST_MAX_RESPONSE_SIZE_MB"); v != "" {
        if mb, err := strconv.ParseInt(v, 10, 64); err == nil && mb > 0 {
            config.MaxResponseSize = mb * 1024 * 1024
        }
    }
    if v := os.Getenv("BLOCKLIST_TIMEOUT_MIN"); v != "" {
        if min, err := strconv.Atoi(v); err == nil && min > 0 {
            config.TotalTimeout = time.Duration(min) * time.Minute
        }
    }

    return config
}

func run() error {
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
    metrics := noopMetrics{}

    config := loadConfigFromEnv()

    if config.TempDir == "" {
        tempDir, err := os.MkdirTemp("", defaultTempDirPattern)
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
        var err error
        cache, err = NewDiskCache(filepath.Join(config.TempDir, "cache"), config.CacheTTL)
        if err != nil {
            logger.WarnContext(ctx, "failed to create cache, continuing without cache", "error", err)
            config.EnableCache = false
        }
    }

    ctxTimeout, cancelTimeout := context.WithTimeout(ctx, config.TotalTimeout)
    defer cancelTimeout()

    logger.InfoContext(ctxTimeout, "starting blocklist generator", "version", "6.1")

    fetcher := NewFetcher(config, cache, logger, metrics)
    results := make(chan FetchResult, len(config.Sources))

    var wg sync.WaitGroup
    sem := make(chan struct{}, config.WorkerCount)

    for _, source := range config.Sources {
        wg.Add(1)
        go func(url string) {
            defer wg.Done()

            select {
            case sem <- struct{}{}:
                defer func() { <-sem }()
            case <-ctxTimeout.Done():
                results <- FetchResult{Source: url, Err: ctxTimeout.Err()}
                return
            }

            timer := time.NewTimer(config.RateLimitDelay)
            select {
            case <-timer.C:
            case <-ctxTimeout.Done():
                timer.Stop()
                results <- FetchResult{Source: url, Err: ctxTimeout.Err()}
                return
            }

            domains, err := fetcher.Fetch(ctxTimeout, url)
            results <- FetchResult{Source: url, Domains: domains, Err: err}
        }(source)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    tempFile, err := os.CreateTemp(config.TempDir, "domains_*.txt")
    if err != nil {
        return err
    }
    defer tempFile.Close()
    defer os.Remove(tempFile.Name())
    
    if err := os.Chmod(tempFile.Name(), 0600); err != nil {
        return err
    }

    writer := bufio.NewWriterSize(tempFile, config.BufferSize)
    domainSet := NewDomainSet()
    totalFetched := 0

    for result := range results {
        if result.Err != nil {
            logger.ErrorContext(ctxTimeout, "source failed", "error", result.Err, "source", filepath.Base(result.Source))
            continue
        }

        for _, domain := range result.Domains {
            if domainSet.Add(domain) {
                if _, err := writer.WriteString(domain); err != nil {
                    return err
                }
                if err := writer.WriteByte('\n'); err != nil {
                    return err
                }
            }
        }
        totalFetched += len(result.Domains)
        logger.InfoContext(ctxTimeout, "source processed", "source", filepath.Base(result.Source), 
            "new_domains", len(result.Domains), "total_unique", domainSet.Size())
    }

    if err := writer.Flush(); err != nil {
        return err
    }

    totalUnique := domainSet.Size()
    if totalUnique == 0 {
        return fmt.Errorf("no domains fetched (fetched %d total)", totalFetched)
    }

    logger.InfoContext(ctxTimeout, "unique domains collected", "count", totalUnique, "total_fetched", totalFetched)

    sorter := NewSorter(config, logger, metrics)
    if err := sorter.Sort(ctxTimeout, domainSet.Slice(), config.OutputFile); err != nil {
        return err
    }

    info, err := os.Stat(config.OutputFile)
    if err != nil {
        return err
    }

    outputFile, err := os.Open(config.OutputFile)
    if err != nil {
        return err
    }
    defer outputFile.Close()

    hasher := sha256.New()
    if _, err := io.Copy(hasher, outputFile); err != nil {
        return err
    }

    logger.InfoContext(ctxTimeout, "generation complete",
        "domains", totalUnique,
        "size_mb", float64(info.Size())/(1024*1024),
        "sha256", hex.EncodeToString(hasher.Sum(nil))[:16])

    return nil
}

func main() {
    startTime := time.Now()

    done := make(chan error, 1)
    go func() {
        done <- run()
    }()

    select {
    case err := <-done:
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            os.Exit(1)
        }
    case <-time.After(gracefulShutdownTimeout):
        fmt.Fprintf(os.Stderr, "Graceful shutdown timeout exceeded\n")
        os.Exit(1)
    }

    fmt.Printf("Time: %v\n", time.Since(startTime).Round(time.Millisecond))
}
