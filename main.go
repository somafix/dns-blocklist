package main

import (
    "bufio"
    "compress/gzip"
    "container/heap"
    "context"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
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

const (
    bufferSize        = 256 * 1024
    externalSortLimit = 500000
    chunkSize         = 500000
    maxDecompressed   = 200 * 1024 * 1024
    shutdownTimeout   = 30 * time.Second
    shardCount        = 100
    maxResponseSize   = 50 * 1024 * 1024
    maxDomainLen      = 253
    requestTimeout    = 30 * time.Second
    totalTimeout      = 5 * time.Minute
    rateLimitDelay    = 200 * time.Millisecond
    maxRetries        = 3
    retryBackoff      = 2 * time.Second
    workerCount       = 4
    cacheTTL          = 24 * time.Hour
    maxIdleConns      = 100
    maxConnsPerHost   = 10
    idleConnTimeout   = 90 * time.Second
    dnsTimeout        = 5 * time.Second
    maxShards         = 1000
    minShards         = 10
)

var (
    domainRegex    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
    ipRegex        = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
    privateIPRanges []*net.IPNet
)

func init() {
    rand.Seed(time.Now().UnixNano())
    
    for _, cidr := range []string{
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    } {
        _, block, _ := net.ParseCIDR(cidr)
        privateIPRanges = append(privateIPRanges, block)
    }
}

type Config struct {
    Sources     []string
    OutputFile  string
    TempDir     string
    WorkerCount int
    ShardCount  int
    EnableCache bool
    EnableGZIP  bool
}

type DomainSet struct {
    mu    sync.RWMutex
    items map[string]struct{}
}

type FetchResult struct {
    Source  string
    Domains []string
    Err     error
}

type Fetcher struct {
    client *http.Client
    cache  *DiskCache
    config Config
    logger *slog.Logger
}

type DiskCache struct {
    dir string
    ttl time.Duration
    mu  sync.Mutex
}

type Sorter struct {
    config Config
    logger *slog.Logger
}

type mergeItem struct {
    domain string
    source int
}

type PriorityQueue []mergeItem

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
    return pq[i].domain < pq[j].domain
}
func (pq PriorityQueue) Swap(i, j int) {
    pq[i], pq[j] = pq[j], pq[i]
}
func (pq *PriorityQueue) Push(x interface{}) {
    *pq = append(*pq, x.(mergeItem))
}
func (pq *PriorityQueue) Pop() interface{} {
    old := *pq
    n := len(old)
    item := old[n-1]
    *pq = old[0 : n-1]
    return item
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

func NewDiskCache(dir string, ttl time.Duration) (*DiskCache, error) {
    if err := os.MkdirAll(dir, 0700); err != nil {
        return nil, err
    }
    return &DiskCache{dir: dir, ttl: ttl}, nil
}

func (c *DiskCache) keyPath(key string) string {
    hash := sha256.Sum256([]byte(key))
    return filepath.Join(c.dir, hex.EncodeToString(hash[:]))
}

func (c *DiskCache) Get(key string) ([]string, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    path := c.keyPath(key)
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    lines := strings.Split(string(data), "\n")
    if len(lines) < 2 {
        return nil, fmt.Errorf("invalid cache format")
    }

    ts, err := strconv.ParseInt(lines[0], 10, 64)
    if err != nil {
        return nil, err
    }

    if time.Since(time.Unix(ts, 0)) > c.ttl {
        os.Remove(path)
        return nil, fmt.Errorf("cache expired")
    }

    return lines[1:], nil
}

func (c *DiskCache) Set(key string, domains []string) error {
    c.mu.Lock()
    defer c.mu.Unlock()

    content := fmt.Sprintf("%d\n%s", time.Now().Unix(), strings.Join(domains, "\n"))
    return os.WriteFile(c.keyPath(key), []byte(content), 0600)
}

func NewFetcher(config Config, cache *DiskCache, logger *slog.Logger) *Fetcher {
    transport := &http.Transport{
        MaxIdleConns:        maxIdleConns,
        MaxConnsPerHost:     maxConnsPerHost,
        MaxIdleConnsPerHost: maxConnsPerHost / 2,
        IdleConnTimeout:     idleConnTimeout,
        TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
    }

    return &Fetcher{
        client: &http.Client{
            Timeout:   requestTimeout,
            Transport: transport,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                if len(via) >= 10 {
                    return fmt.Errorf("too many redirects")
                }
                return validateURL(req.URL.String())
            },
        },
        cache:  cache,
        config: config,
        logger: logger,
    }
}

func validateURL(rawURL string) error {
    parsed, err := url.Parse(rawURL)
    if err != nil {
        return err
    }

    if parsed.Scheme != "http" && parsed.Scheme != "https" {
        return fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
    }

    ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
    defer cancel()

    ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", parsed.Hostname())
    if err != nil {
        return nil
    }

    for _, ip := range ips {
        for _, block := range privateIPRanges {
            if block.Contains(ip) {
                return fmt.Errorf("private IP not allowed: %s", ip)
            }
        }
    }

    return nil
}

func normalizeDomain(domain string) (string, error) {
    domain = strings.ToLower(strings.TrimSuffix(domain, "."))

    for _, r := range domain {
        if r > 127 {
            return "", fmt.Errorf("non-ascii: %s", domain)
        }
    }

    if strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
        return "", fmt.Errorf("invalid: %s", domain)
    }

    if len(domain) > maxDomainLen {
        return "", fmt.Errorf("too long: %d", len(domain))
    }

    return domain, nil
}

func isValidDomain(domain string) bool {
    if len(domain) == 0 || len(domain) > maxDomainLen {
        return false
    }

    if strings.ContainsAny(domain, "*\\/:?&=@#$%^`|~") {
        return false
    }

    if strings.HasSuffix(domain, ".local") || strings.HasSuffix(domain, ".localhost") {
        return false
    }

    if ipRegex.MatchString(domain) {
        return false
    }

    return domainRegex.MatchString(domain)
}

func extractDomain(line string) string {
    fields := strings.Fields(line)
    if len(fields) == 0 {
        return ""
    }

    var domain string
    if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
        domain = fields[1]
    } else if len(fields) == 1 && strings.Contains(fields[0], ".") && !ipRegex.MatchString(fields[0]) {
        domain = fields[0]
    } else {
        return ""
    }

    domain = strings.TrimSuffix(domain, ".")
    if domain == "" || strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
        return ""
    }

    return domain
}

func (f *Fetcher) Fetch(ctx context.Context, sourceURL string) ([]string, error) {
    if err := validateURL(sourceURL); err != nil {
        return nil, err
    }

    if f.config.EnableCache && f.cache != nil {
        if domains, err := f.cache.Get(sourceURL); err == nil {
            f.logger.DebugContext(ctx, "cache hit", "url", sourceURL)
            return domains, nil
        }
    }

    var lastErr error
    for attempt := 0; attempt <= maxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return nil, ctx.Err()
            default:
            }

            backoff := retryBackoff * time.Duration(attempt*attempt)
            backoff += time.Duration(rand.Int63n(int64(backoff / 2)))

            timer := time.NewTimer(backoff)
            select {
            case <-ctx.Done():
                timer.Stop()
                return nil, ctx.Err()
            case <-timer.C:
            }
        }

        domains, err := f.fetchSource(ctx, sourceURL)
        if err == nil {
            if f.config.EnableCache && f.cache != nil {
                if err := f.cache.Set(sourceURL, domains); err != nil {
                    f.logger.ErrorContext(ctx, "cache set failed", "error", err)
                }
            }
            return domains, nil
        }

        lastErr = err
        f.logger.WarnContext(ctx, "fetch failed", "url", sourceURL, "attempt", attempt, "error", err)
    }

    return nil, fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

func (f *Fetcher) fetchSource(ctx context.Context, sourceURL string) ([]string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("User-Agent", "blocklist-generator/6.5")
    if f.config.EnableGZIP {
        req.Header.Set("Accept-Encoding", "gzip")
    }

    resp, err := f.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("http %d", resp.StatusCode)
    }

    reader := io.LimitReader(resp.Body, maxResponseSize)

    if f.config.EnableGZIP && resp.Header.Get("Content-Encoding") == "gzip" {
        gzReader, err := gzip.NewReader(reader)
        if err != nil {
            return nil, err
        }
        defer gzReader.Close()
        reader = io.LimitReader(gzReader, maxDecompressed)
    }

    scanner := bufio.NewScanner(reader)
    scanner.Buffer(make([]byte, bufferSize), bufferSize)

    domains := make([]string, 0, 10000)
    seen := make(map[string]struct{})

    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return domains, ctx.Err()
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

        if !isValidDomain(normalized) {
            continue
        }

        if _, exists := seen[normalized]; !exists {
            seen[normalized] = struct{}{}
            domains = append(domains, normalized)
        }
    }

    if err := scanner.Err(); err != nil {
        return domains, err
    }

    return domains, nil
}

func NewSorter(config Config, logger *slog.Logger) *Sorter {
    return &Sorter{config: config, logger: logger}
}

func (s *Sorter) Sort(ctx context.Context, domains []string, outputPath string) error {
    if len(domains) == 0 {
        return fmt.Errorf("no domains to sort")
    }

    if len(domains) > externalSortLimit {
        s.logger.DebugContext(ctx, "external sort", "count", len(domains))
        return s.externalSort(ctx, domains, outputPath)
    }

    return s.inMemorySort(ctx, domains, outputPath)
}

func (s *Sorter) inMemorySort(ctx context.Context, domains []string, outputPath string) error {
    unique := make(map[string]struct{})
    for _, d := range domains {
        unique[d] = struct{}{}
    }

    sorted := make([]string, 0, len(unique))
    for d := range unique {
        sorted = append(sorted, d)
    }
    sort.Strings(sorted)

    file, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := bufio.NewWriterSize(file, bufferSize)
    defer writer.Flush()

    for _, d := range sorted {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        if _, err := writer.WriteString(d); err != nil {
            return err
        }
        if err := writer.WriteByte('\n'); err != nil {
            return err
        }
    }

    return nil
}

func (s *Sorter) externalSort(ctx context.Context, domains []string, outputPath string) error {
    tempDir, err := os.MkdirTemp("", "blocksort_*")
    if err != nil {
        return err
    }
    defer os.RemoveAll(tempDir)

    shardPaths, err := s.writeShards(ctx, domains, tempDir)
    if err != nil {
        return err
    }

    sortedShards, err := s.sortShards(ctx, shardPaths, tempDir)
    if err != nil {
        return err
    }

    return s.mergeShards(ctx, sortedShards, outputPath)
}

func (s *Sorter) writeShards(ctx context.Context, domains []string, tempDir string) ([]string, error) {
    writers := make([]*bufio.Writer, s.config.ShardCount)
    paths := make([]string, s.config.ShardCount)
    files := make([]*os.File, s.config.ShardCount)

    for i := 0; i < s.config.ShardCount; i++ {
        file, err := os.CreateTemp(tempDir, fmt.Sprintf("shard_%d_*.tmp", i))
        if err != nil {
            for j := 0; j < i; j++ {
                files[j].Close()
                os.Remove(paths[j])
            }
            return nil, err
        }
        files[i] = file
        paths[i] = file.Name()
        writers[i] = bufio.NewWriterSize(file, bufferSize)
    }

    defer func() {
        for i := 0; i < s.config.ShardCount; i++ {
            if files[i] != nil {
                writers[i].Flush()
                files[i].Close()
            }
        }
    }()

    for _, domain := range domains {
        select {
        case <-ctx.Done():
            return nil, ctx.Err()
        default:
        }

        hasher := fnv.New32a()
        hasher.Write([]byte(domain))
        idx := int(hasher.Sum32()) % s.config.ShardCount

        if _, err := writers[idx].WriteString(domain); err != nil {
            return nil, err
        }
        if err := writers[idx].WriteByte('\n'); err != nil {
            return nil, err
        }
    }

    return paths, nil
}

func (s *Sorter) sortShards(ctx context.Context, shardPaths []string, tempDir string) ([]string, error) {
    result := make([]string, len(shardPaths))
    errCh := make(chan error, len(shardPaths))
    var wg sync.WaitGroup

    for i, path := range shardPaths {
        if path == "" {
            continue
        }

        wg.Add(1)
        go func(idx int, p string) {
            defer wg.Done()

            sortedPath, err := s.sortSingleShard(ctx, p, tempDir)
            if err != nil {
                errCh <- err
                return
            }
            result[idx] = sortedPath
        }(i, path)
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

    return result, nil
}

func (s *Sorter) sortSingleShard(ctx context.Context, inputPath, tempDir string) (string, error) {
    file, err := os.Open(inputPath)
    if err != nil {
        return "", err
    }
    defer file.Close()
    defer os.Remove(inputPath)

    scanner := bufio.NewScanner(file)
    domains := make([]string, 0)
    seen := make(map[string]struct{})

    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return "", ctx.Err()
        default:
        }

        domain := scanner.Text()
        if domain == "" {
            continue
        }
        if _, exists := seen[domain]; !exists {
            seen[domain] = struct{}{}
            domains = append(domains, domain)
        }
    }

    if err := scanner.Err(); err != nil {
        return "", err
    }

    sort.Strings(domains)

    outputPath := filepath.Join(tempDir, fmt.Sprintf("sorted_%d_%d.tmp", rand.Int63(), time.Now().UnixNano()))
    output, err := os.Create(outputPath)
    if err != nil {
        return "", err
    }
    defer output.Close()

    writer := bufio.NewWriterSize(output, bufferSize)
    defer writer.Flush()

    for _, d := range domains {
        if _, err := writer.WriteString(d); err != nil {
            return "", err
        }
        if err := writer.WriteByte('\n'); err != nil {
            return "", err
        }
    }

    return outputPath, nil
}

func (s *Sorter) mergeShards(ctx context.Context, shardPaths []string, outputPath string) error {
    validPaths := make([]string, 0)
    for _, path := range shardPaths {
        if path != "" {
            if info, err := os.Stat(path); err == nil && info.Size() > 0 {
                validPaths = append(validPaths, path)
            }
        }
    }

    if len(validPaths) == 0 {
        return fmt.Errorf("no data to merge")
    }

    files := make([]*os.File, len(validPaths))
    scanners := make([]*bufio.Scanner, len(validPaths))
    pq := make(PriorityQueue, 0)

    for i, path := range validPaths {
        file, err := os.Open(path)
        if err != nil {
            return err
        }
        files[i] = file
        scanners[i] = bufio.NewScanner(file)

        if scanners[i].Scan() {
            heap.Push(&pq, mergeItem{
                domain: scanners[i].Text(),
                source: i,
            })
        }
    }

    defer func() {
        for _, f := range files {
            if f != nil {
                f.Close()
                os.Remove(f.Name())
            }
        }
    }()

    output, err := os.Create(outputPath)
    if err != nil {
        return err
    }
    defer output.Close()

    writer := bufio.NewWriterSize(output, bufferSize)
    defer writer.Flush()

    var lastDomain string
    for pq.Len() > 0 {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        item := heap.Pop(&pq).(mergeItem)

        if item.domain != lastDomain {
            if _, err := writer.WriteString(item.domain); err != nil {
                return err
            }
            if err := writer.WriteByte('\n'); err != nil {
                return err
            }
            lastDomain = item.domain
        }

        if scanners[item.source].Scan() {
            heap.Push(&pq, mergeItem{
                domain: scanners[item.source].Text(),
                source: item.source,
            })
        }
    }

    return nil
}

func loadConfig() Config {
    sources := os.Getenv("BLOCKLIST_SOURCES")
    var sourceList []string
    if sources != "" {
        sourceList = strings.Split(sources, ",")
    } else {
        sourceList = []string{
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
            "https://someonewhocares.org/hosts/zero/hosts",
            "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        }
    }

    shardCnt := getEnvInt("BLOCKLIST_SHARDS", shardCount)
    if shardCnt > maxShards {
        shardCnt = maxShards
    }
    if shardCnt < minShards {
        shardCnt = minShards
    }

    return Config{
        Sources:     sourceList,
        OutputFile:  getEnv("BLOCKLIST_OUTPUT", "blocklist.txt"),
        TempDir:     getEnv("BLOCKLIST_TEMP_DIR", ""),
        WorkerCount: getEnvInt("BLOCKLIST_WORKERS", workerCount),
        ShardCount:  shardCnt,
        EnableCache: getEnvBool("BLOCKLIST_ENABLE_CACHE", true),
        EnableGZIP:  getEnvBool("BLOCKLIST_ENABLE_GZIP", true),
    }
}

func getEnv(key, defaultVal string) string {
    if val := os.Getenv(key); val != "" {
        return val
    }
    return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
    if val := os.Getenv(key); val != "" {
        if intVal, err := strconv.Atoi(val); err == nil && intVal > 0 {
            return intVal
        }
    }
    return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
    if val := os.Getenv(key); val != "" {
        return strings.ToLower(val) == "true" || val == "1"
    }
    return defaultVal
}

func run() error {
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    config := loadConfig()

    workDir := config.TempDir
    var ownedTemp bool
    if workDir == "" {
        var err error
        workDir, err = os.MkdirTemp("", "blocklist_*")
        if err != nil {
            return err
        }
        ownedTemp = true
    }

    if err := os.MkdirAll(workDir, 0700); err != nil {
        return err
    }

    if ownedTemp {
        defer os.RemoveAll(workDir)
    }

    var cache *DiskCache
    if config.EnableCache {
        var err error
        cache, err = NewDiskCache(filepath.Join(workDir, "cache"), cacheTTL)
        if err != nil {
            logger.Warn("cache disabled", "error", err)
            config.EnableCache = false
        }
    }

    ctxTimeout, cancelTimeout := context.WithTimeout(ctx, totalTimeout)
    defer cancelTimeout()

    logger.Info("starting", "version", "6.5", "sources", len(config.Sources))

    fetcher := NewFetcher(config, cache, logger)
    results := make(chan FetchResult, len(config.Sources))

    sem := make(chan struct{}, config.WorkerCount)
    var wg sync.WaitGroup

    uniqueSources := make(map[string]bool)
    for _, src := range config.Sources {
        if !uniqueSources[src] {
            uniqueSources[src] = true
        }
    }

    for src := range uniqueSources {
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

            timer := time.NewTimer(rateLimitDelay)
            select {
            case <-timer.C:
            case <-ctxTimeout.Done():
                timer.Stop()
                results <- FetchResult{Source: url, Err: ctxTimeout.Err()}
                return
            }

            domains, err := fetcher.Fetch(ctxTimeout, url)
            results <- FetchResult{Source: url, Domains: domains, Err: err}
        }(src)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    domainSet := NewDomainSet()
    totalFetched := 0

    for res := range results {
        if res.Err != nil {
            logger.Error("source failed", "source", res.Source, "error", res.Err)
            continue
        }

        for _, domain := range res.Domains {
            if domainSet.Add(domain) {
                totalFetched++
            }
        }
        logger.Info("source processed", "source", res.Source, "new", len(res.Domains), "total", domainSet.Size())
    }

    if domainSet.Size() == 0 {
        return fmt.Errorf("no domains fetched (fetched %d total)", totalFetched)
    }

    logger.Info("collected", "unique", domainSet.Size(), "total", totalFetched)

    sorter := NewSorter(config, logger)
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

    logger.Info("complete",
        "domains", domainSet.Size(),
        "size_mb", float64(info.Size())/(1024*1024),
        "sha256", hex.EncodeToString(hasher.Sum(nil))[:16])

    return nil
}

func main() {
    start := time.Now()

    if err := run(); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Time: %v\n", time.Since(start).Round(time.Millisecond))
}
