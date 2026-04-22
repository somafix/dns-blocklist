package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	maxDomainLen    = 253
	requestTimeout  = 30 * time.Second
	totalTimeout    = 5 * time.Minute
	workerCount     = 4
	cacheTTL        = 24 * time.Hour
	maxResponseSize = 50 * 1024 * 1024
	maxDecompressed = 200 * 1024 * 1024
)

var (
	domainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	ipRegex     = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
)

type Config struct {
	Sources     []string
	OutputFile  string
	TempDir     string
	WorkerCount int
	EnableCache bool
}

type DomainSet struct {
	mu    sync.RWMutex
	items map[string]struct{}
}

func NewDomainSet() *DomainSet {
	return &DomainSet{items: make(map[string]struct{})}
}

func (s *DomainSet) Add(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[domain] = struct{}{}
}

func (s *DomainSet) Slice() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]string, 0, len(s.items))
	for d := range s.items {
		result = append(result, d)
	}
	return result
}

func (s *DomainSet) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

type DiskCache struct {
	dir string
	ttl time.Duration
	mu  sync.Mutex
}

func NewDiskCache(dir string, ttl time.Duration) (*DiskCache, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &DiskCache{dir: dir, ttl: ttl}, nil
}

func (c *DiskCache) Get(key string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	data, err := os.ReadFile(filepath.Join(c.dir, hashKey(key)))
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid cache")
	}

	ts, err := strconv.ParseInt(lines[0], 10, 64)
	if err != nil {
		return nil, err
	}

	if time.Since(time.Unix(ts, 0)) > c.ttl {
		os.Remove(filepath.Join(c.dir, hashKey(key)))
		return nil, fmt.Errorf("expired")
	}

	return lines[1:], nil
}

func (c *DiskCache) Set(key string, domains []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	content := fmt.Sprintf("%d\n%s", time.Now().Unix(), strings.Join(domains, "\n"))
	return os.WriteFile(filepath.Join(c.dir, hashKey(key)), []byte(content), 0600)
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if len(domain) == 0 || len(domain) > maxDomainLen {
		return ""
	}
	if strings.ContainsAny(domain, "/\\*?") || strings.Contains(domain, "..") {
		return ""
	}
	if ipRegex.MatchString(domain) {
		return ""
	}
	if !domainRegex.MatchString(domain) {
		return ""
	}
	return domain
}

func extractDomain(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
		return fields[1]
	}
	if len(fields) == 1 && strings.Contains(fields[0], ".") {
		return fields[0]
	}
	return ""
}

func fetchSource(ctx context.Context, url string, enableGZIP bool, cache *DiskCache) ([]string, error) {
	if cache != nil {
		if domains, err := cache.Get(url); err == nil {
			return domains, nil
		}
	}

	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blocklist-generator/2.0")
	if enableGZIP {
		req.Header.Set("Accept-Encoding", "gzip")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	reader := io.LimitReader(resp.Body, maxResponseSize)
	if enableGZIP && resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = io.LimitReader(gz, maxDecompressed)
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	seen := make(map[string]bool)
	domains := make([]string, 0)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return domains, ctx.Err()
		default:
		}

		raw := extractDomain(scanner.Text())
		if raw == "" {
			continue
		}

		normalized := normalizeDomain(raw)
		if normalized == "" {
			continue
		}

		if !seen[normalized] {
			seen[normalized] = true
			domains = append(domains, normalized)
		}
	}

	if err := scanner.Err(); err != nil {
		return domains, err
	}

	if cache != nil {
		cache.Set(url, domains)
	}

	return domains, nil
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	sourcesEnv := os.Getenv("BLOCKLIST_SOURCES")
	var sources []string
	if sourcesEnv != "" {
		sources = strings.Split(sourcesEnv, ",")
	} else {
		sources = []string{
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			"https://someonewhocares.org/hosts/zero/hosts",
		}
	}

	outputFile := os.Getenv("BLOCKLIST_OUTPUT")
	if outputFile == "" {
		outputFile = "blocklist.txt"
	}

	tempDir := os.Getenv("BLOCKLIST_TEMP_DIR")
	var ownedTemp bool
	if tempDir == "" {
		var err error
		tempDir, err = os.MkdirTemp("", "blocklist_*")
		if err != nil {
			return err
		}
		ownedTemp = true
	}
	defer func() {
		if ownedTemp {
			os.RemoveAll(tempDir)
		}
	}()

	enableCache := os.Getenv("BLOCKLIST_ENABLE_CACHE") != "false"

	var cache *DiskCache
	if enableCache {
		var err error
		cache, err = NewDiskCache(filepath.Join(tempDir, "cache"), cacheTTL)
		if err != nil {
			logger.Warn("cache disabled", "error", err)
		}
	}

	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, totalTimeout)
	defer cancelTimeout()

	logger.Info("starting", "sources", len(sources))

	type result struct {
		src     string
		domains []string
		err     error
	}

	results := make(chan result, len(sources))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workerCount)

	for _, src := range sources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			domains, err := fetchSource(ctxTimeout, url, true, cache)
			results <- result{src: url, domains: domains, err: err}
		}(src)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	domainSet := NewDomainSet()
	for res := range results {
		if res.err != nil {
			logger.Error("fetch failed", "source", res.src, "error", res.err)
			continue
		}
		for _, d := range res.domains {
			domainSet.Add(d)
		}
		logger.Info("source done", "source", res.src, "count", len(res.domains), "total", domainSet.Size())
	}

	if domainSet.Size() == 0 {
		return fmt.Errorf("no domains fetched")
	}

	logger.Info("sorting", "domains", domainSet.Size())

	domains := domainSet.Slice()
	sort.Strings(domains)

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, d := range domains {
		if _, err := writer.WriteString(d + "\n"); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	hasher := sha256.New()
	file.Seek(0, 0)
	io.Copy(hasher, file)

	logger.Info("complete",
		"domains", len(domains),
		"output", outputFile,
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
