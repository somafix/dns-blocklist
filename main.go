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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	requestTimeout = 30 * time.Second
	totalTimeout   = 5 * time.Minute
	workerCount    = 4
	cacheTTL       = 24 * time.Hour
)

var domainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

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

type Cache struct {
	dir string
}

func NewCache(dir string) (*Cache, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Cache{dir: dir}, nil
}

func (c *Cache) Get(key string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, key))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("invalid")
	}
	ts, _ := strconv.ParseInt(lines[0], 10, 64)
	if time.Since(time.Unix(ts, 0)) > cacheTTL {
		return nil, fmt.Errorf("expired")
	}
	return lines[1:], nil
}

func (c *Cache) Set(key string, domains []string) error {
	content := fmt.Sprintf("%d\n%s", time.Now().Unix(), strings.Join(domains, "\n"))
	return os.WriteFile(filepath.Join(c.dir, key), []byte(content), 0600)
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if len(domain) == 0 || len(domain) > 253 {
		return ""
	}
	if strings.ContainsAny(domain, "/\\*?") || strings.Contains(domain, "..") {
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

func fetchSource(ctx context.Context, url string, cache *Cache) ([]string, error) {
	key := fmt.Sprintf("%x", sha256.Sum256([]byte(url)))[:16]
	if cache != nil {
		if domains, err := cache.Get(key); err == nil {
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
	req.Header.Set("User-Agent", "blocklist/1.0")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	reader := io.LimitReader(resp.Body, 50*1024*1024)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
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

	if cache != nil {
		cache.Set(key, domains)
	}
	return domains, nil
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sources := []string{
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
		"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
		"https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt",
		"https://urlhaus.abuse.ch/downloads/hostfile/",
		"https://phishing.army/download/phishing_army_blocklist.txt",
	}

	outputFile := "blocklist.txt"
	tempDir, _ := os.MkdirTemp("", "cache")
	defer os.RemoveAll(tempDir)

	cache, _ := NewCache(tempDir)
	ctxTimeout, _ := context.WithTimeout(ctx, totalTimeout)

	results := make(chan []string, len(sources))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workerCount)

	for _, src := range sources {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			domains, _ := fetchSource(ctxTimeout, url, cache)
			results <- domains
		}(src)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	set := NewDomainSet()
	for domains := range results {
		for _, d := range domains {
			set.Add(d)
		}
	}

	domains := set.Slice()
	sort.Strings(domains)

	file, _ := os.Create(outputFile)
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, d := range domains {
		writer.WriteString(d + "\n")
	}
	writer.Flush()

	fmt.Printf("Generated %d domains\n", len(domains))
}
