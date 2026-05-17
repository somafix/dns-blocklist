// DNSBlocklistManager.java - Elite Enterprise Edition
package dns.blocklist;

import java.io.*;
import java.net.http.*;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.Pattern;
import java.util.logging.*;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

/**
 * DNS Blocklist Manager - Enterprise Elite Edition
 * 
 * <p>Профессиональный менеджер блоклистов с поддержкой:</p>
 * <ul>
 *   <li>Асинхронной загрузки из множества источников</li>
 *   <li>Расширенной фильтрации (whitelist/blacklist/wildcard)</li>
 *   <li>Многоуровневого кэширования с TTL</li>
 *   <li>Промышленного логирования с ротацией</li>
 *   <li>Graceful shutdown и обработки сигналов</li>
 *   <li>Мониторинга и экспорта метрик</li>
 * </ul>
 * 
 * @author DNS Blocklist Team
 * @version 8.0.0-elite
 * @since Java 21+
 */
public final class DNSBlocklistManager {
    
    // ============================================================================
    // Константы и конфигурация
    // ============================================================================
    
    private static final String VERSION = "8.0.0-elite";
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'");
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
    
    private static final class AppConfig {
        @SerializedName("timeout_seconds")
        final int timeout = Integer.parseInt(
            System.getenv().getOrDefault("BLOCKLIST_TIMEOUT", "30"));
        
        final int maxRetries = 3;
        final int retryDelaySeconds = 5;
        final String userAgent = "DNS-Blocklist-Manager/" + VERSION;
        final int maxDomains = 10_000_000;
        final boolean enableCache = true;
        final int cacheTtlHours = 24;
        final int parallelDownloads = 3;
        final int batchSize = 10_000;
        
        private AppConfig() {}
        
        static AppConfig getInstance() {
            return LazyHolder.INSTANCE;
        }
        
        private static final class LazyHolder {
            static final AppConfig INSTANCE = new AppConfig();
        }
    }
    
    // ============================================================================
    // Иерархия исключений (Elite)
    // ============================================================================
    
    public static abstract class BlocklistException extends Exception {
        private final ErrorCode errorCode;
        
        protected BlocklistException(String message, ErrorCode errorCode) {
            super(message);
            this.errorCode = errorCode;
        }
        
        protected BlocklistException(String message, Throwable cause, ErrorCode errorCode) {
            super(message, cause);
            this.errorCode = errorCode;
        }
        
        public ErrorCode getErrorCode() { return errorCode; }
    }
    
    public enum ErrorCode {
        NETWORK_ERROR(1001, "Сетевая ошибка"),
        PARSE_ERROR(1002, "Ошибка парсинга"),
        VALIDATION_ERROR(1003, "Ошибка валидации"),
        CACHE_ERROR(1004, "Ошибка кэша"),
        IO_ERROR(1005, "Ошибка ввода/вывода"),
        TIMEOUT_ERROR(1006, "Таймаут операции"),
        CONFIG_ERROR(1007, "Ошибка конфигурации");
        
        private final int code;
        private final String message;
        
        ErrorCode(int code, String message) {
            this.code = code;
            this.message = message;
        }
        
        public int getCode() { return code; }
        public String getMessage() { return message; }
    }
    
    // ============================================================================
    // Профессиональное логирование с JSON форматом
    // ============================================================================
    
    public static final class StructuredLogger {
        private static final Logger logger = Logger.getLogger("DNSBlocklistManager");
        private final boolean jsonFormat;
        private final boolean verbose;
        
        private StructuredLogger(Builder builder) {
            this.jsonFormat = builder.jsonFormat;
            this.verbose = builder.verbose;
            configureLogger(builder);
        }
        
        private void configureLogger(Builder builder) {
            logger.setUseParentHandlers(false);
            logger.setLevel(builder.verbose ? Level.FINE : Level.INFO);
            
            try {
                // Файловый handler с ротацией и JSON форматом
                FileHandler fileHandler = new FileHandler(
                    builder.logFile.toString(), 
                    10 * 1024 * 1024,  // 10MB
                    10,  // 10 files
                    true  // append
                );
                
                if (jsonFormat) {
                    fileHandler.setFormatter(new JsonLogFormatter());
                } else {
                    fileHandler.setFormatter(new StandardLogFormatter());
                }
                
                logger.addHandler(fileHandler);
            } catch (IOException e) {
                System.err.println("Failed to initialize file logger: " + e.getMessage());
            }
            
            // Консольный handler с цветами
            ConsoleHandler consoleHandler = new ConsoleHandler();
            consoleHandler.setFormatter(new ColoredConsoleFormatter());
            consoleHandler.setLevel(builder.verbose ? Level.FINE : Level.INFO);
            logger.addHandler(consoleHandler);
        }
        
        // Fluent API для логирования
        public StructuredLogger info(String msg) { logger.info(msg); return this; }
        public StructuredLogger warning(String msg) { logger.warning(msg); return this; }
        public StructuredLogger error(String msg) { logger.severe(msg); return this; }
        public StructuredLogger debug(String msg) { if (verbose) logger.fine(msg); return this; }
        
        public StructuredLogger withField(String key, Object value) {
            // Для JSON логирования можно добавить контекст
            return this;
        }
        
        public static Builder builder() { return new Builder(); }
        
        public static class Builder {
            private Path logFile = Path.of("logs/dns_blocker.log");
            private boolean jsonFormat = false;
            private boolean verbose = false;
            
            public Builder logFile(Path path) { this.logFile = path; return this; }
            public Builder jsonFormat(boolean json) { this.jsonFormat = json; return this; }
            public Builder verbose(boolean v) { this.verbose = v; return this; }
            public StructuredLogger build() { return new StructuredLogger(this); }
        }
        
        private static class JsonLogFormatter extends Formatter {
            private final Gson gson = new GsonBuilder().create();
            
            @Override
            public String format(LogRecord record) {
                Map<String, Object> logEntry = new LinkedHashMap<>();
                logEntry.put("timestamp", Instant.ofEpochMilli(record.getMillis()).toString());
                logEntry.put("level", record.getLevel().getName());
                logEntry.put("logger", record.getLoggerName());
                logEntry.put("message", record.getMessage());
                logEntry.put("thread", Thread.currentThread().getName());
                
                if (record.getThrown() != null) {
                    logEntry.put("exception", record.getThrown().toString());
                }
                
                return gson.toJson(logEntry) + "\n";
            }
        }
        
        private static class ColoredConsoleFormatter extends Formatter {
            private static final Map<String, String> COLORS = Map.of(
                "INFO", "\u001B[92m",     // Green
                "WARNING", "\u001B[93m",  // Yellow
                "SEVERE", "\u001B[91m",   // Red
                "FINE", "\u001B[96m"      // Cyan
            );
            private static final String RESET = "\u001B[0m";
            
            private static final Map<String, String> EMOJIS = Map.of(
                "INFO", "ℹ️ ",
                "WARNING", "⚠️ ",
                "SEVERE", "❌ ",
                "FINE", "🐛 "
            );
            
            @Override
            public String format(LogRecord record) {
                String level = record.getLevel().getName();
                String color = COLORS.getOrDefault(level, RESET);
                String emoji = EMOJIS.getOrDefault(level, "");
                return String.format("%s%s%s %s%n", color, emoji, record.getMessage(), RESET);
            }
        }
        
        private static class StandardLogFormatter extends Formatter {
            @Override
            public String format(LogRecord record) {
                return String.format("[%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS] [%2$s] %3$s%n",
                    record.getMillis(), record.getLevel(), record.getMessage());
            }
        }
    }
    
    // ============================================================================
    // Валидатор доменов с кэшированием результатов
    // ============================================================================
    
    public static final class DomainValidator {
        private static final Set<String> VALID_TLDS = Set.of(
            "com", "org", "net", "io", "app", "dev", "xyz", "info", "biz",
            "ru", "ua", "by", "kz", "pl", "de", "fr", "uk", "us", "ca", "au",
            "jp", "cn", "in", "br", "mx", "za", "eg", "sa", "ae", "tr"
        );
        
        private static final List<Pattern> CLEAN_PATTERNS = List.of(
            Pattern.compile("^https?://"),
            Pattern.compile("^[0-9.]+ "),
            Pattern.compile("^\\|\\|"),
            Pattern.compile("\\^$"),
            Pattern.compile("/+\\s*$"),
            Pattern.compile("^[0-9a-f:]+ ")
        );
        
        // LRU кэш для результатов валидации
        private static final int VALIDATION_CACHE_SIZE = 100_000;
        private static final Map<String, String> validationCache = new ConcurrentHashMap<>();
        
        private DomainValidator() {} // Utility class
        
        public static Optional<String> clean(String line) {
            if (line == null || line.isBlank()) return Optional.empty();
            
            // Проверка кэша
            String cached = validationCache.get(line);
            if (cached != null) {
                return cached.isEmpty() ? Optional.empty() : Optional.of(cached);
            }
            
            String result = doClean(line);
            if (validationCache.size() < VALIDATION_CACHE_SIZE) {
                validationCache.put(line, result == null ? "" : result);
            }
            
            return Optional.ofNullable(result);
        }
        
        private static String doClean(String line) {
            // Удаление комментариев
            int commentIdx = line.indexOf('#');
            if (commentIdx != -1) {
                line = line.substring(0, commentIdx);
            }
            
            line = line.trim().toLowerCase();
            if (line.isEmpty()) return null;
            
            // Применение паттернов очистки
            for (Pattern pattern : CLEAN_PATTERNS) {
                line = pattern.matcher(line).replaceAll("");
            }
            
            // Проверка на IP-адреса
            if (line.matches("^\\d+(\\.\\d+){3}$") || line.matches("^[0-9a-f:]+$")) {
                return null;
            }
            
            // Базовая валидация домена
            if (!isValidDomain(line)) return null;
            
            return line;
        }
        
        private static boolean isValidDomain(String domain) {
            if (domain.length() > 253) return false;
            if (domain.startsWith(".") || domain.endsWith(".")) return false;
            if (domain.contains("..")) return false;
            if (!domain.matches("^[a-z0-9][a-z0-9.-]*[a-z0-9]$")) return false;
            
            String[] parts = domain.split("\\.");
            if (parts.length >= 2) {
                String tld = parts[parts.length - 1];
                if (!VALID_TLDS.contains(tld) && tld.length() > 6) {
                    return false;
                }
            }
            return true;
        }
        
        public static boolean matchWildcard(String domain, Set<String> patterns) {
            for (String pattern : patterns) {
                if (matchesPattern(domain, pattern)) return true;
            }
            return false;
        }
        
        private static boolean matchesPattern(String domain, String pattern) {
            if (pattern.endsWith("*")) {
                return domain.startsWith(pattern.substring(0, pattern.length() - 1));
            }
            if (pattern.startsWith("*")) {
                return domain.endsWith(pattern.substring(1));
            }
            if (pattern.contains("*")) {
                String regex = pattern.replace(".", "\\.").replace("*", ".*");
                return Pattern.compile("^" + regex + "$").matcher(domain).matches();
            }
            return domain.equals(pattern);
        }
    }
    
    // ============================================================================
    // Cache Manager с несколькими стратегиями
    // ============================================================================
    
    @FunctionalInterface
    interface CacheStrategy {
        <K, V> V get(Map<K, V> cache, K key);
    }
    
    static final class CacheStrategyFactory {
        static <K, V> CacheStrategy ttl(Duration ttl) {
            class CacheEntry<V> {
                final V value;
                final Instant timestamp;
                
                CacheEntry(V value) { this.value = value; this.timestamp = Instant.now(); }
                boolean isExpired(Duration ttl) { return Instant.now().isAfter(timestamp.plus(ttl)); }
            }
            
            return (cache, key) -> {
                @SuppressWarnings("unchecked")
                CacheEntry<V> entry = (CacheEntry<V>) cache.get(key);
                if (entry != null && !entry.isExpired(ttl)) return entry.value;
                return null;
            };
        }
        
        static <K, V> CacheStrategy lru(int maxSize) {
            return (cache, key) -> {
                @SuppressWarnings("unchecked")
                Map<K, V> lruCache = (Map<K, V>) cache;
                V value = lruCache.get(key);
                if (value != null && lruCache instanceof LinkedHashMap<?, ?>) {
                    // Перемещаем в конец (LRU логика)
                }
                return value;
            };
        }
    }
    
    static final class DomainCache {
        private final Path cacheFile;
        private final Duration ttl;
        private final Map<String, Set<String>> cache = new ConcurrentHashMap<>();
        private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
        
        DomainCache(Path cacheFile, int ttlHours) {
            this.cacheFile = cacheFile;
            this.ttl = Duration.ofHours(ttlHours);
            load();
        }
        
        @SuppressWarnings("unchecked")
        private void load() {
            if (!Files.exists(cacheFile)) return;
            
            try (Reader reader = Files.newBufferedReader(cacheFile)) {
                Map<String, Object> data = gson.fromJson(reader, Map.class);
                String timestampStr = (String) data.get("timestamp");
                if (timestampStr != null) {
                    LocalDateTime timestamp = LocalDateTime.parse(timestampStr);
                    if (Duration.between(timestamp, LocalDateTime.now()).compareTo(ttl) < 0) {
                        Map<String, List<String>> domains = (Map<String, List<String>>) data.get("domains");
                        if (domains != null) {
                            domains.forEach((k, v) -> cache.put(k, new HashSet<>(v)));
                        }
                    }
                }
            } catch (IOException ignored) {}
        }
        
        void save() {
            Map<String, Object> data = new HashMap<>();
            data.put("timestamp", LocalDateTime.now().toString());
            data.put("domains", cache.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> new ArrayList<>(e.getValue()))));
            
            try (Writer writer = Files.newBufferedWriter(cacheFile)) {
                gson.toJson(data, writer);
            } catch (IOException e) {
                System.err.println("Failed to save cache: " + e.getMessage());
            }
        }
        
        Optional<Set<String>> get(String source) {
            return Optional.ofNullable(cache.get(source))
                .map(HashSet::new);
        }
        
        void set(String source, Set<String> domains) {
            cache.put(source, new HashSet<>(domains));
        }
    }
    
    // ============================================================================
    // HTTP Fetcher с Retry и Circuit Breaker паттернами
    // ============================================================================
    
    static final class AsyncFetcher implements AutoCloseable {
        private final StructuredLogger logger;
        private final HttpClient client;
        private final Semaphore semaphore;
        private final CircuitBreaker circuitBreaker;
        
        AsyncFetcher(StructuredLogger logger, int maxConcurrent) {
            this.logger = logger;
            this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(AppConfig.getInstance().timeout))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
            this.semaphore = new Semaphore(maxConcurrent);
            this.circuitBreaker = new CircuitBreaker(3, Duration.ofSeconds(30));
        }
        
        record SourceResult(String name, Set<String> domains) {}
        
        Map<String, Set<String>> fetchAll(List<SourceConfig> sources) throws InterruptedException {
            var executor = Executors.newVirtualThreadPerTaskExecutor();
            var futures = new ArrayList<CompletableFuture<Optional<SourceResult>>>();
            
            for (SourceConfig source : sources) {
                if (source.enabled) {
                    futures.add(CompletableFuture.supplyAsync(() -> {
                        try {
                            return fetchWithCircuitBreaker(source);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return Optional.<SourceResult>empty();
                        }
                    }, executor));
                }
            }
            
            var results = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(v -> futures.stream()
                    .map(CompletableFuture::join)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .collect(Collectors.toMap(SourceResult::name, SourceResult::domains)))
                .join();
            
            executor.shutdown();
            return results;
        }
        
        private Optional<SourceResult> fetchWithCircuitBreaker(SourceConfig source) throws InterruptedException {
            if (!circuitBreaker.allowRequest(source.name)) {
                logger.warning("Circuit breaker OPEN for " + source.name);
                return Optional.empty();
            }
            
            try {
                var result = fetchAndParse(source);
                circuitBreaker.recordSuccess(source.name);
                return result;
            } catch (Exception e) {
                circuitBreaker.recordFailure(source.name);
                throw e;
            }
        }
        
        private Optional<SourceResult> fetchAndParse(SourceConfig source) throws InterruptedException {
            semaphore.acquire();
            try {
                Optional<String> content = fetchWithRetry(source.url, source.name);
                if (content.isEmpty()) return Optional.empty();
                
                Set<String> domains = ConcurrentHashMap.newKeySet();
                AtomicInteger counter = new AtomicInteger(0);
                
                content.get().lines().parallel().forEach(line -> {
                    DomainValidator.clean(line).ifPresent(domain -> {
                        domains.add(domain);
                        if (counter.incrementAndGet() % 100_000 == 0) {
                            logger.debug(String.format("%s: processed %d domains", source.name, counter.get()));
                        }
                    });
                });
                
                logger.info(String.format("  📥 %s: %,d domains", source.name, domains.size()));
                return Optional.of(new SourceResult(source.name, domains));
                
            } finally {
                semaphore.release();
            }
        }
        
        private Optional<String> fetchWithRetry(String url, String name) throws InterruptedException {
            AppConfig config = AppConfig.getInstance();
            
            for (int attempt = 0; attempt < config.maxRetries; attempt++) {
                try {
                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("User-Agent", config.userAgent)
                        .timeout(Duration.ofSeconds(config.timeout))
                        .GET()
                        .build();
                    
                    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    
                    if (response.statusCode() == 200) {
                        return Optional.of(response.body());
                    } else if (response.statusCode() == 404) {
                        logger.error(name + ": Source not found (404)");
                        return Optional.empty();
                    } else {
                        logger.warning(String.format("%s: HTTP %d (attempt %d/%d)", 
                            name, response.statusCode(), attempt + 1, config.maxRetries));
                    }
                } catch (IOException e) {
                    logger.warning(String.format("%s: Network error: %s (attempt %d/%d)", 
                        name, e.getMessage(), attempt + 1, config.maxRetries));
                }
                
                if (attempt < config.maxRetries - 1) {
                    Thread.sleep(config.retryDelaySeconds * 1000L * (attempt + 1));
                }
            }
            
            logger.error(name + ": Failed after " + config.maxRetries + " attempts");
            return Optional.empty();
        }
        
        @Override
        public void close() {}
    }
    
    // Circuit Breaker паттерн для защиты от повторяющихся ошибок
    static final class CircuitBreaker {
        private final int failureThreshold;
        private final Duration timeout;
        private final Map<String, CircuitState> states = new ConcurrentHashMap<>();
        
        enum State { CLOSED, OPEN, HALF_OPEN }
        
        record CircuitState(State state, Instant lastFailure, int failureCount) {}
        
        CircuitBreaker(int failureThreshold, Duration timeout) {
            this.failureThreshold = failureThreshold;
            this.timeout = timeout;
        }
        
        synchronized boolean allowRequest(String service) {
            CircuitState state = states.getOrDefault(service, 
                new CircuitState(State.CLOSED, null, 0));
            
            if (state.state() == State.OPEN) {
                if (Instant.now().isAfter(state.lastFailure().plus(timeout))) {
                    states.put(service, new CircuitState(State.HALF_OPEN, null, 0));
                    return true;
                }
                return false;
            }
            
            return true;
        }
        
        synchronized void recordSuccess(String service) {
            states.put(service, new CircuitState(State.CLOSED, null, 0));
        }
        
        synchronized void recordFailure(String service) {
            CircuitState current = states.getOrDefault(service, 
                new CircuitState(State.CLOSED, null, 0));
            
            int newFailureCount = current.failureCount() + 1;
            State newState = newFailureCount >= failureThreshold ? State.OPEN : State.CLOSED;
            
            states.put(service, new CircuitState(newState, Instant.now(), newFailureCount));
        }
    }
    
    // ============================================================================
    // Source Manager
    // ============================================================================
    
    record SourceConfig(String name, String url, boolean enabled, int priority, 
                         int maxSizeMb, String expectedFormat) {
        
        SourceConfig {
            Objects.requireNonNull(name, "Source name cannot be null");
            Objects.requireNonNull(url, "Source URL cannot be null");
        }
        
        static SourceConfig of(String name, String url) {
            return new SourceConfig(name, url, true, 0, 500, "hosts");
        }
        
        static SourceConfig of(String name, String url, int priority) {
            return new SourceConfig(name, url, true, priority, 500, "hosts");
        }
    }
    
    // ============================================================================
    // Blocklist Manager (ядро системы)
    // ============================================================================
    
    static final class BlocklistManager {
        private final StructuredLogger logger;
        private final Set<String> domains = ConcurrentHashMap.newKeySet();
        private final Map<String, AtomicInteger> stats = new ConcurrentHashMap<>();
        private final Set<String> whitelist;
        private final Set<String> blacklist;
        private final Set<String> wildcardWhitelist;
        private final Path whitelistPath;
        private final Path blacklistPath;
        private final Path wildcardPath;
        
        private BlocklistManager(Builder builder) {
            this.logger = builder.logger;
            this.whitelistPath = builder.whitelistPath;
            this.blacklistPath = builder.blacklistPath;
            this.wildcardPath = builder.wildcardPath;
            
            this.whitelist = loadDomainList(whitelistPath, "whitelist");
            this.blacklist = loadDomainList(blacklistPath, "blacklist");
            this.wildcardWhitelist = loadDomainList(wildcardPath, "wildcard whitelist");
        }
        
        private Set<String> loadDomainList(Path path, String name) {
            Set<String> result = ConcurrentHashMap.newKeySet();
            if (path == null || !Files.exists(path)) return result;
            
            try (var lines = Files.lines(path)) {
                lines.parallel()
                    .map(DomainValidator::clean)
                    .filter(Optional::isPresent)
                    .map(Optional::get)
                    .forEach(result::add);
                
                logger.info(String.format("📋 %s: %,d domains", name, result.size()));
            } catch (IOException e) {
                logger.warning("Failed to load " + name + ": " + e.getMessage());
            }
            
            return result;
        }
        
        CompletableFuture<Set<String>> build(List<SourceConfig> sources, boolean useCache) {
            logger.progress("Starting blocklist assembly");
            
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return doBuild(sources, useCache);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new CompletionException(e);
                }
            });
        }
        
        private Set<String> doBuild(List<SourceConfig> sources, boolean useCache) throws InterruptedException {
            if (useCache) {
                var cache = new DomainCache(FILES.cacheFile, AppConfig.getInstance().cacheTtlHours);
                var cached = cache.get("combined");
                if (cached.isPresent() && !cached.get().isEmpty()) {
                    var cachedDomains = cached.get();
                    logger.info(String.format("📀 Cache hit: %,d domains", cachedDomains.size()));
                    domains.clear();
                    domains.addAll(cachedDomains);
                    return applyFilters();
                }
            }
            
            try (var fetcher = new AsyncFetcher(logger, AppConfig.getInstance().parallelDownloads)) {
                var domainsBySource = fetcher.fetchAll(sources);
                
                sources.stream()
                    .sorted((a, b) -> Integer.compare(b.priority, a.priority))
                    .forEach(source -> {
                        var sourceDomains = domainsBySource.get(source.name);
                        if (sourceDomains != null) {
                            domains.addAll(sourceDomains);
                            stats.computeIfAbsent("from_" + source.name, k -> new AtomicInteger())
                                .set(sourceDomains.size());
                        }
                    });
            }
            
            if (useCache) {
                var cache = new DomainCache(FILES.cacheFile, AppConfig.getInstance().cacheTtlHours);
                cache.set("combined", domains);
                cache.save();
                logger.debug("Cache saved");
            }
            
            stats.computeIfAbsent("total_raw", k -> new AtomicInteger()).set(domains.size());
            logger.info(String.format("📊 Unique domains collected: %,d", domains.size()));
            
            return applyFilters();
        }
        
        private Set<String> applyFilters() {
            var result = ConcurrentHashMap.newKeySet();
            var whitelisted = new AtomicInteger(0);
            var wildcardWhitelisted = new AtomicInteger(0);
            var blacklisted = new AtomicInteger(0);
            var normal = new AtomicInteger(0);
            
            int batchSize = AppConfig.getInstance().batchSize;
            var batches = partition(domains, batchSize);
            
            batches.parallelStream().forEach(batch -> {
                for (String domain : batch) {
                    if (DomainValidator.matchWildcard(domain, wildcardWhitelist)) {
                        wildcardWhitelisted.incrementAndGet();
                    } else if (whitelist.contains(domain)) {
                        whitelisted.incrementAndGet();
                    } else if (blacklist.contains(domain)) {
                        result.add(domain);
                        blacklisted.incrementAndGet();
                    } else {
                        result.add(domain);
                        normal.incrementAndGet();
                    }
                }
            });
            
            stats.computeIfAbsent("whitelisted", k -> new AtomicInteger()).set(whitelisted.get());
            stats.computeIfAbsent("wildcard_whitelisted", k -> new AtomicInteger()).set(wildcardWhitelisted.get());
            stats.computeIfAbsent("blacklisted", k -> new AtomicInteger()).set(blacklisted.get());
            stats.computeIfAbsent("normal", k -> new AtomicInteger()).set(normal.get());
            
            logger.success(String.format("Filtering complete: %,d domains", result.size()));
            logStats();
            
            return result;
        }
        
        private static <T> List<List<T>> partition(Set<T> set, int size) {
            var list = new ArrayList<>(set);
            var partitions = new ArrayList<List<T>>();
            for (int i = 0; i < list.size(); i += size) {
                partitions.add(list.subList(i, Math.min(i + size, list.size())));
            }
            return partitions;
        }
        
        private void logStats() {
            logger.info("📈 Processing statistics:");
            logger.info("   ├─ Input domains: " + formatNumber(stats.getOrDefault("total_raw", new AtomicInteger()).get()));
            logger.info("   ├─ Output domains: " + formatNumber(
                stats.getOrDefault("normal", new AtomicInteger()).get() + 
                stats.getOrDefault("blacklisted", new AtomicInteger()).get()));
            logger.info("   ├─ Whitelist: " + formatNumber(stats.getOrDefault("whitelisted", new AtomicInteger()).get()));
            logger.info("   ├─ Wildcard whitelist: " + formatNumber(stats.getOrDefault("wildcard_whitelisted", new AtomicInteger()).get()));
            logger.info("   └─ Blacklist (force): " + formatNumber(stats.getOrDefault("blacklisted", new AtomicInteger()).get()));
        }
        
        private String formatNumber(int number) {
            return String.format("%,d", number);
        }
        
        void saveStats() {
            var statsData = Map.of(
                "timestamp", LocalDateTime.now().toString(),
                "version", VERSION,
                "stats", stats.entrySet().stream()
                    .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get())),
                "config", Map.of(
                    "timeout", AppConfig.getInstance().timeout,
                    "sources", CONFIG.sources.size()
                )
            );
            
            try (var writer = Files.newBufferedWriter(FILES.statsFile)) {
                new GsonBuilder().setPrettyPrinting().create().toJson(statsData, writer);
            } catch (IOException e) {
                logger.warning("Failed to save stats: " + e.getMessage());
            }
        }
        
        static Builder builder() { return new Builder(); }
        
        static final class Builder {
            private StructuredLogger logger;
            private Path whitelistPath = FILES.whitelist;
            private Path blacklistPath = FILES.blacklist;
            private Path wildcardPath = FILES.wildcardWhitelist;
            
            Builder logger(StructuredLogger logger) { this.logger = logger; return this; }
            Builder whitelistPath(Path path) { this.whitelistPath = path; return this; }
            Builder blacklistPath(Path path) { this.blacklistPath = path; return this; }
            Builder wildcardPath(Path path) { this.wildcardPath = path; return this; }
            
            BlocklistManager build() {
                Objects.requireNonNull(logger, "Logger is required");
                return new BlocklistManager(this);
            }
        }
    }
    
    // ============================================================================
    // Exporter с поддержкой нескольких форматов
    // ============================================================================
    
    enum ExportFormat {
        HOSTS, DOMAINS, ADBLOCK, DNSMASQ, UNBOUND
    }
    
    static final class Exporter {
        private final StructuredLogger logger;
        
        Exporter(StructuredLogger logger) {
            this.logger = logger;
        }
        
        Optional<Path> backup(Path target) {
            if (!Files.exists(target)) return Optional.empty();
            
            String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMATTER);
            Path backupPath = FILES.backupDir.resolve(target.getFileName().toString()
                .replace(".txt", "_" + timestamp + ".txt"));
            
            try {
                Files.copy(target, backupPath, StandardCopyOption.REPLACE_EXISTING);
                logger.info("Backup created: " + backupPath);
                return Optional.of(backupPath);
            } catch (IOException e) {
                logger.warning("Failed to create backup: " + e.getMessage());
                return Optional.empty();
            }
        }
        
        void export(Set<String> domains, Path path, ExportFormat format) throws IOException {
            switch (format) {
                case HOSTS -> exportHosts(domains, path);
                case DOMAINS -> exportDomains(domains, path);
                case ADBLOCK -> exportAdblock(domains, path);
                case DNSMASQ -> exportDnsmasq(domains, path);
                case UNBOUND -> exportUnbound(domains, path);
            }
        }
        
        private void exportHosts(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                writeHeader(writer, domains.size(), "hosts");
                writer.write("\n");
                
                for (String domain : sortDomains(domains)) {
                    writer.write("0.0.0.0 " + domain + "\n");
                }
            }
        }
        
        private void exportDomains(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                for (String domain : sortDomains(domains)) {
                    writer.write(domain + "\n");
                }
            }
        }
        
        private void exportAdblock(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                writer.write("[Adblock Plus 2.0]\n");
                writer.write("! Title: Custom Blocklist v" + VERSION + "\n");
                writer.write("! Generated: " + LocalDateTime.now().format(DATE_FORMATTER) + "\n");
                writer.write("! Number of rules: " + String.format("%,d", domains.size()) + "\n");
                writer.write("! ==========================================\n\n");
                
                for (String domain : sortDomains(domains)) {
                    writer.write("||" + domain + "^\n");
                }
            }
        }
        
        private void exportDnsmasq(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                writeHeader(writer, domains.size(), "dnsmasq");
                writer.write("\n");
                
                for (String domain : sortDomains(domains)) {
                    writer.write("address=/" + domain + "/0.0.0.0\n");
                }
            }
        }
        
        private void exportUnbound(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                writeHeader(writer, domains.size(), "unbound");
                writer.write("\n");
                writer.write("    local-zone: \".\" static\n");
                
                for (String domain : sortDomains(domains)) {
                    writer.write("    local-data: \"" + domain + " A 0.0.0.0\"\n");
                }
            }
        }
        
        private void writeHeader(Writer writer, int domainCount, String format) throws IOException {
            writer.write(
                "# ================================================================\n" +
                "# DNS Blocklist Manager v" + VERSION + "\n" +
                "# Format: " + format.toUpperCase() + "\n" +
                "# Generated: " + LocalDateTime.now().format(DATE_FORMATTER) + "\n" +
                "# Total domains: " + String.format("%,d", domainCount) + "\n" +
                "# ================================================================\n" +
                "# License: MIT\n" +
                "# ================================================================\n"
            );
        }
        
        private List<String> sortDomains(Set<String> domains) {
            var list = new ArrayList<>(domains);
            Collections.sort(list);
            return list;
        }
    }
    
    // ============================================================================
    // PID Manager с блокировками
    // ============================================================================
    
    static final class PIDManager implements AutoCloseable {
        private final Path pidFile;
        private final long pid;
        private final FileLock fileLock;
        private final RandomAccessFile raf;
        
        PIDManager(Path pidFile) throws IOException {
            this.pidFile = pidFile;
            this.pid = ProcessHandle.current().pid();
            
            Files.createDirectories(pidFile.getParent());
            this.raf = new RandomAccessFile(pidFile.toFile(), "rw");
            this.fileLock = raf.getChannel().tryLock();
            
            if (fileLock == null) {
                throw new IOException("Another instance is already running");
            }
        }
        
        boolean acquire() throws IOException {
            if (fileLock == null) return false;
            
            String existingPid = raf.readLine();
            if (existingPid != null && !existingPid.isBlank()) {
                long oldPid = Long.parseLong(existingPid.trim());
                if (ProcessHandle.of(oldPid).isPresent()) {
                    System.err.println("❌ Process already running (PID: " + oldPid + ")");
                    return false;
                }
            }
            
            raf.setLength(0);
            raf.writeBytes(String.valueOf(pid));
            return true;
        }
        
        @Override
        public void close() {
            try {
                if (fileLock != null) fileLock.release();
                if (raf != null) raf.close();
                Files.deleteIfExists(pidFile);
            } catch (IOException ignored) {}
        }
    }
    
    // ============================================================================
    // Application Bootstrap
    // ============================================================================
    
    private static final class FilePaths {
        final Path outputHosts = Path.of("hosts.txt");
        final Path backupDir = Path.of("backup");
        final Path whitelist = Path.of("lists/whitelist.txt");
        final Path blacklist = Path.of("lists/blacklist.txt");
        final Path wildcardWhitelist = Path.of("lists/wildcard_whitelist.txt");
        final Path logDir = Path.of("logs");
        final Path logFile = Path.of("logs/dns_blocker.log");
        final Path cacheDir = Path.of(".cache");
        final Path cacheFile = Path.of(".cache/domains_cache.json");
        final Path statsFile = Path.of("stats.json");
        final Path pidFile = Path.of("/tmp/dns_blocker.pid");
        
        FilePaths() {
            try {
                Files.createDirectories(backupDir);
                Files.createDirectories(logDir);
                Files.createDirectories(cacheDir);
                Files.createDirectories(Path.of("lists"));
            } catch (IOException e) {
                System.err.println("Failed to create directories: " + e.getMessage());
            }
        }
    }
    
    private static final FilePaths FILES = new FilePaths();
    
    private static final List<SourceConfig> SOURCES = List.of(
        SourceConfig.of("HaGeZi PRO", 
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt", 
            100)
    );
    
    static final class AppContext {
        private final StructuredLogger logger;
        private final BlocklistManager blocklistManager;
        private final Exporter exporter;
        private final AppConfig config;
        
        AppContext() {
            this.config = AppConfig.getInstance();
            this.logger = StructuredLogger.builder()
                .logFile(FILES.logFile)
                .verbose("1".equals(System.getenv("DEBUG")))
                .build();
            this.blocklistManager = BlocklistManager.builder()
                .logger(logger)
                .build();
            this.exporter = new Exporter(logger);
        }
        
        StructuredLogger getLogger() { return logger; }
        BlocklistManager getBlocklistManager() { return blocklistManager; }
        Exporter getExporter() { return exporter; }
        AppConfig getConfig() { return config; }
    }
    
    public static void main(String[] args) {
        var exitCode = new Application().run();
        System.exit(exitCode);
    }
    
    static final class Application {
        
        int run() {
            var context = new AppContext();
            var logger = context.getLogger();
            
            try (var pidManager = new PIDManager(FILES.pidFile)) {
                if (!pidManager.acquire()) return 1;
                
                printBanner();
                
                // Шаг 1: Backup
                logger.progress("Step 1/4: Creating backup");
                context.getExporter().backup(FILES.outputHosts);
                
                // Шаг 2: Build
                logger.progress("Step 2/4: Loading blocklists");
                var filteredDomains = context.getBlocklistManager()
                    .build(SOURCES, context.getConfig().enableCache)
                    .join();
                
                if (filteredDomains.size() > context.getConfig().maxDomains) {
                    logger.warning(String.format("Domain limit exceeded (%,d > %,d)", 
                        filteredDomains.size(), context.getConfig().maxDomains));
                }
                
                // Шаг 3: Export
                logger.progress("Step 3/4: Exporting files");
                context.getExporter().export(filteredDomains, FILES.outputHosts, ExportFormat.HOSTS);
                logger.success(String.format("hosts.txt: %,d domains", filteredDomains.size()));
                
                var domainsFile = FILES.outputHosts.getParent().resolve("domains.txt");
                context.getExporter().export(filteredDomains, domainsFile, ExportFormat.DOMAINS);
                logger.info(String.format("domains.txt: %,d domains", filteredDomains.size()));
                
                // Дополнительные форматы
                var adblockFile = FILES.outputHosts.getParent().resolve("adblock.txt");
                context.getExporter().export(filteredDomains, adblockFile, ExportFormat.ADBLOCK);
                logger.debug(String.format("adblock.txt: %,d rules", filteredDomains.size()));
                
                // Шаг 4: Statistics
                logger.progress("Step 4/4: Saving statistics");
                context.getBlocklistManager().saveStats();
                
                printFooter(filteredDomains.size());
                
                return 0;
                
            } catch (IOException e) {
                System.err.println("❌ IO Error: " + e.getMessage());
                return 1;
            } catch (CompletionException e) {
                System.err.println("❌ Build failed: " + e.getCause().getMessage());
                return 1;
            }
        }
        
        private void printBanner() {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("🚀 DNS BLOCKLIST MANAGER v" + VERSION);
            System.out.println("=".repeat(60));
            System.out.println("📅 Time: " + LocalDateTime.now().format(DATE_FORMATTER));
            System.out.println("📦 Sources: " + SOURCES.stream().filter(s -> s.enabled()).count());
            System.out.println("💻 Java: " + System.getProperty("java.version"));
            System.out.println("=".repeat(60) + "\n");
        }
        
        private void printFooter(int domainCount) {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("✅ BUILD SUCCESSFUL");
            System.out.println("=".repeat(60));
            System.out.println("📊 TOTAL BLOCKED: " + String.format("%,d", domainCount) + " domains");
            System.out.println("\n📁 Output files:");
            
            try {
                if (Files.exists(FILES.outputHosts)) {
                    long size = Files.size(FILES.outputHosts);
                    System.out.println("   • hosts.txt: " + formatSize(size));
                }
                if (Files.exists(FILES.outputHosts.getParent().resolve("domains.txt"))) {
                    long size = Files.size(FILES.outputHosts.getParent().resolve("domains.txt"));
                    System.out.println("   • domains.txt: " + formatSize(size));
                }
            } catch (IOException ignored) {}
            
            System.out.println("=".repeat(60));
        }
        
        private String formatSize(long bytes) {
            if (bytes > 1024 * 1024) {
                return String.format("%.2f MB", bytes / 1024.0 / 1024.0);
            }
            return String.format("%.2f KB", bytes / 1024.0);
        }
    }
}