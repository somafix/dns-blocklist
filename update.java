// DNSBlocklistManager.java - Production-Ready Elite Edition
//

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
import java.util.stream.Collectors;

/**
 * DNS Blocklist Manager - Production Elite Edition
 * 
 * @version 1.0.0
 */
public final class DNSBlocklistManager {
    
    private static final String VERSION = "1.0.0-elite";
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    // ============================================================================
    // Конфигурация
    // ============================================================================
    
    private static final class Config {
        static final int TIMEOUT_SECONDS = 30;
        static final int MAX_RETRIES = 3;
        static final int PARALLEL_DOWNLOADS = 5;
        static final int CACHE_TTL_HOURS = 24;
        static final int MAX_DOMAINS = 10_000_000;
        static final String USER_AGENT = "DNS-Blocklist-Manager/" + VERSION;
        
        static Config get() { return Holder.INSTANCE; }
        private static final class Holder { static final Config INSTANCE = new Config(); }
    }
    
    // ============================================================================
    // Структуры данных
    // ============================================================================
    
    record Source(String name, String url, int priority) {}
    
    private static final List<Source> SOURCES = List.of(
        new Source("HaGeZi PRO", 
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt", 
            100)
    );
    
    // ============================================================================
    // Пути
    // ============================================================================
    
    private static final Path OUTPUT_HOSTS = Path.of("hosts.txt");
    private static final Path OUTPUT_DOMAINS = Path.of("domains.txt");
    private static final Path BACKUP_DIR = Path.of("backup");
    private static final Path CACHE_FILE = Path.of(".cache/domains.txt");
    private static final Path STATS_FILE = Path.of("stats.json");
    private static final Path LISTS_DIR = Path.of("lists");
    private static final Path WHITELIST = LISTS_DIR.resolve("whitelist.txt");
    private static final Path BLACKLIST = LISTS_DIR.resolve("blacklist.txt");
    private static final Path WILDCARD_WHITELIST = LISTS_DIR.resolve("wildcard_whitelist.txt");
    
    // ============================================================================
    // Валидатор доменов
    // ============================================================================
    
    private static final class DomainValidator {
        private static final Pattern IPV4_PATTERN = Pattern.compile("^\\d+(\\.\\d+){3}$");
        private static final Pattern VALID_DOMAIN = Pattern.compile("^[a-z0-9][a-z0-9.-]*[a-z0-9]$");
        
        static String clean(String line) {
            if (line == null || line.isBlank()) return null;
            
            // Удаляем комментарии
            int comment = line.indexOf('#');
            if (comment != -1) line = line.substring(0, comment);
            
            line = line.trim().toLowerCase();
            if (line.isEmpty()) return null;
            
            // Удаляем префиксы
            if (line.startsWith("0.0.0.0 ")) line = line.substring(8);
            if (line.startsWith("127.0.0.1 ")) line = line.substring(10);
            if (line.startsWith("||")) line = line.substring(2);
            if (line.endsWith("^")) line = line.substring(0, line.length() - 1);
            if (line.startsWith("http://") || line.startsWith("https://")) {
                line = line.substring(line.indexOf("://") + 3);
                int slash = line.indexOf('/');
                if (slash != -1) line = line.substring(0, slash);
            }
            
            line = line.trim();
            if (line.isEmpty()) return null;
            
            // Проверка на IP
            if (IPV4_PATTERN.matcher(line).matches()) return null;
            
            // Проверка на валидный домен
            if (line.length() > 253) return null;
            if (line.startsWith(".") || line.endsWith(".")) return null;
            if (line.contains("..")) return null;
            if (!VALID_DOMAIN.matcher(line).matches()) return null;
            
            return line;
        }
        
        static boolean matchWildcard(String domain, Set<String> patterns) {
            for (String pattern : patterns) {
                if (pattern.endsWith("*")) {
                    if (domain.startsWith(pattern.substring(0, pattern.length() - 1))) return true;
                } else if (pattern.startsWith("*")) {
                    if (domain.endsWith(pattern.substring(1))) return true;
                } else if (pattern.contains("*")) {
                    String regex = pattern.replace(".", "\\.").replace("*", ".*");
                    if (Pattern.compile(regex).matcher(domain).matches()) return true;
                } else if (domain.equals(pattern)) {
                    return true;
                }
            }
            return false;
        }
    }
    
    // ============================================================================
    // Загрузчик с retry
    // ============================================================================
    
    private static final class Fetcher {
        private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(Config.TIMEOUT_SECONDS))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
        
        Optional<String> fetch(String url, String name) {
            for (int attempt = 1; attempt <= Config.MAX_RETRIES; attempt++) {
                try {
                    var request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("User-Agent", Config.USER_AGENT)
                        .timeout(Duration.ofSeconds(Config.TIMEOUT_SECONDS))
                        .GET()
                        .build();
                    
                    var response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    
                    if (response.statusCode() == 200) {
                        return Optional.of(response.body());
                    } else if (response.statusCode() == 404) {
                        System.err.println("  ❌ " + name + ": 404 Not Found");
                        return Optional.empty();
                    } else {
                        System.err.println("  ⚠️ " + name + ": HTTP " + response.statusCode() + 
                            " (attempt " + attempt + "/" + Config.MAX_RETRIES + ")");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Optional.empty();
                } catch (Exception e) {
                    System.err.println("  ⚠️ " + name + ": " + e.getMessage() + 
                        " (attempt " + attempt + "/" + Config.MAX_RETRIES + ")");
                }
                
                if (attempt < Config.MAX_RETRIES) {
                    try { Thread.sleep(2000L * attempt); } catch (InterruptedException e) { break; }
                }
            }
            
            System.err.println("  ❌ " + name + ": Failed after " + Config.MAX_RETRIES + " attempts");
            return Optional.empty();
        }
    }
    
    // ============================================================================
    // Менеджер блоклиста
    // ============================================================================
    
    private static final class BlocklistBuilder {
        private final Set<String> domains = ConcurrentHashMap.newKeySet();
        private final Map<String, Integer> stats = new ConcurrentHashMap<>();
        
        private Set<String> loadUserList(Path path) {
            Set<String> result = new HashSet<>();
            if (!Files.exists(path)) return result;
            
            try (var lines = Files.lines(path)) {
                lines.map(DomainValidator::clean)
                     .filter(Objects::nonNull)
                     .forEach(result::add);
                System.out.println("  📋 " + path.getFileName() + ": " + result.size() + " domains");
            } catch (IOException e) {
                System.err.println("  ⚠️ Failed to load " + path + ": " + e.getMessage());
            }
            return result;
        }
        
        Set<String> build(List<Source> sources, boolean useCache) throws Exception {
            System.out.println("\n📊 Building blocklist...");
            
            // Загружаем пользовательские списки
            var whitelist = loadUserList(WHITELIST);
            var blacklist = loadUserList(BLACKLIST);
            var wildcardWhitelist = loadUserList(WILDCARD_WHITELIST);
            
            // Проверяем кэш
            Set<String> cached = null;
            if (useCache && Files.exists(CACHE_FILE)) {
                long cacheAge = System.currentTimeMillis() - Files.getLastModifiedTime(CACHE_FILE).toMillis();
                if (cacheAge < TimeUnit.HOURS.toMillis(Config.CACHE_TTL_HOURS)) {
                    cached = loadCache();
                    if (cached != null && !cached.isEmpty()) {
                        System.out.println("  📀 Cache hit: " + String.format("%,d", cached.size()) + " domains");
                        domains.addAll(cached);
                    }
                }
            }
            
            // Загружаем источники
            if (cached == null || cached.isEmpty()) {
                System.out.println("  🌐 Downloading sources...");
                var executor = Executors.newVirtualThreadPerTaskExecutor();
                var futures = new ArrayList<CompletableFuture<Void>>();
                
                for (Source source : sources) {
                    futures.add(CompletableFuture.runAsync(() -> {
                        var fetcher = new Fetcher();
                        var content = fetcher.fetch(source.url, source.name);
                        
                        if (content.isPresent()) {
                            int count = processContent(content.get(), domains);
                            stats.put(source.name, count);
                            System.out.println("  📥 " + source.name + ": " + String.format("%,d", count) + " domains");
                        }
                    }, executor));
                }
                
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
                executor.shutdown();
                
                // Сохраняем кэш
                if (useCache && !domains.isEmpty()) {
                    saveCache(domains);
                    System.out.println("  💾 Cache saved: " + String.format("%,d", domains.size()) + " domains");
                }
            }
            
            stats.put("total_raw", domains.size());
            System.out.println("  📊 Unique before filter: " + String.format("%,d", domains.size()));
            
            // Применяем фильтры
            var result = new HashSet<String>();
            int whitelisted = 0, wildcarded = 0, blacklisted = 0;
            
            for (String domain : domains) {
                if (DomainValidator.matchWildcard(domain, wildcardWhitelist)) {
                    wildcarded++;
                } else if (whitelist.contains(domain)) {
                    whitelisted++;
                } else if (blacklist.contains(domain)) {
                    result.add(domain);
                    blacklisted++;
                } else {
                    result.add(domain);
                }
            }
            
            stats.put("whitelisted", whitelisted);
            stats.put("wildcard_whitelisted", wildcarded);
            stats.put("blacklisted", blacklisted);
            stats.put("normal", result.size() - blacklisted);
            
            System.out.println("\n📈 Statistics:");
            System.out.println("  ├─ Input:  " + String.format("%,d", stats.get("total_raw")));
            System.out.println("  ├─ Output: " + String.format("%,d", result.size()));
            System.out.println("  ├─ Whitelist: " + String.format("%,d", whitelisted));
            System.out.println("  ├─ Wildcard: " + String.format("%,d", wildcarded));
            System.out.println("  └─ Blacklist: " + String.format("%,d", blacklisted));
            
            return result;
        }
        
        private int processContent(String content, Set<String> target) {
            var count = new AtomicInteger(0);
            content.lines().parallel().forEach(line -> {
                var domain = DomainValidator.clean(line);
                if (domain != null) {
                    target.add(domain);
                    count.incrementAndGet();
                }
            });
            return count.get();
        }
        
        @SuppressWarnings("unchecked")
        private Set<String> loadCache() {
            try (var ois = new ObjectInputStream(new BufferedInputStream(Files.newInputStream(CACHE_FILE)))) {
                return (Set<String>) ois.readObject();
            } catch (Exception e) {
                return null;
            }
        }
        
        private void saveCache(Set<String> domains) {
            try {
                Files.createDirectories(CACHE_FILE.getParent());
                try (var oos = new ObjectOutputStream(new BufferedOutputStream(Files.newOutputStream(CACHE_FILE)))) {
                    oos.writeObject(new HashSet<>(domains));
                }
            } catch (IOException e) {
                System.err.println("  ⚠️ Failed to save cache: " + e.getMessage());
            }
        }
        
        void saveStats() {
            var data = Map.of(
                "timestamp", LocalDateTime.now().toString(),
                "version", VERSION,
                "stats", new HashMap<>(stats),
                "config", Map.of("sources", SOURCES.size())
            );
            
            try (var writer = Files.newBufferedWriter(STATS_FILE)) {
                var gson = new com.google.gson.GsonBuilder().setPrettyPrinting().create();
                writer.write(gson.toJson(data));
            } catch (IOException e) {
                System.err.println("  ⚠️ Failed to save stats: " + e.getMessage());
            }
        }
    }
    
    // ============================================================================
    // Экспорт
    // ============================================================================
    
    private static final class Exporter {
        
        void backup() {
            if (!Files.exists(OUTPUT_HOSTS)) return;
            
            try {
                Files.createDirectories(BACKUP_DIR);
                var timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
                var backup = BACKUP_DIR.resolve("hosts_" + timestamp + ".txt");
                Files.copy(OUTPUT_HOSTS, backup, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("  💾 Backup: " + backup.getFileName());
            } catch (IOException e) {
                System.err.println("  ⚠️ Backup failed: " + e.getMessage());
            }
        }
        
        void exportHosts(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                writer.write("# ================================================================\n");
                writer.write("# DNS Blocklist Manager v" + VERSION + "\n");
                writer.write("# Generated: " + LocalDateTime.now().format(DATE_FORMATTER) + "\n");
                writer.write("# Total domains: " + String.format("%,d", domains.size()) + "\n");
                writer.write("# ================================================================\n\n");
                
                var sorted = new ArrayList<>(domains);
                Collections.sort(sorted);
                
                for (String domain : sorted) {
                    writer.write("0.0.0.0 " + domain + "\n");
                }
            }
        }
        
        void exportDomains(Set<String> domains, Path path) throws IOException {
            try (var writer = Files.newBufferedWriter(path)) {
                var sorted = new ArrayList<>(domains);
                Collections.sort(sorted);
                for (String domain : sorted) {
                    writer.write(domain + "\n");
                }
            }
        }
    }
    
    // ============================================================================
    // PID Manager
    // ============================================================================
    
    private static final class PIDManager implements AutoCloseable {
        private final Path pidFile = Path.of("/tmp/dns_blocker_" + System.getProperty("user.name") + ".pid");
        private final long pid = ProcessHandle.current().pid();
        
        boolean acquire() throws IOException {
            Files.createDirectories(pidFile.getParent());
            
            if (Files.exists(pidFile)) {
                var existingPid = Files.readString(pidFile).trim();
                if (!existingPid.isEmpty()) {
                    try {
                        long oldPid = Long.parseLong(existingPid);
                        if (ProcessHandle.of(oldPid).isPresent()) {
                            System.err.println("❌ Already running (PID: " + oldPid + ")");
                            return false;
                        }
                    } catch (NumberFormatException ignored) {}
                }
            }
            
            Files.writeString(pidFile, String.valueOf(pid));
            return true;
        }
        
        @Override
        public void close() {
            try {
                if (Files.exists(pidFile)) {
                    var current = Files.readString(pidFile).trim();
                    if (current.equals(String.valueOf(pid))) {
                        Files.delete(pidFile);
                    }
                }
            } catch (IOException ignored) {}
        }
    }
    
    // ============================================================================
    // Главный метод
    // ============================================================================
    
    public static void main(String[] args) {
        var exitCode = run();
        System.exit(exitCode);
    }
    
    private static int run() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("🚀 DNS BLOCKLIST MANAGER v" + VERSION);
        System.out.println("=".repeat(60));
        System.out.println("📅 Time: " + LocalDateTime.now().format(DATE_FORMATTER));
        System.out.println("🔧 Java: " + System.getProperty("java.version"));
        System.out.println("💻 CPU: " + Runtime.getRuntime().availableProcessors() + " cores");
        System.out.println("=".repeat(60));
        
        try (var pidManager = new PIDManager()) {
            if (!pidManager.acquire()) return 1;
            
            // Создаём директории
            Files.createDirectories(LISTS_DIR);
            Files.createDirectories(BACKUP_DIR);
            
            // Бэкап
            System.out.println("\n💾 Step 1/4: Backup");
            var exporter = new Exporter();
            exporter.backup();
            
            // Сборка
            System.out.println("\n🌐 Step 2/4: Building blocklist");
            var builder = new BlocklistBuilder();
            var domains = builder.build(SOURCES, true);
            
            if (domains.size() > Config.MAX_DOMAINS) {
                System.err.println("  ⚠️ Warning: " + String.format("%,d", domains.size()) + 
                    " domains exceeds limit " + String.format("%,d", Config.MAX_DOMAINS));
            }
            
            // Экспорт
            System.out.println("\n💾 Step 3/4: Exporting");
            exporter.exportHosts(domains, OUTPUT_HOSTS);
            System.out.println("  ✅ hosts.txt: " + String.format("%,d", domains.size()) + " domains, " +
                formatSize(Files.size(OUTPUT_HOSTS)));
            
            exporter.exportDomains(domains, OUTPUT_DOMAINS);
            System.out.println("  ✅ domains.txt: " + String.format("%,d", domains.size()) + " domains, " +
                formatSize(Files.size(OUTPUT_DOMAINS)));
            
            // Статистика
            System.out.println("\n📊 Step 4/4: Statistics");
            builder.saveStats();
            System.out.println("  ✅ stats.json saved");
            
            // Финальный вывод
            System.out.println("\n" + "=".repeat(60));
            System.out.println("✅ BUILD SUCCESSFUL");
            System.out.println("=".repeat(60));
            System.out.println("📊 TOTAL BLOCKED: " + String.format("%,d", domains.size()) + " domains");
            System.out.println("=".repeat(60));
            
            return 0;
            
        } catch (Exception e) {
            System.err.println("\n❌ ERROR: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
    }
    
    private static String formatSize(long bytes) throws IOException {
        if (bytes > 1024 * 1024) return String.format("%.2f MB", bytes / 1024.0 / 1024.0);
        if (bytes > 1024) return String.format("%.2f KB", bytes / 1024.0);
        return bytes + " B";
    }
}