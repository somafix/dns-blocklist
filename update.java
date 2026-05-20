// DNSBlocklistManager.java - Production-Ready Elite Edition (Refactored)
//

package dns.blocklist;

import com.google.gson.GsonBuilder;

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
 * <p>Manages DNS blocklist sources, applies whitelist/blacklist filters,
 * and exports results in hosts.txt and domains.txt formats.
 * 
 * @version 2.0.0
 */
public final class DNSBlocklistManager {
    
    private static final String VERSION = "2.0.0";
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
        
        private Config() {}
        
        static Config get() { return Holder.INSTANCE; }
        private static final class Holder { 
            static final Config INSTANCE = new Config(); 
        }
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
    private static final Path CACHE_FILE = Path.of(".cache/domains.ser");
    private static final Path STATS_FILE = Path.of("stats.json");
    private static final Path LISTS_DIR = Path.of("lists");
    private static final Path WHITELIST = LISTS_DIR.resolve("whitelist.txt");
    private static final Path BLACKLIST = LISTS_DIR.resolve("blacklist.txt");
    private static final Path WILDCARD_WHITELIST = LISTS_DIR.resolve("wildcard_whitelist.txt");
    
    // ============================================================================
    // Валидатор доменов
    // ============================================================================
    
    private static final class DomainValidator {
        private static final Pattern IPV4_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
        private static final Pattern VALID_DOMAIN = Pattern.compile("^(?!-)[a-z0-9-]{1,63}(\\.[a-z0-9-]{1,63})*\\.?$");
        
        private DomainValidator() {}
        
        static String clean(String line) {
            if (line == null || line.isBlank()) {
                return null;
            }
            
            // Удаляем комментарии
            int comment = line.indexOf('#');
            if (comment != -1) {
                line = line.substring(0, comment);
            }
            
            line = line.trim().toLowerCase();
            if (line.isEmpty()) {
                return null;
            }
            
            // Удаляем префиксы hosts-файла
            if (line.startsWith("0.0.0.0 ") || line.startsWith("127.0.0.1 ")) {
                line = line.substring(line.indexOf(' ') + 1).trim();
            }
            
            // Удаляем префиксы AdBlock формата
            if (line.startsWith("||")) {
                line = line.substring(2);
            }
            if (line.endsWith("^")) {
                line = line.substring(0, line.length() - 1);
            }
            
            // Удаляем протоколы
            if (line.startsWith("http://") || line.startsWith("https://")) {
                line = line.substring(line.indexOf("://") + 3);
                int slash = line.indexOf('/');
                if (slash != -1) {
                    line = line.substring(0, slash);
                }
            }
            
            line = line.trim();
            if (line.isEmpty()) {
                return null;
            }
            
            // Проверка на IP-адрес
            if (IPV4_PATTERN.matcher(line).matches()) {
                return null;
            }
            
            // Проверка на валидный домен
            if (line.length() > 253) {
                return null;
            }
            if (line.startsWith(".") || line.endsWith(".")) {
                return null;
            }
            if (line.contains("..")) {
                return null;
            }
            if (!VALID_DOMAIN.matcher(line).matches()) {
                return null;
            }
            
            return line;
        }
        
        static boolean matchWildcard(String domain, Set<String> patterns) {
            for (String pattern : patterns) {
                if (pattern.contains("*")) {
                    String regex = pattern
                        .replace(".", "\\.")
                        .replace("*", ".*");
                    if (Pattern.matches(regex, domain)) {
                        return true;
                    }
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
                    }
                    
                    if (response.statusCode() == 404) {
                        System.err.println("  ❌ " + name + ": 404 Not Found");
                        return Optional.empty();
                    }
                    
                    System.err.println("  ⚠️ " + name + ": HTTP " + response.statusCode() + 
                        " (attempt " + attempt + "/" + Config.MAX_RETRIES + ")");
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return Optional.empty();
                } catch (Exception e) {
                    System.err.println("  ⚠️ " + name + ": " + e.getMessage() + 
                        " (attempt " + attempt + "/" + Config.MAX_RETRIES + ")");
                }
                
                if (attempt < Config.MAX_RETRIES) {
                    try {
                        Thread.sleep(2000L * attempt);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
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
            if (!Files.exists(path)) {
                return Set.of();
            }
            
            try (var lines = Files.lines(path)) {
                var result = lines
                    .map(DomainValidator::clean)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toSet());
                System.out.println("  📋 " + path.getFileName() + ": " + result.size() + " domains");
                return result;
            } catch (IOException e) {
                System.err.println("  ⚠️ Failed to load " + path + ": " + e.getMessage());
                return Set.of();
            }
        }
        
        Set<String> build(List<Source> sources, boolean useCache) throws Exception {
            System.out.println("\n📊 Building blocklist...");
            
            // Загружаем пользовательские списки
            var whitelist = loadUserList(WHITELIST);
            var blacklist = loadUserList(BLACKLIST);
            var wildcardWhitelist = loadUserList(WILDCARD_WHITELIST);
            
            // Проверяем кэш
            if (useCache && Files.exists(CACHE_FILE) && isCacheValid()) {
                var cached = loadCache();
                if (cached != null && !cached.isEmpty()) {
                    System.out.println("  📀 Cache hit: " + String.format("%,d", cached.size()) + " domains");
                    domains.addAll(cached);
                }
            }
            
            // Загружаем источники, если кэш не использован
            if (domains.isEmpty()) {
                System.out.println("  🌐 Downloading sources...");
                downloadSources(sources);
                
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
            int whitelisted = 0;
            int wildcarded = 0;
            int blacklisted = 0;
            
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
            
            printStatistics(result.size());
            
            return result;
        }
        
        private void downloadSources(List<Source> sources) {
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
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
            }
        }
        
        private boolean isCacheValid() {
            try {
                long cacheAge = System.currentTimeMillis() - Files.getLastModifiedTime(CACHE_FILE).toMillis();
                return cacheAge < TimeUnit.HOURS.toMillis(Config.CACHE_TTL_HOURS);
            } catch (IOException e) {
                return false;
            }
        }
        
        private int processContent(String content, Set<String> target) {
            var count = new AtomicInteger(0);
            content.lines().parallel().forEach(line -> {
                var domain = DomainValidator.clean(line);
                if (domain != null && target.add(domain)) {
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
                System.err.println("  ⚠️ Failed to load cache: " + e.getMessage());
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
        
        private void printStatistics(int finalSize) {
            System.out.println("\n📈 Statistics:");
            System.out.println("  ├─ Input:  " + String.format("%,d", stats.get("total_raw")));
            System.out.println("  ├─ Output: " + String.format("%,d", finalSize));
            System.out.println("  ├─ Whitelist: " + String.format("%,d", stats.getOrDefault("whitelisted", 0)));
            System.out.println("  ├─ Wildcard: " + String.format("%,d", stats.getOrDefault("wildcard_whitelisted", 0)));
            System.out.println("  └─ Blacklist: " + String.format("%,d", stats.getOrDefault("blacklisted", 0)));
        }
        
        void saveStats() {
            var data = Map.of(
                "timestamp", LocalDateTime.now().toString(),
                "version", VERSION,
                "stats", new HashMap<>(stats),
                "config", Map.of("sources", SOURCES.size())
            );
            
            try (var writer = Files.newBufferedWriter(STATS_FILE)) {
                var gson = new GsonBuilder().setPrettyPrinting().create();
                gson.toJson(data, writer);
            } catch (IOException e) {
                System.err.println("  ⚠️ Failed to save stats: " + e.getMessage());
            }
        }
    }
    
    // ============================================================================
    // Экспорт
    // ============================================================================
    
    private static final class Exporter {
        
        void backup() throws IOException {
            if (!Files.exists(OUTPUT_HOSTS)) {
                return;
            }
            
            Files.createDirectories(BACKUP_DIR);
            var timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            var backup = BACKUP_DIR.resolve("hosts_" + timestamp + ".txt");
            Files.copy(OUTPUT_HOSTS, backup, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("  💾 Backup: " + backup.getFileName());
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
        
        String formatSize(long bytes) {
            if (bytes > 1024 * 1024) {
                return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
            }
            if (bytes > 1024) {
                return String.format("%.2f KB", bytes / 1024.0);
            }
            return bytes + " B";
        }
    }
    
    // ============================================================================
    // PID Manager
    // ============================================================================
    
    private static final class PIDManager implements AutoCloseable {
        private final Path pidFile = Path.of(System.getProperty("java.io.tmpdir"), 
            "dns_blocker_" + System.getProperty("user.name") + ".pid");
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
                    } catch (NumberFormatException ignored) {
                        // Invalid PID format, proceed to overwrite
                    }
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
            } catch (IOException ignored) {
                // Best effort cleanup
            }
        }
    }
    
    // ============================================================================
    // Главный метод
    // ============================================================================
    
    public static void main(String[] args) {
        System.exit(run());
    }
    
    private static int run() {
        printHeader();
        
        try (var pidManager = new PIDManager()) {
            if (!pidManager.acquire()) {
                return 1;
            }
            
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
                exporter.formatSize(Files.size(OUTPUT_HOSTS)));
            
            exporter.exportDomains(domains, OUTPUT_DOMAINS);
            System.out.println("  ✅ domains.txt: " + String.format("%,d", domains.size()) + " domains, " +
                exporter.formatSize(Files.size(OUTPUT_DOMAINS)));
            
            // Статистика
            System.out.println("\n📊 Step 4/4: Statistics");
            builder.saveStats();
            System.out.println("  ✅ stats.json saved");
            
            // Финальный вывод
            printFooter(domains.size());
            
            return 0;
            
        } catch (Exception e) {
            System.err.println("\n❌ ERROR: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
    }
    
    private static void printHeader() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("🚀 DNS BLOCKLIST MANAGER v" + VERSION);
        System.out.println("=".repeat(60));
        System.out.println("📅 Time: " + LocalDateTime.now().format(DATE_FORMATTER));
        System.out.println("🔧 Java: " + System.getProperty("java.version"));
        System.out.println("💻 CPU: " + Runtime.getRuntime().availableProcessors() + " cores");
        System.out.println("=".repeat(60));
    }
    
    private static void printFooter(int domainCount) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("✅ BUILD SUCCESSFUL");
        System.out.println("=".repeat(60));
        System.out.println("📊 TOTAL BLOCKED: " + String.format("%,d", domainCount) + " domains");
        System.out.println("=".repeat(60));
    }
}