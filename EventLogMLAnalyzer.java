import java.io.*;
import java.util.*;
import java.util.stream.*;
import java.text.*;
import java.time.*;
import java.time.format.*;

/**
 * Machine Learning Event Log Analyzer for Windows Security Logs
 * Analyzes patterns, detects anomalies, and identifies potential threats
 */
public class EventLogMLAnalyzer {
    
    // Event Log Entry Structure
    static class EventEntry {
        LocalDateTime timeCreated;
        int eventId;
        String level;
        String provider;
        String message;
        String machine;
        String logName;
        
        // Extracted security fields
        String accountName;
        String processName;
        String logonType;
        
        public EventEntry(String[] csvRow) {
            try {
                this.timeCreated = parseDateTime(csvRow[0]);
                this.eventId = Integer.parseInt(csvRow[1].trim());
                this.level = csvRow[2].trim();
                this.provider = csvRow[3].trim();
                this.message = csvRow[4].trim();
                this.machine = csvRow[5].trim();
                this.logName = csvRow[6].trim();
                
                // Extract security-specific fields
                extractSecurityFields();
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse event entry: " + e.getMessage());
            }
        }
        
        private LocalDateTime parseDateTime(String dateStr) {
            try {
                // Handle format: "17/10/2025 14:37:50"
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("d/M/yyyy HH:mm:ss");
                return LocalDateTime.parse(dateStr.trim(), formatter);
            } catch (Exception e) {
                try {
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("M/d/yyyy h:mm:ss a");
                    return LocalDateTime.parse(dateStr.trim(), formatter);
                } catch (Exception e2) {
                    return LocalDateTime.now();
                }
            }
        }
        
        private void extractSecurityFields() {
            // Extract Account Name
            if (message.contains("Account Name:")) {
                String[] lines = message.split("\n");
                for (String line : lines) {
                    if (line.trim().startsWith("Account Name:")) {
                        accountName = line.split(":")[1].trim();
                        break;
                    }
                }
            }
            
            // Extract Process Name
            if (message.contains("Process Name:")) {
                String[] lines = message.split("\n");
                for (String line : lines) {
                    if (line.trim().startsWith("Process Name:")) {
                        processName = line.split(":", 2)[1].trim();
                        break;
                    }
                }
            }
            
            // Extract Logon Type
            if (message.contains("Logon Type:")) {
                String[] lines = message.split("\n");
                for (String line : lines) {
                    if (line.trim().startsWith("Logon Type:")) {
                        logonType = line.split(":")[1].trim();
                        break;
                    }
                }
            }
        }
        
        @Override
        public String toString() {
            return String.format("[%s] ID:%d %s - %s", 
                timeCreated.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
                eventId, level, provider);
        }
    }
    
    // Feature Vector for ML
    static class EventFeatures {
        double hourOfDay;
        double dayOfWeek;
        double eventIdNormalized;
        double eventFrequency;
        double providerRarity;
        double messageLengthNormalized;
        double timeSinceLastEvent;
        boolean isError;
        boolean isWarning;
        boolean isSystemAccount;
        double anomalyScore;
        
        public double[] toVector() {
            return new double[]{
                hourOfDay, dayOfWeek, eventIdNormalized, 
                eventFrequency, providerRarity, messageLengthNormalized,
                timeSinceLastEvent, isError ? 1.0 : 0.0, 
                isWarning ? 1.0 : 0.0, isSystemAccount ? 1.0 : 0.0
            };
        }
    }
    
    // Anomaly Detection using Isolation Forest-like approach
    static class AnomalyDetector {
        private double[] means;
        private double[] stdDevs;
        private double[] mins;
        private double[] maxs;
        private List<double[]> trainingData;
        
        public void train(List<EventFeatures> features) {
            trainingData = features.stream()
                .map(EventFeatures::toVector)
                .collect(Collectors.toList());
            
            if (trainingData.isEmpty()) return;
            
            int dimensions = trainingData.get(0).length;
            means = new double[dimensions];
            stdDevs = new double[dimensions];
            mins = new double[dimensions];
            maxs = new double[dimensions];
            
            Arrays.fill(mins, Double.MAX_VALUE);
            Arrays.fill(maxs, Double.MIN_VALUE);
            
            // Calculate means, mins, maxs
            for (int i = 0; i < dimensions; i++) {
                final int dim = i;
                means[i] = trainingData.stream()
                    .mapToDouble(v -> v[dim])
                    .average()
                    .orElse(0.0);
                    
                mins[i] = trainingData.stream()
                    .mapToDouble(v -> v[dim])
                    .min()
                    .orElse(0.0);
                    
                maxs[i] = trainingData.stream()
                    .mapToDouble(v -> v[dim])
                    .max()
                    .orElse(1.0);
            }
            
            // Calculate standard deviations
            for (int i = 0; i < dimensions; i++) {
                final int dim = i;
                double variance = trainingData.stream()
                    .mapToDouble(v -> Math.pow(v[dim] - means[dim], 2))
                    .average()
                    .orElse(0.0);
                stdDevs[i] = Math.sqrt(variance);
            }
        }
        
        public double calculateAnomalyScore(EventFeatures feature) {
            double[] vector = feature.toVector();
            double score = 0.0;
            int validDimensions = 0;
            
            for (int i = 0; i < vector.length; i++) {
                if (stdDevs[i] > 0.001) {
                    double zScore = Math.abs((vector[i] - means[i]) / stdDevs[i]);
                    score += zScore;
                    validDimensions++;
                }
            }
            
            return validDimensions > 0 ? score / validDimensions : 0.0;
        }
    }
    
    // Pattern Recognition Engine
    static class PatternRecognizer {
        private Map<Integer, Integer> eventIdFrequency = new HashMap<>();
        private Map<String, Integer> providerFrequency = new HashMap<>();
        private Map<String, Integer> accountFrequency = new HashMap<>();
        private Map<String, Integer> processFrequency = new HashMap<>();
        private Map<Integer, List<LocalDateTime>> eventTimestamps = new HashMap<>();
        private Map<String, List<LocalDateTime>> accountActivity = new HashMap<>();
        
        public void learn(List<EventEntry> entries) {
            for (EventEntry entry : entries) {
                eventIdFrequency.merge(entry.eventId, 1, Integer::sum);
                providerFrequency.merge(entry.provider, 1, Integer::sum);
                
                if (entry.accountName != null) {
                    accountFrequency.merge(entry.accountName, 1, Integer::sum);
                    accountActivity.computeIfAbsent(entry.accountName, k -> new ArrayList<>())
                        .add(entry.timeCreated);
                }
                
                if (entry.processName != null) {
                    processFrequency.merge(entry.processName, 1, Integer::sum);
                }
                
                eventTimestamps.computeIfAbsent(entry.eventId, k -> new ArrayList<>())
                    .add(entry.timeCreated);
            }
        }
        
        public double getEventFrequency(int eventId) {
            return eventIdFrequency.getOrDefault(eventId, 0);
        }
        
        public double getProviderRarity(String provider) {
            int count = providerFrequency.getOrDefault(provider, 1);
            int total = Math.max(1, providerFrequency.values().stream().mapToInt(Integer::intValue).sum());
            return 1.0 - ((double) count / total);
        }
        
        public boolean detectBurstPattern(int eventId, int timeWindowMinutes) {
            List<LocalDateTime> timestamps = eventTimestamps.get(eventId);
            
            if (timestamps == null || timestamps.size() < 10) return false;
            
            List<LocalDateTime> sorted = new ArrayList<>(timestamps);
            Collections.sort(sorted);
            
            if (sorted.isEmpty()) return false;
            
            LocalDateTime windowStart = sorted.get(sorted.size() - 1).minusMinutes(timeWindowMinutes);
            
            long recentCount = sorted.stream()
                .filter(t -> t.isAfter(windowStart))
                .count();
            
            return recentCount > 15; // Burst threshold
        }
        
        public List<String> detectSuspiciousAccounts() {
            List<String> suspicious = new ArrayList<>();
            
            for (Map.Entry<String, List<LocalDateTime>> entry : accountActivity.entrySet()) {
                String account = entry.getKey();
                List<LocalDateTime> times = entry.getValue();
                
                // Check for unusual activity hours (late night/early morning)
                long nightActivity = times.stream()
                    .filter(t -> t.getHour() < 6 || t.getHour() > 22)
                    .count();
                
                if (nightActivity > times.size() * 0.3) {
                    suspicious.add(account + " (unusual hours)");
                }
            }
            
            return suspicious;
        }
    }
    
    // Feature Engineering
    static class FeatureEngineer {
        private PatternRecognizer recognizer;
        private LocalDateTime lastEventTime = null;
        
        public FeatureEngineer(PatternRecognizer recognizer) {
            this.recognizer = recognizer;
        }
        
        public EventFeatures extractFeatures(EventEntry entry) {
            EventFeatures features = new EventFeatures();
            
            features.hourOfDay = entry.timeCreated.getHour() / 24.0;
            features.dayOfWeek = entry.timeCreated.getDayOfWeek().getValue() / 7.0;
            features.eventIdNormalized = Math.min(entry.eventId / 10000.0, 1.0);
            features.eventFrequency = Math.min(recognizer.getEventFrequency(entry.eventId) / 100.0, 1.0);
            features.providerRarity = recognizer.getProviderRarity(entry.provider);
            features.messageLengthNormalized = Math.min(entry.message.length() / 2000.0, 1.0);
            
            // Time since last event
            if (lastEventTime != null) {
                long secondsDiff = Math.abs(java.time.Duration.between(lastEventTime, entry.timeCreated).getSeconds());
                features.timeSinceLastEvent = Math.min(secondsDiff / 3600.0, 1.0); // Normalize to hours
            }
            lastEventTime = entry.timeCreated;
            
            features.isError = entry.level.equalsIgnoreCase("Error");
            features.isWarning = entry.level.equalsIgnoreCase("Warning");
            features.isSystemAccount = entry.accountName != null && 
                (entry.accountName.contains("SYSTEM") || entry.accountName.endsWith("$"));
            
            return features;
        }
    }
    
    // Suspicious Event Classifier
    static class ThreatClassifier {
        private static final Set<Integer> CRITICAL_EVENTS = new HashSet<>(Arrays.asList(
            4625, // Failed logon
            4720, // User account created
            4722, // User account enabled
            4724, // Password reset attempt
            4732, // Member added to security group
            4648, // Logon with explicit credentials
            4672, // Special privileges assigned to new logon
            4673, // Sensitive privilege use
            4697, // Service installed
            4698, // Scheduled task created
            4699, // Scheduled task deleted
            4700, // Scheduled task enabled
            4702, // Scheduled task updated
            7045, // New service installed
            1102, // Audit log cleared
            4719, // System audit policy changed
            4688, // New process created
            4689  // Process terminated
        ));
        
        private static final Set<Integer> AUTHENTICATION_EVENTS = new HashSet<>(Arrays.asList(
            4624, 4625, 4634, 4647, 4648, 4672
        ));
        
        public String classifyEvent(EventEntry entry) {
            int id = entry.eventId;
            
            if (id == 4625) return "FAILED_AUTHENTICATION";
            if (id == 4720 || id == 4722 || id == 4732) return "PRIVILEGE_ESCALATION";
            if (id == 4697 || id == 7045) return "SERVICE_MANIPULATION";
            if (id == 1102 || id == 4719) return "AUDIT_TAMPERING";
            if (id == 4648) return "LATERAL_MOVEMENT";
            if (id == 4698 || id == 4702) return "SCHEDULED_TASK_ACTIVITY";
            if (id == 4672) return "ELEVATED_PRIVILEGES";
            if (AUTHENTICATION_EVENTS.contains(id)) return "AUTHENTICATION";
            
            return "NORMAL";
        }
        
        public boolean isCritical(EventEntry entry) {
            return CRITICAL_EVENTS.contains(entry.eventId);
        }
        
        public int getThreatLevel(EventEntry entry) {
            String classification = classifyEvent(entry);
            
            switch (classification) {
                case "FAILED_AUTHENTICATION": return 8;
                case "PRIVILEGE_ESCALATION": return 9;
                case "SERVICE_MANIPULATION": return 7;
                case "AUDIT_TAMPERING": return 10;
                case "LATERAL_MOVEMENT": return 8;
                case "SCHEDULED_TASK_ACTIVITY": return 6;
                case "ELEVATED_PRIVILEGES": return 5;
                default: return 1;
            }
        }
    }
    
    // Main Analyzer
    private List<EventEntry> entries = new ArrayList<>();
    private PatternRecognizer recognizer = new PatternRecognizer();
    private AnomalyDetector anomalyDetector = new AnomalyDetector();
    private FeatureEngineer featureEngineer;
    private ThreatClassifier classifier = new ThreatClassifier();
    
    public void loadCSV(String filePath) throws IOException {
        System.out.println("Loading: " + filePath);
        
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line = br.readLine(); // Skip header
            int lineNum = 1;
            
            while ((line = br.readLine()) != null) {
                lineNum++;
                try {
                    String[] values = parseCSVLine(line);
                    if (values.length >= 7) {
                        entries.add(new EventEntry(values));
                    }
                } catch (Exception e) {
                    System.err.println("Warning: Skipped line " + lineNum + ": " + e.getMessage());
                }
            }
        }
        
        System.out.println("Loaded " + entries.size() + " events from " + new File(filePath).getName());
    }
    
    private String[] parseCSVLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        
        for (char c : line.toCharArray()) {
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                values.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        values.add(current.toString());
        
        return values.toArray(new String[0]);
    }
    
    public void trainModel() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("TRAINING MACHINE LEARNING MODEL");
        System.out.println("=".repeat(60));
        
        // Sort entries by time
        entries.sort(Comparator.comparing(e -> e.timeCreated));
        
        // Learn patterns
        recognizer.learn(entries);
        featureEngineer = new FeatureEngineer(recognizer);
        
        // Extract features and train anomaly detector
        List<EventFeatures> features = entries.stream()
            .map(featureEngineer::extractFeatures)
            .collect(Collectors.toList());
        
        anomalyDetector.train(features);
        
        System.out.println("✓ Model trained on " + entries.size() + " events");
        System.out.println("✓ Pattern recognition active");
        System.out.println("✓ Anomaly detection calibrated\n");
    }
    
    public void analyzeAndReport() {
        System.out.println("=".repeat(60));
        System.out.println("SECURITY ANALYSIS REPORT");
        System.out.println("=".repeat(60));
        
        // Calculate anomaly scores
        Map<EventEntry, Double> anomalyScores = new HashMap<>();
        List<EventEntry> highAnomalies = new ArrayList<>();
        List<EventEntry> criticalEvents = new ArrayList<>();
        Map<String, Integer> eventTypeCount = new HashMap<>();
        Map<String, Integer> threatTypeCount = new HashMap<>();
        
        for (EventEntry entry : entries) {
            EventFeatures features = featureEngineer.extractFeatures(entry);
            double score = anomalyDetector.calculateAnomalyScore(features);
            anomalyScores.put(entry, score);
            
            if (score > 2.0) {
                highAnomalies.add(entry);
            }
            
            if (classifier.isCritical(entry)) {
                criticalEvents.add(entry);
            }
            
            String classification = classifier.classifyEvent(entry);
            eventTypeCount.merge(classification, 1, Integer::sum);
            
            if (!classification.equals("NORMAL")) {
                threatTypeCount.merge(classification, 1, Integer::sum);
            }
        }
        
        // SUMMARY STATISTICS
        System.out.println("\n📊 SUMMARY STATISTICS");
        System.out.println("-".repeat(60));
        System.out.println("Total Events Analyzed: " + entries.size());
        System.out.println("Date Range: " + getDateRange());
        System.out.println("High Anomaly Events: " + highAnomalies.size());
        System.out.println("Critical Security Events: " + criticalEvents.size());
        
        // EVENT DISTRIBUTION
        System.out.println("\n📈 EVENT DISTRIBUTION");
        System.out.println("-".repeat(60));
        eventTypeCount.entrySet().stream()
            .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
            .limit(10)
            .forEach(e -> System.out.printf("%-30s %6d events\n", e.getKey(), e.getValue()));
        
        // THREAT ANALYSIS
        if (!threatTypeCount.isEmpty()) {
            System.out.println("\n⚠️  THREAT CLASSIFICATION");
            System.out.println("-".repeat(60));
            threatTypeCount.entrySet().stream()
                .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                .forEach(e -> {
                    String indicator = getThreatIndicator(e.getKey());
                    System.out.printf("%s %-30s %6d events\n", indicator, e.getKey(), e.getValue());
                });
        }
        
        // TOP ANOMALIES
        System.out.println("\n🔍 TOP 10 ANOMALOUS EVENTS");
        System.out.println("-".repeat(60));
        highAnomalies.stream()
            .sorted((a, b) -> Double.compare(anomalyScores.get(b), anomalyScores.get(a)))
            .limit(10)
            .forEach(e -> {
                double score = anomalyScores.get(e);
                String threat = classifier.classifyEvent(e);
                System.out.printf("[Score: %.2f] [%s] %s\n", score, threat, e);
                System.out.printf("  Account: %s | Process: %s\n", 
                    e.accountName != null ? e.accountName : "N/A",
                    e.processName != null ? extractFileName(e.processName) : "N/A");
                System.out.println();
            });
        
        // CRITICAL EVENTS DETAIL
        if (!criticalEvents.isEmpty()) {
            System.out.println("🚨 CRITICAL SECURITY EVENTS");
            System.out.println("-".repeat(60));
            criticalEvents.stream()
                .limit(15)
                .forEach(e -> {
                    String threat = classifier.classifyEvent(e);
                    int level = classifier.getThreatLevel(e);
                    System.out.printf("[Level %d/10] Event %d - %s\n", level, e.eventId, threat);
                    System.out.printf("  Time: %s\n", e.timeCreated.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                    if (e.accountName != null) System.out.printf("  Account: %s\n", e.accountName);
                    System.out.println();
                });
        }
        
        // BURST DETECTION
        System.out.println("💥 BURST PATTERN DETECTION");
        System.out.println("-".repeat(60));
        Set<Integer> checkedIds = new HashSet<>();
        boolean burstFound = false;
        
        for (EventEntry entry : entries) {
            if (!checkedIds.contains(entry.eventId)) {
                if (recognizer.detectBurstPattern(entry.eventId, 60)) {
                    System.out.printf("⚡ Event ID %d: Burst detected (>15 occurrences in 60 min)\n", 
                        entry.eventId);
                    System.out.printf("   Provider: %s\n", entry.provider);
                    burstFound = true;
                }
                checkedIds.add(entry.eventId);
            }
        }
        
        if (!burstFound) {
            System.out.println("✓ No suspicious burst patterns detected");
        }
        
        // SUSPICIOUS ACCOUNTS
        List<String> suspiciousAccounts = recognizer.detectSuspiciousAccounts();
        if (!suspiciousAccounts.isEmpty()) {
            System.out.println("\n👤 SUSPICIOUS ACCOUNT ACTIVITY");
            System.out.println("-".repeat(60));
            suspiciousAccounts.forEach(account -> System.out.println("⚠  " + account));
        }
        
        // RECOMMENDATIONS
        System.out.println("\n💡 RECOMMENDATIONS");
        System.out.println("-".repeat(60));
        generateRecommendations(threatTypeCount, highAnomalies.size(), criticalEvents.size());
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Analysis complete!");
        System.out.println("=".repeat(60) + "\n");
    }
    
    private String getDateRange() {
        if (entries.isEmpty()) return "No data";
        
        LocalDateTime min = entries.stream()
            .map(e -> e.timeCreated)
            .min(LocalDateTime::compareTo)
            .orElse(LocalDateTime.now());
            
        LocalDateTime max = entries.stream()
            .map(e -> e.timeCreated)
            .max(LocalDateTime::compareTo)
            .orElse(LocalDateTime.now());
            
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
        return min.format(fmt) + " to " + max.format(fmt);
    }
    
    private String getThreatIndicator(String threatType) {
        switch (threatType) {
            case "AUDIT_TAMPERING": return "🔴";
            case "PRIVILEGE_ESCALATION": return "🔴";
            case "FAILED_AUTHENTICATION": return "🟠";
            case "LATERAL_MOVEMENT": return "🟠";
            case "SERVICE_MANIPULATION": return "🟡";
            default: return "🟢";
        }
    }
    
    private String extractFileName(String fullPath) {
        if (fullPath == null) return "N/A";
        int lastSlash = fullPath.lastIndexOf('\\');
        return lastSlash >= 0 ? fullPath.substring(lastSlash + 1) : fullPath;
    }
    
    private void generateRecommendations(Map<String, Integer> threats, int anomalyCount, int criticalCount) {
        if (threats.containsKey("FAILED_AUTHENTICATION")) {
            System.out.println("• Review failed authentication attempts - possible brute force attack");
        }
        if (threats.containsKey("PRIVILEGE_ESCALATION")) {
            System.out.println("• Investigate privilege escalation events immediately");
        }
        if (threats.containsKey("AUDIT_TAMPERING")) {
            System.out.println("• CRITICAL: Audit log tampering detected - investigate immediately!");
        }
        if (anomalyCount > 50) {
            System.out.println("• High number of anomalies detected - review system behavior");
        }
        if (criticalCount > 100) {
            System.out.println("• Elevated critical event activity - consider security audit");
        }
        if (threats.isEmpty() && anomalyCount < 10) {
            System.out.println("✓ System appears to be operating normally");
            System.out.println("✓ No immediate security concerns detected");
        }
    }
    
    public static void main(String[] args) {
        EventLogMLAnalyzer analyzer = new EventLogMLAnalyzer();
        
        try {
            System.out.println("\n" + "=".repeat(60));
            System.out.println("Windows Event Log ML Analyzer v1.0");
            System.out.println("Machine Learning Security Analysis Tool");
            System.out.println("=".repeat(60) + "\n");
            
            // Load event log files
            String folder = "./data/training/";
            String[] files = {
                "MyComputer.csv"
            };
            
            boolean foundFiles = false;
            for (String file : files) {
                String path = folder + file;
                File f = new File(path);
                if (f.exists()) {
                    analyzer.loadCSV(path);
                    foundFiles = true;
                }
            }
            
            if (!foundFiles) {
                System.err.println("❌ No event log files found in " + folder);
                System.err.println("Please run the PowerShell script first to generate logs.");
                return;
            }
            
            // Train and analyze
            analyzer.trainModel();
            analyzer.analyzeAndReport();
            
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}