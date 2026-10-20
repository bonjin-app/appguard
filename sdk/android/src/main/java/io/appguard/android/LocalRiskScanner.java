package io.appguard.android;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Debug;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only untrusted hints, never an integrity or authorization verdict. Call off the UI thread. */
public final class LocalRiskScanner {
    public enum State { detected, not_observed, unavailable, not_configured }
    private static final String INVALID = "Invalid local risk configuration";
    private static final int RESOURCE_LIMIT = 1024 * 1024;
    private static final String[] ROOT_PATHS = {"/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/sbin/.magisk", "/data/adb/magisk"};
    private static final Pattern MAP_LINE = Pattern.compile(
            "[0-9a-fA-F]+-[0-9a-fA-F]+\\s+[r-][w-][x-][ps]\\s+[0-9a-fA-F]+\\s+[0-9a-fA-F]+:[0-9a-fA-F]+\\s+[0-9]+(?:\\s+(.*))?");

    /** Optional expected identity, current APK signer allowlist, and exact AssetManager byte pins. */
    public static final class Config {
        private final String expectedAppId;
        private final Set<String> signerPins;
        private final Map<String,String> resources;
        public Config() { this(null, Collections.emptySet(), Collections.emptyMap()); }
        public Config(String expectedAppId, Set<String> signerPins, Map<String,String> resources) {
            if (expectedAppId != null && (expectedAppId.length() > 255 ||
                    !expectedAppId.matches("[A-Za-z0-9][A-Za-z0-9._-]*"))) throw invalid();
            if (signerPins == null || resources == null || signerPins.size() > 8 || resources.size() > 8) throw invalid();
            Set<String> pins = new HashSet<>();
            for (String pin : signerPins) { if (!validHash(pin)) throw invalid(); pins.add(pin); }
            Map<String,String> assets = new TreeMap<>();
            for (Map.Entry<String,String> entry : resources.entrySet()) {
                String path = entry.getKey();
                if (path == null || path.isEmpty() || path.length() > 256 || !validHash(entry.getValue())) throw invalid();
                for (String component : path.split("/", -1)) {
                    if (component.length() > 128 || !component.matches("[A-Za-z0-9_-][A-Za-z0-9._-]*") ||
                            component.equals(".") || component.equals("..")) throw invalid();
                }
                assets.put(path, entry.getValue());
            }
            this.expectedAppId = expectedAppId;
            this.signerPins = Collections.unmodifiableSet(pins);
            this.resources = Collections.unmodifiableMap(assets);
        }
        private static boolean validHash(String hash) { return hash != null && hash.matches("[0-9a-f]{64}"); }
    }

    /** Fixed, privacy-preserving observations and deduplicated server-policy categories. */
    public static final class Report {
        private final Map<String,State> checks;
        private final List<String> signals;
        private Report(Map<String,State> checks) {
            this.checks = Collections.unmodifiableMap(new LinkedHashMap<>(checks));
            List<String> categories = new ArrayList<>();
            if (checks.get("debugger_attached") == State.detected || checks.get("debug_build") == State.detected) categories.add("debugger");
            if (checks.get("root_artifact") == State.detected) categories.add("root");
            if (checks.get("hook_artifact") == State.detected) categories.add("hook");
            if (checks.get("app_identity_mismatch") == State.detected || checks.get("app_signer_mismatch") == State.detected || checks.get("bundle_resource_mismatch") == State.detected) categories.add("tamper");
            if (checks.containsValue(State.unavailable)) categories.add("local_checks_unavailable");
            this.signals = Collections.unmodifiableList(categories);
        }
        public Map<String,State> checks() { return checks; }
        public List<String> riskSignals() { return signals; }
        public String toJson() {
            StringBuilder out = new StringBuilder("{\"schema\":\"appguard-local-risk-v0\",\"platform\":\"android\",\"checks\":[");
            boolean comma = false;
            for (Map.Entry<String,State> entry : checks.entrySet()) {
                if (comma) out.append(','); comma = true;
                out.append("{\"code\":\"").append(entry.getKey()).append("\",\"state\":\"").append(entry.getValue()).append("\"}");
            }
            out.append("],\"riskSignals\":["); comma = false;
            for (String signal : signals) { if (comma) out.append(','); comma = true; out.append('"').append(signal).append('"'); }
            return out.append("]}").toString();
        }
        @Override public String toString() { return toJson(); }
    }

    // Only OS boundaries are injectable. No public synthetic-observation scanner.
    interface Observations {
        boolean debugger() throws Exception;
        InputStream status() throws Exception;
        boolean debugBuild() throws Exception;
        boolean rootArtifact(String path) throws Exception;
        InputStream maps() throws Exception;
        String appId() throws Exception;
        List<byte[]> currentSigners() throws Exception;
        InputStream asset(String path) throws Exception;
    }
    private final Observations observations;
    LocalRiskScanner(Observations observations) { this.observations = observations; }
    public LocalRiskScanner(Context context) {
        if (context == null) throw invalid();
        Context app = context.getApplicationContext();
        observations = new AndroidObservations(app != null ? app : context);
    }
    public Report scan(Config config) {
        if (config == null) throw invalid();
        Map<String,State> checks = new LinkedHashMap<>();
        checks.put("debugger_attached", combine(probe(() -> observations.debugger()), tracer()));
        checks.put("debug_build", probe(() -> observations.debugBuild()));
        State root = State.not_observed;
        for (String path : ROOT_PATHS) root = combine(root, probe(() -> observations.rootArtifact(path)));
        checks.put("root_artifact", root);
        checks.put("hook_artifact", hooks());
        checks.put("app_identity_mismatch", config.expectedAppId == null ? State.not_configured : probe(() -> {
            String id = observations.appId(); if (id == null || id.isEmpty()) throw new IOException();
            return !config.expectedAppId.equals(id);
        }));
        checks.put("app_signer_mismatch", config.signerPins.isEmpty() ? State.not_configured : signers(config));
        checks.put("bundle_resource_mismatch", resources(config));
        return new Report(checks);
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException(INVALID); }
    private interface BooleanProbe { boolean read() throws Exception; }
    private static State probe(BooleanProbe action) {
        try { return action.read() ? State.detected : State.not_observed; }
        catch (Exception | LinkageError failure) { return State.unavailable; }
    }
    private static State combine(State a, State b) {
        if (a == State.detected || b == State.detected) return State.detected;
        if (a == State.unavailable || b == State.unavailable) return State.unavailable;
        return State.not_observed;
    }
    private State tracer() {
        return probe(() -> {
            String text = readText(observations.status(), 64 * 1024);
            boolean found = false; boolean positive = false;
            for (String line : text.split("\n", -1)) {
                if (!line.startsWith("TracerPid:")) continue;
                if (found || !line.matches("TracerPid:[ \\t]*[0-9]+[ \\t]*")) throw new IOException();
                found = true;
                String digits = line.substring(10).trim();
                // Proc exposes a process ID; out-of-range fields are malformed observations.
                positive = Integer.parseInt(digits) > 0;
            }
            if (!found) throw new IOException();
            return positive;
        });
    }
    private State hooks() {
        return probe(() -> {
            String text = readText(observations.maps(), 512 * 1024);
            boolean positive = false; boolean malformed = text.isEmpty();
            for (String line : text.split("\n", -1)) {
                if (line.isEmpty()) continue;
                Matcher matcher = MAP_LINE.matcher(line);
                if (!matcher.matches()) { malformed = true; continue; }
                String path = matcher.group(1);
                if (path == null) continue;
                if (path.endsWith(" (deleted)")) path = path.substring(0, path.length() - 10);
                String name = path.substring(path.lastIndexOf('/') + 1);
                if (name.matches("libfrida(?:-gadget|-agent)?(?:-[A-Za-z0-9_-]+)?\\.so") ||
                        name.equals("libxposed_art.so") || name.equals("libxposed.so") ||
                        name.equals("libsubstrate.so") || name.equals("libsubstrate-dvm.so")) positive = true;
            }
            if (positive) return true;
            if (malformed) throw new IOException();
            return false;
        });
    }
    private State signers(Config config) {
        return probe(() -> {
            List<byte[]> signers = observations.currentSigners();
            if (signers == null || signers.isEmpty()) throw new IOException();
            State result = State.not_observed;
            for (byte[] certificate : signers) {
                if (certificate == null || certificate.length == 0) result = combine(result, State.unavailable);
                else result = combine(result, config.signerPins.contains(hex(MessageDigest.getInstance("SHA-256").digest(certificate)))
                        ? State.not_observed : State.detected);
            }
            if (result == State.unavailable) throw new IOException();
            return result == State.detected;
        });
    }
    private State resources(Config config) {
        if (config.resources.isEmpty()) return State.not_configured;
        State result = State.not_observed;
        for (Map.Entry<String,String> resource : config.resources.entrySet()) {
            State state;
            InputStream opened;
            try { opened = observations.asset(resource.getKey()); }
            catch (FileNotFoundException missing) { result = combine(result, State.detected); continue; }
            catch (Exception | LinkageError failure) { result = combine(result, State.unavailable); continue; }
            try (InputStream input = opened) {
                state = resource.getValue().equals(hashBounded(input, RESOURCE_LIMIT)) ? State.not_observed : State.detected;
            } catch (Exception | LinkageError failure) { state = State.unavailable; }
            result = combine(result, state);
        }
        return result;
    }
    private static String hashBounded(InputStream input, int limit) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        copyBounded(input, limit, digest, null);
        return hex(digest.digest());
    }
    private static String readText(InputStream input, int limit) throws Exception {
        try (InputStream owned = input) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            copyBounded(owned, limit, null, bytes);
            byte[] raw = bytes.toByteArray();
            for (byte value : raw) if (value == 0 || value < 0) throw new IOException();
            return new String(raw, StandardCharsets.US_ASCII);
        }
    }
    private static void copyBounded(InputStream input, int limit, MessageDigest digest, ByteArrayOutputStream output) throws IOException {
        if (input == null) throw new IOException();
        byte[] buffer = new byte[8192]; int total = 0;
        while (true) {
            int count = input.read(buffer, 0, Math.min(buffer.length, limit - total + 1));
            if (count < 0) return;
            if (count == 0) { int single = input.read(); if (single < 0) return; buffer[0] = (byte)single; count = 1; }
            total += count; if (total > limit) throw new IOException();
            if (digest != null) digest.update(buffer, 0, count);
            if (output != null) output.write(buffer, 0, count);
        }
    }
    private static String hex(byte[] bytes) {
        char[] alphabet = "0123456789abcdef".toCharArray(); StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(alphabet[(value & 255) >>> 4]).append(alphabet[value & 15]);
        return out.toString();
    }
    private static final class AndroidObservations implements Observations {
        private final Context context;
        AndroidObservations(Context context) { this.context = context; }
        public boolean debugger() { return Debug.isDebuggerConnected() || Debug.waitingForDebugger(); }
        public InputStream status() throws IOException { return Files.newInputStream(Paths.get("/proc/self/status")); }
        public boolean debugBuild() { return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0; }
        public boolean rootArtifact(String path) throws IOException {
            try { Files.readAttributes(Paths.get(path), BasicFileAttributes.class, java.nio.file.LinkOption.NOFOLLOW_LINKS); return true; }
            catch (NoSuchFileException missing) { return false; }
        }
        public InputStream maps() throws IOException { return Files.newInputStream(Paths.get("/proc/self/maps")); }
        public String appId() throws PackageManager.NameNotFoundException {
            String name = context.getPackageName();
            return context.getPackageManager().getPackageInfo(name, 0).packageName;
        }
        @SuppressWarnings("deprecation")
        public List<byte[]> currentSigners() throws PackageManager.NameNotFoundException, IOException {
            PackageManager manager = context.getPackageManager();
            Signature[] signatures;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo info = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
                if (info.signingInfo == null) throw new IOException();
                signatures = info.signingInfo.getApkContentsSigners();
            } else {
                signatures = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES).signatures;
            }
            if (signatures == null || signatures.length == 0) throw new IOException();
            List<byte[]> result = new ArrayList<>();
            for (Signature signature : signatures) { if (signature == null) throw new IOException(); result.add(signature.toByteArray()); }
            return result;
        }
        public InputStream asset(String path) throws IOException { return context.getAssets().open(path); }
    }
}
