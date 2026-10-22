import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.text.NumberFormat;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/** Selected runtime behavior, never complete native/feature/license approval. */
public final class AppGuardRuntimeProbe {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AtomicBoolean UNVERIFIED = new AtomicBoolean();
    private static final Object PROCESS_LOCK = new Object();
    private static final List<Process> OWNED_PROCESSES = new ArrayList<>();
    private static boolean processesStopping;
    private static final String[] NAMES = {"crypto_p256", "aes_gcm", "pkcs12_roundtrip", "jsse_default_trust",
        "mtls_loopback", "utf8_io", "locale_data", "timezone_data", "localhost_nss", "headless_font"};
    private static final int IO_TIMEOUT_MS = 2000;

    @FunctionalInterface private interface Check { boolean run() throws Exception; }
    private record ServerResult(boolean authenticated, boolean refused) {}
    private record Exchange(boolean authenticated, boolean clientRefused, boolean serverRefused) {}

    private AppGuardRuntimeProbe() {}

    public static void main(String[] args) {
        Map<String, Boolean> checks = new LinkedHashMap<>();
        for (String name : NAMES) checks.put(name, false);
        int exit = 2;
        if (args.length == 0) {
            Check[] actions = {AppGuardRuntimeProbe::cryptoP256, AppGuardRuntimeProbe::aesGcm,
                AppGuardRuntimeProbe::pkcs12Roundtrip, AppGuardRuntimeProbe::defaultTrust,
                AppGuardRuntimeProbe::mtlsLoopback, AppGuardRuntimeProbe::utf8Io,
                AppGuardRuntimeProbe::localeData, AppGuardRuntimeProbe::timezoneData,
                AppGuardRuntimeProbe::localhostNss, AppGuardRuntimeProbe::headlessFont};
            try {
                for (int i = 0; i < NAMES.length; i++) checks.put(NAMES[i], attempt(actions[i], i == 4 ? 40 : 5));
            } catch (Throwable fatal) { UNVERIFIED.set(true); }
            finally { stopOwnedProcesses(); }
            exit = UNVERIFIED.get() ? 2 : checks.values().stream().allMatch(Boolean::booleanValue) ? 0 : 1;
        }
        boolean passed = checks.values().stream().allMatch(Boolean::booleanValue);
        StringBuilder output = new StringBuilder("{\"schema\":1,\"checks\":{");
        for (int i = 0; i < NAMES.length; i++) {
            if (i != 0) output.append(',');
            output.append('"').append(NAMES[i]).append("\":").append(checks.get(NAMES[i]));
        }
        System.out.println(output.append("},\"passed\":").append(passed).append('}'));
        // Daemon workers cannot make a failed native call hold the process open.
        // An unconfirmed worker/resource cleanup is exit2, never measured success.
        System.exit(exit);
    }

    private static ExecutorService worker(String name) {
        return Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, name);
            thread.setDaemon(true);
            return thread;
        });
    }

    private static boolean attempt(Check check, int seconds) {
        ExecutorService executor = worker("appguard-runtime-check");
        Future<Boolean> future = executor.submit(check::run);
        boolean passed = false;
        try {
            passed = future.get(seconds, TimeUnit.SECONDS);
        } catch (ExecutionException error) {
            if (error.getCause() instanceof VirtualMachineError) UNVERIFIED.set(true);
        } catch (InterruptedException error) {
            UNVERIFIED.set(true);
            Thread.currentThread().interrupt();
        } catch (TimeoutException error) {
            future.cancel(true);
        } finally {
            executor.shutdownNow();
            if (!awaitStopped(executor, 500)) { UNVERIFIED.set(true); passed = false; }
        }
        return passed;
    }

    private static boolean awaitStopped(ExecutorService executor, long milliseconds) {
        boolean interrupted = Thread.interrupted();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(milliseconds);
        try {
            while (!executor.isTerminated() && System.nanoTime() < deadline) {
                try { executor.awaitTermination(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS); }
                catch (InterruptedException error) { interrupted = true; }
            }
            return executor.isTerminated();
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }

    private static boolean cryptoP256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
        KeyPair pair = generator.generateKeyPair();
        byte[] message = "appguard-runtime-p256".getBytes(StandardCharsets.UTF_8);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(pair.getPrivate(), RANDOM); signature.update(message);
        byte[] signed = signature.sign();
        signature.initVerify(pair.getPublic()); signature.update(message);
        if (!signature.verify(signed)) return false;
        message[0] ^= 1;
        signature.initVerify(pair.getPublic()); signature.update(message);
        if (signature.verify(signed)) return false;
        message[0] ^= 1; signed[signed.length - 1] ^= 1;
        signature.initVerify(pair.getPublic()); signature.update(message);
        try { return !signature.verify(signed); }
        catch (SignatureException refused) { return true; }
    }

    private static boolean aesGcm() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES"); generator.init(256, RANDOM);
        SecretKey key = generator.generateKey();
        byte[] iv = new byte[12]; RANDOM.nextBytes(iv);
        byte[] message = "appguard-runtime-gcm\u0000".getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(message);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        if (!MessageDigest.isEqual(message, cipher.doFinal(encrypted))) return false;
        encrypted[encrypted.length - 1] ^= 1;
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        try { cipher.doFinal(encrypted); return false; }
        catch (AEADBadTagException refused) { return true; }
    }

    private static Path privateDirectory() throws IOException {
        return Files.createTempDirectory("appguard-runtime-", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")));
    }

    private static Path privateFile(Path directory, String name) throws IOException {
        return Files.createFile(directory.resolve(name), PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rw-------")));
    }

    private static void removePrivate(Path directory) throws IOException {
        try {
            Files.walkFileTree(directory, new SimpleFileVisitor<>() {
                private int entries;
                @Override public FileVisitResult visitFile(Path path, BasicFileAttributes attributes) throws IOException {
                    if (++entries > 128) throw new IOException("unverified");
                    Files.delete(path); return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult preVisitDirectory(Path path, BasicFileAttributes attributes) throws IOException {
                    if (++entries > 128) throw new IOException("unverified");
                    return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult postVisitDirectory(Path path, IOException error) throws IOException {
                    if (error != null) throw error;
                    Files.delete(path); return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException error) { UNVERIFIED.set(true); throw error; }
    }

    private static char[] password() {
        byte[] random = new byte[32]; RANDOM.nextBytes(random);
        char[] result = Base64.getUrlEncoder().withoutPadding().encodeToString(random).toCharArray();
        Arrays.fill(random, (byte) 0); return result;
    }

    private static boolean pkcs12Roundtrip() throws Exception {
        Path directory = privateDirectory(); char[] password = password();
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES"); generator.init(256, RANDOM);
            SecretKey secret = generator.generateKey();
            KeyStore original = KeyStore.getInstance("PKCS12"); original.load(null, password);
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);
            try { original.setEntry("probe", new KeyStore.SecretKeyEntry(secret), protection); }
            finally { protection.destroy(); }
            Path path = privateFile(directory, "secret.p12");
            try (OutputStream stream = Files.newOutputStream(path)) { original.store(stream, password); }
            KeyStore restored = KeyStore.getInstance("PKCS12");
            try (InputStream stream = Files.newInputStream(path)) { restored.load(stream, password); }
            return restored.size() == 1 && MessageDigest.isEqual(secret.getEncoded(), restored.getKey("probe", password).getEncoded());
        } finally { Arrays.fill(password, '\0'); removePrivate(directory); }
    }

    private static boolean defaultTrust() throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        boolean roots = false;
        for (TrustManager manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509 && x509.getAcceptedIssuers().length > 0) roots = true;
        }
        SSLContext context = SSLContext.getInstance("TLSv1.3"); context.init(null, factory.getTrustManagers(), RANDOM);
        return roots && Arrays.asList(context.getDefaultSSLParameters().getProtocols()).contains("TLSv1.3");
    }

    private static void stopProcess(Process process) throws IOException {
        boolean interrupted = Thread.interrupted();
        try {
            List<ProcessHandle> children = process.descendants().toList();
            for (ProcessHandle child : children) if (child.isAlive()) child.destroyForcibly();
            if (process.isAlive()) process.destroyForcibly();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (process.isAlive() && System.nanoTime() < deadline) {
                try { process.waitFor(50, TimeUnit.MILLISECONDS); }
                catch (InterruptedException error) { interrupted = true; }
            }
            if (process.isAlive() || children.stream().anyMatch(ProcessHandle::isAlive)) {
                UNVERIFIED.set(true); throw new IOException("unverified");
            }
        } finally { if (interrupted) Thread.currentThread().interrupt(); }
    }

    private static void stopOwnedProcesses() {
        List<Process> processes;
        synchronized (PROCESS_LOCK) {
            processesStopping = true;
            processes = List.copyOf(OWNED_PROCESSES);
        }
        for (Process process : processes) {
            try { stopProcess(process); }
            catch (IOException error) { UNVERIFIED.set(true); }
        }
    }

    private static KeyStore certificate(Path directory, String alias, boolean server, char[] password) throws Exception {
        Path home = Path.of(System.getProperty("java.home"));
        Path store = directory.resolve(alias + ".p12");
        List<String> command = new ArrayList<>(List.of(home.resolve("bin/keytool").toString(),
            "-J-Xms8m", "-J-Xmx64m", "-J-XX:ActiveProcessorCount=1", "-J-XX:-UsePerfData",
            "-J-Duser.home=" + directory, "-J-Djava.io.tmpdir=" + directory,
            "-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1",
            "-sigalg", "SHA256withECDSA", "-dname", "CN=localhost", "-validity", "1",
            "-ext", "KU=digitalSignature", "-ext", "EKU=" + (server ? "serverAuth" : "clientAuth"),
            "-keystore", store.toString(), "-storetype", "PKCS12", "-storepass:env", "APPGUARD_PROBE_PASSWORD", "-noprompt"));
        if (server) command.addAll(List.of("-ext", "SAN=IP:127.0.0.1,DNS:localhost"));
        ProcessBuilder builder = new ProcessBuilder(command);
        Map<String, String> environment = builder.environment(); environment.clear();
        for (String name : List.of("LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ")) {
            if (System.getenv(name) != null) environment.put(name, System.getenv(name));
        }
        environment.put("HOME", directory.toString()); environment.put("TMPDIR", directory.toString());
        environment.put("XDG_CACHE_HOME", directory.toString());
        environment.put("JAVA_HOME", home.toString()); environment.put("APPGUARD_PROBE_PASSWORD", new String(password));
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
        Process process;
        try {
            synchronized (PROCESS_LOCK) {
                if (processesStopping || Thread.currentThread().isInterrupted()) throw new IOException("unverified");
                process = builder.start(); OWNED_PROCESSES.add(process);
            }
        } finally { environment.clear(); }
        try {
            process.getOutputStream().close();
            if (!process.waitFor(10, TimeUnit.SECONDS) || process.exitValue() != 0) throw new IOException("unverified");
        } finally {
            try { stopProcess(process); }
            finally { synchronized (PROCESS_LOCK) { if (!process.isAlive()) OWNED_PROCESSES.remove(process); } }
        }
        Files.setPosixFilePermissions(store, PosixFilePermissions.fromString("rw-------"));
        KeyStore result = KeyStore.getInstance("PKCS12");
        try (InputStream stream = Files.newInputStream(store)) { result.load(stream, password); }
        return result;
    }

    private static SSLContext tlsContext(KeyStore identity, char[] password, Certificate trusted) throws Exception {
        KeyManager[] keys = new KeyManager[0];
        if (identity != null) {
            KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(identity, password); keys = factory.getKeyManagers();
        }
        KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null); trust.setCertificateEntry("peer", trusted);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(trust);
        SSLContext context = SSLContext.getInstance("TLSv1.3"); context.init(keys, factory.getTrustManagers(), RANDOM);
        return context;
    }

    private static boolean peer(SSLSession session, Certificate expected) throws Exception {
        return session.getProtocol().equals("TLSv1.3") && MessageDigest.isEqual(session.getPeerCertificates()[0].getEncoded(), expected.getEncoded());
    }

    private static Exchange exchange(SSLContext serverContext, SSLContext clientContext, String peerHost,
                                     Certificate serverCertificate, Certificate clientCertificate) throws Exception {
        InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
        SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket();
        AtomicReference<SSLSocket> accepted = new AtomicReference<>();
        ExecutorService executor = worker("appguard-runtime-tls");
        Socket transport = new Socket(); SSLSocket client = null;
        try {
            server.setEnabledProtocols(new String[] {"TLSv1.3"}); server.setNeedClientAuth(true);
            server.setSoTimeout(IO_TIMEOUT_MS); server.bind(new InetSocketAddress(loopback, 0), 1);
            Future<ServerResult> result = executor.submit(() -> {
                try (SSLSocket connection = (SSLSocket) server.accept()) {
                    accepted.set(connection); connection.setSoTimeout(IO_TIMEOUT_MS); connection.setNeedClientAuth(true);
                    connection.startHandshake();
                    boolean authenticated = peer(connection.getSession(), clientCertificate) && connection.getInputStream().read() == 65;
                    if (authenticated) { connection.getOutputStream().write(71); connection.getOutputStream().flush(); }
                    return new ServerResult(authenticated, false);
                } catch (SSLHandshakeException refusal) { return new ServerResult(false, true); }
                // A peer can close after its own typed handshake refusal. Generic
                // transport failure is unauthenticated, never a refusal proof.
                catch (IOException peerClose) { return new ServerResult(false, false); }
            });
            transport.connect(new InetSocketAddress(loopback, server.getLocalPort()), IO_TIMEOUT_MS);
            client = (SSLSocket) clientContext.getSocketFactory().createSocket(transport, peerHost, server.getLocalPort(), true);
            client.setSoTimeout(IO_TIMEOUT_MS); client.setEnabledProtocols(new String[] {"TLSv1.3"});
            SSLParameters parameters = client.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS"); client.setSSLParameters(parameters);
            boolean authenticated = false, refused = false;
            try {
                client.startHandshake();
                if (peer(client.getSession(), serverCertificate)) {
                    client.getOutputStream().write(65); client.getOutputStream().flush();
                    authenticated = client.getInputStream().read() == 71;
                }
            } catch (SSLHandshakeException refusal) { refused = true; }
            catch (IOException expectedPeerClose) { /* Only a typed server handshake refusal can validate this case. */ }
            ServerResult observed = result.get(5, TimeUnit.SECONDS);
            return new Exchange(authenticated && observed.authenticated(), refused, observed.refused());
        } finally {
            boolean closed = true;
            for (AutoCloseable resource : new AutoCloseable[] {client, transport, accepted.get(), server}) {
                if (resource != null) try { resource.close(); } catch (Exception error) { closed = false; }
            }
            executor.shutdownNow();
            if (!awaitStopped(executor, 1000) || !closed) { UNVERIFIED.set(true); throw new IOException("unverified"); }
        }
    }

    private static boolean mtlsLoopback() throws Exception {
        Path directory = privateDirectory(); char[] password = password();
        try {
            KeyStore server = certificate(directory, "server", true, password);
            KeyStore client = certificate(directory, "client", false, password);
            Certificate serverCertificate = server.getCertificate("server"), clientCertificate = client.getCertificate("client");
            SSLContext serverContext = tlsContext(server, password, clientCertificate);
            SSLContext clientContext = tlsContext(client, password, serverCertificate);
            Exchange valid = exchange(serverContext, clientContext, "127.0.0.1", serverCertificate, clientCertificate);
            if (!valid.authenticated()) return false;
            Exchange missingClient = exchange(serverContext, tlsContext(null, password, serverCertificate), "127.0.0.1", serverCertificate, clientCertificate);
            Exchange wrongEndpoint = exchange(serverContext, clientContext, "wrong.invalid", serverCertificate, clientCertificate);
            return !missingClient.authenticated() && missingClient.serverRefused()
                && !wrongEndpoint.authenticated() && wrongEndpoint.clientRefused();
        } finally { Arrays.fill(password, '\0'); removePrivate(directory); }
    }

    private static boolean utf8Io() throws Exception {
        Path directory = privateDirectory();
        try {
            String text = "AppGuard: 日本語 café \uD83D\uDD12";
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            Path file = privateFile(directory, "utf8.txt"); Files.write(file, bytes);
            return Charset.defaultCharset().equals(StandardCharsets.UTF_8)
                && text.equals(new String(bytes, StandardCharsets.UTF_8))
                && text.equals(Files.readString(file, StandardCharsets.UTF_8)) && MessageDigest.isEqual(bytes, Files.readAllBytes(file));
        } finally { removePrivate(directory); }
    }

    private static boolean localeData() {
        return "1月".equals(DateTimeFormatter.ofPattern("MMMM", Locale.JAPAN).format(LocalDate.of(2000, 1, 1)))
            && "12,345.5".equals(NumberFormat.getNumberInstance(Locale.JAPAN).format(12345.5))
            && "日本語".equals(Locale.JAPANESE.getDisplayLanguage(Locale.JAPAN));
    }

    private static boolean timezoneData() {
        ZoneId ny = ZoneId.of("America/New_York"), kathmandu = ZoneId.of("Asia/Kathmandu");
        return ny.getRules().getOffset(Instant.parse("2000-01-01T12:00:00Z")).getTotalSeconds() == -18000
            && ny.getRules().getOffset(Instant.parse("2000-07-01T12:00:00Z")).getTotalSeconds() == -14400
            && kathmandu.getRules().getOffset(Instant.parse("1985-01-01T00:00:00Z")).getTotalSeconds() == 19800
            && kathmandu.getRules().getOffset(Instant.parse("2000-01-01T00:00:00Z")).getTotalSeconds() == 20700;
    }

    private static boolean localhostNss() throws Exception {
        InetAddress[] addresses = InetAddress.getAllByName("localhost");
        return addresses.length > 0 && addresses.length <= 16 && Arrays.stream(addresses).allMatch(InetAddress::isLoopbackAddress);
    }

    private static boolean headlessFont() throws Exception {
        Path directory = privateDirectory(); String home = System.getProperty("user.home");
        BufferedImage image = null;
        try {
            System.setProperty("java.awt.headless", "true"); System.setProperty("user.home", directory.toString());
            image = new BufferedImage(160, 40, BufferedImage.TYPE_INT_ARGB);
            Graphics2D graphics = image.createGraphics();
            try {
                graphics.setColor(Color.WHITE); graphics.fillRect(0, 0, 160, 40); graphics.setColor(Color.BLACK);
                Font font = new Font(Font.SANS_SERIF, Font.PLAIN, 18); graphics.setFont(font);
                if (!font.canDisplay('A') || graphics.getFontMetrics().stringWidth("AppGuard") <= 0) return false;
                graphics.drawString("AppGuard", 4, 26);
            } finally { graphics.dispose(); }
            for (int y = 0; y < image.getHeight(); y++) for (int x = 0; x < image.getWidth(); x++) {
                if (image.getRGB(x, y) != Color.WHITE.getRGB()) return true;
            }
            return false;
        } finally {
            if (image != null) image.flush();
            if (home != null) System.setProperty("user.home", home); else System.clearProperty("user.home");
            removePrivate(directory);
        }
    }
}
