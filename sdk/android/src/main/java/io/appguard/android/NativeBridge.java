package io.appguard.android;

import android.content.Context;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import org.json.JSONArray;
import org.json.JSONObject;

/** Bounded JSON facade over the typed request/enrollment SDK. No transport or arbitrary-sign API. */
public final class NativeBridge {
    private static Set<String> fields(String... names) { return java.util.Collections.unmodifiableSet(new java.util.HashSet<>(java.util.Arrays.asList(names))); }
    private static final int MAX_JSON_BYTES = 1500000;
    private static final Set<String> COMMON = fields("alias", "hardwareRequirement");
    private static final Set<String> PREPARE = fields("alias", "hardwareRequirement", "origin", "method", "target", "bodyBase64",
            "contentType", "authorization", "appId", "keyId", "created", "expires", "nonce");
    private static final Set<String> ENROLLMENT = fields("alias", "hardwareRequirement", "challenge", "expectedAppId",
            "expectedOrigin", "expectedSubject", "expectedKeyId");
    private static final Set<String> CHALLENGE = fields("appId", "origin", "subject", "keyId", "publicKeySha256", "nonce", "expires");
    private final KeyProvider keys;
    private final LongSupplier clock;

    /** Uses only this application's installation keys and the native wall clock. */
    public NativeBridge(Context context) {
        this((alias, requirement) -> {
            AndroidInstallationKey key = AndroidInstallationKey.getOrCreate(context, alias, requirement);
            return new KeyHandle(key, key.backing().name());
        }, () -> Instant.now().getEpochSecond());
    }

    // Package-private seams substitute only key storage and wall time in host tests.
    interface KeyProvider { KeyHandle load(String alias, AndroidInstallationKey.Requirement requirement) throws GeneralSecurityException; }
    static final class KeyHandle {
        final RequestSigner.PublicSigningKey key;
        final String backing;
        KeyHandle(RequestSigner.PublicSigningKey key, String backing) { this.key = key; this.backing = backing; }
    }
    NativeBridge(KeyProvider keys, LongSupplier clock) { this.keys = keys; this.clock = clock; }

    /** Always returns the fixed JSON envelope. Native exception messages never cross this boundary. */
    public String invoke(String operation, String payload) {
        try {
            Set<String> fields;
            if ("publicKey".equals(operation)) fields = COMMON;
            else if ("prepare".equals(operation)) fields = PREPARE;
            else if ("enrollmentProof".equals(operation)) fields = ENROLLMENT;
            else return failure("APPGUARD_UNSUPPORTED");
            Map<String, Object> object = StrictJSON.parse(payload);
            requireFields(object, fields);
            String alias = string(object, "alias"); RequestSigner.validateIdentifier(alias);
            AndroidInstallationKey.Requirement requirement;
            switch (string(object, "hardwareRequirement")) {
                case "any": requirement = AndroidInstallationKey.Requirement.ANY_KEYSTORE; break;
                case "hardware": requirement = AndroidInstallationKey.Requirement.HARDWARE_REQUIRED; break;
                case "strongbox": requirement = AndroidInstallationKey.Requirement.STRONGBOX_REQUIRED; break;
                default: throw new IllegalArgumentException();
            }
            LazyKey key = new LazyKey(alias, requirement);
            JSONObject result = new JSONObject();
            if ("publicKey".equals(operation)) {
                KeyHandle handle = key.load();
                result.put("publicKeyPem", EcdsaP256.publicPem(java.security.KeyFactory.getInstance("EC")
                        .generatePublic(new java.security.spec.X509EncodedKeySpec(handle.key.publicKeySpki()))));
                result.put("backing", handle.backing);
            } else if ("prepare".equals(operation)) {
                String bodyBase64 = string(object, "bodyBase64");
                // Reject by encoded length before decoding/allocating a body.
                if (bodyBase64.length() > 1398104) throw new IllegalArgumentException();
                byte[] body = Base64.getDecoder().decode(bodyBase64);
                if (body.length > 1048576 || !Base64.getEncoder().encodeToString(body).equals(bodyBase64)) throw new IllegalArgumentException();
                long created = integer(object, "created"), expires = integer(object, "expires"), now = clock.getAsLong();
                if (now < 0 || now > 999999999999999L || created > now + 30 || now >= expires) throw new IllegalArgumentException();
                RequestSigner.Input input = new RequestSigner.Input(string(object, "method"), string(object, "target"), body,
                        string(object, "contentType"), string(object, "authorization"), string(object, "appId"), string(object, "keyId"),
                        string(object, "origin"), created, expires, string(object, "nonce"));
                // The key is loaded lazily: typed validation and header limits run before persistent I/O.
                RequestSigner.Prepared prepared = new RequestSigner().prepare(input, key);
                JSONArray headers = new JSONArray();
                for (RequestSigner.Header header : prepared.headers()) headers.put(new JSONArray().put(header.name).put(header.value));
                result.put("origin", string(object, "origin")).put("method", prepared.method()).put("target", prepared.target())
                        .put("bodyBase64", Base64.getEncoder().encodeToString(prepared.body())).put("keyId", prepared.keyId()).put("headers", headers);
            } else {
                Object value = object.get("challenge");
                if (!(value instanceof Map)) throw new IllegalArgumentException();
                @SuppressWarnings("unchecked") Map<String, Object> challenge = (Map<String, Object>) value;
                requireFields(challenge, CHALLENGE);
                EnrollmentProof.Challenge input = new EnrollmentProof.Challenge(string(challenge, "appId"), string(challenge, "origin"),
                        string(challenge, "subject"), string(challenge, "keyId"), string(challenge, "publicKeySha256"),
                        string(challenge, "nonce"), integer(challenge, "expires"));
                EnrollmentProof.Result proof = EnrollmentProof.create(input, string(object, "expectedAppId"), string(object, "expectedOrigin"),
                        string(object, "expectedSubject"), string(object, "expectedKeyId"), clock.getAsLong(), key);
                result.put("proofBase64", Base64.getEncoder().encodeToString(proof.proof()))
                        .put("clientDataHashBase64", Base64.getEncoder().encodeToString(proof.clientDataHash()))
                        .put("googleRequestHash", proof.googleRequestHash());
            }
            return new JSONObject().put("ok", true).put("result", result).toString();
        } catch (KeyUnavailable error) {
            return failure("APPGUARD_KEY_UNAVAILABLE");
        } catch (IllegalArgumentException error) {
            return failure("APPGUARD_INVALID_INPUT");
        } catch (Exception error) {
            return failure("APPGUARD_OPERATION_FAILED");
        }
    }

    private final class LazyKey implements RequestSigner.PublicSigningKey {
        private final String alias;
        private final AndroidInstallationKey.Requirement requirement;
        private KeyHandle handle;
        LazyKey(String alias, AndroidInstallationKey.Requirement requirement) { this.alias = alias; this.requirement = requirement; }
        KeyHandle load() {
            if (handle == null) {
                try {
                    handle = keys.load(alias, requirement);
                    if (handle == null || handle.key == null || handle.backing == null) throw new KeyUnavailable();
                } catch (Exception error) { throw new KeyUnavailable(); }
            }
            return handle;
        }
        @Override public byte[] signDer(byte[] base) throws GeneralSecurityException { return load().key.signDer(base); }
        @Override public byte[] publicKeySpki() throws GeneralSecurityException { return load().key.publicKeySpki(); }
    }
    private static final class KeyUnavailable extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static void requireFields(Map<String, Object> object, Set<String> expected) {
        if (!object.keySet().equals(expected)) throw new IllegalArgumentException();
    }
    private static String string(Map<String, Object> object, String name) {
        Object value = object.get(name); if (!(value instanceof String)) throw new IllegalArgumentException(); return (String) value;
    }
    private static long integer(Map<String, Object> object, String name) {
        Object value = object.get(name); if (!(value instanceof Long)) throw new IllegalArgumentException(); return (Long) value;
    }
    private static String failure(String code) { return "{\"ok\":false,\"error\":{\"code\":\"" + code + "\"}}"; }

    /** This schema has only objects, strings and unsigned integers. Reject all other JSON values,
     * duplicate decoded keys, invalid UTF-16, non-JSON whitespace and numeric coercions. Depth is bounded. */
    private static final class StrictJSON {
        private final String text;
        private int at;
        private StrictJSON(String text) { this.text = text; }
        static Map<String, Object> parse(String text) {
            if (text == null || text.length() > MAX_JSON_BYTES || text.getBytes(StandardCharsets.UTF_8).length > MAX_JSON_BYTES) invalid();
            StrictJSON parser = new StrictJSON(text); Map<String, Object> result = parser.object(0); parser.whitespace();
            if (parser.at != text.length()) invalid(); return result;
        }
        private Map<String, Object> object(int depth) {
            if (depth > 2) invalid(); whitespace(); expect('{'); whitespace(); Map<String, Object> result = new LinkedHashMap<>();
            if (take('}')) return result;
            while (true) {
                whitespace(); String name = quoted(); whitespace(); expect(':'); whitespace();
                if (at == text.length() || result.containsKey(name)) invalid();
                char ch = text.charAt(at); Object value;
                if (ch == '"') value = quoted();
                else if (ch == '{') value = object(depth + 1);
                else value = number();
                result.put(name, value); whitespace();
                if (take('}')) return result; expect(',');
            }
        }
        private Long number() {
            int start = at;
            if (at >= text.length() || text.charAt(at) < '0' || text.charAt(at) > '9') invalid();
            while (at < text.length() && text.charAt(at) >= '0' && text.charAt(at) <= '9') at++;
            String token = text.substring(start, at);
            if (token.length() > 15 || token.length() > 1 && token.charAt(0) == '0') invalid();
            return Long.valueOf(token);
        }
        private String quoted() {
            expect('"'); StringBuilder out = new StringBuilder();
            while (at < text.length()) {
                char ch = text.charAt(at++);
                if (ch == '"') {
                    String result = out.toString();
                    for (int i = 0; i < result.length(); i++) {
                        char unit = result.charAt(i);
                        if (Character.isHighSurrogate(unit)) {
                            if (++i >= result.length() || !Character.isLowSurrogate(result.charAt(i))) invalid();
                        } else if (Character.isLowSurrogate(unit)) invalid();
                    }
                    return result;
                }
                if (ch < 32) invalid();
                if (ch == '\\') {
                    if (at == text.length()) invalid(); char escape = text.charAt(at++);
                    switch (escape) {
                        case '"': case '\\': case '/': ch = escape; break;
                        case 'b': ch = '\b'; break; case 'f': ch = '\f'; break; case 'n': ch = '\n'; break;
                        case 'r': ch = '\r'; break; case 't': ch = '\t'; break;
                        case 'u':
                            if (at + 4 > text.length()) invalid(); int unit = 0;
                            for (int i = 0; i < 4; i++) {
                                char hex = text.charAt(at++); int digit = hex >= '0' && hex <= '9' ? hex - '0' : hex >= 'a' && hex <= 'f' ? hex - 'a' + 10 : hex >= 'A' && hex <= 'F' ? hex - 'A' + 10 : -1;
                                if (digit < 0) invalid(); unit = unit * 16 + digit;
                            }
                            ch = (char) unit; break;
                        default: invalid();
                    }
                }
                out.append(ch);
            }
            invalid(); return "";
        }
        private void whitespace() { while (at < text.length() && " \t\r\n".indexOf(text.charAt(at)) >= 0) at++; }
        private boolean take(char ch) { if (at < text.length() && text.charAt(at) == ch) { at++; return true; } return false; }
        private void expect(char ch) { if (!take(ch)) invalid(); }
        private static void invalid() { throw new IllegalArgumentException(); }
    }
}
