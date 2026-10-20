package io.appguard.android;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Prepares one immutable request for the experimental appguard-request-v0 profile. */
public final class RequestSigner {
    public static final String ALGORITHM = "ecdsa-p256-sha256";
    public static final String TAG = "appguard-request-v0";
    private static final String COVERED = "(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\")";
    private static final Pattern TOKEN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    private static final Pattern TARGET = Pattern.compile("/[A-Za-z0-9._~!$&'()*+,;=:@/?%\\-]*");
    private static final Pattern ORIGIN = Pattern.compile("https://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?");
    private static final long MAX_TIME = 999999999999999L;

    /** Implementations sign SHA-256/ECDSA P-256 and return canonical ASN.1 DER, not raw r||s. */
    public interface SigningKey {
        byte[] signDer(byte[] signatureBase) throws GeneralSecurityException;
    }

    public interface PublicSigningKey extends SigningKey {
        byte[] publicKeySpki() throws GeneralSecurityException;
    }

    public static final class Header {
        public final String name;
        public final String value;
        public Header(String name, String value) { this.name = name; this.value = value; }
    }

    /** Explicit timestamps enable deterministic tests; servers independently enforce time/skew. */
    public static final class Input {
        private final String method, target, contentType, authorization, appId, keyId, origin, nonce;
        private final byte[] body;
        private final long created, expires;
        public Input(String method, String target, byte[] body, String contentType, String authorization,
                     String appId, String keyId, String origin, long created, long expires, String nonce) {
            if (body != null && body.length > 1048576) invalid();
            this.method = method; this.target = target; this.body = body == null ? null : body.clone();
            this.contentType = contentType; this.authorization = authorization; this.appId = appId;
            this.keyId = keyId; this.origin = origin; this.created = created; this.expires = expires; this.nonce = nonce;
        }
        /** Uses the device clock and OS-backed CSPRNG; the server still judges clock validity. */
        public static Input fresh(String method, String target, byte[] body, String contentType,
                                  String authorization, String appId, String keyId, String origin) {
            byte[] nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);
            long now = Instant.now().getEpochSecond();
            return new Input(method, target, body, contentType, authorization, appId, keyId, origin,
                    now, now + 120, Base64.getUrlEncoder().withoutPadding().encodeToString(nonce));
        }
    }

    public static final class Prepared {
        private final String method, target, keyId;
        private final byte[] body;
        private final List<Header> headers;
        private Prepared(Input in, List<Header> headers) {
            method = in.method; target = in.target; keyId = in.keyId; body = in.body.clone();
            this.headers = Collections.unmodifiableList(new ArrayList<>(headers));
        }
        public String method() { return method; }
        public String target() { return target; }
        /** Server-enrolled identifier; never inferred from a local keystore alias. */
        public String keyId() { return keyId; }
        public byte[] body() { return body.clone(); }
        public List<Header> headers() { return headers; }
    }

    public Prepared prepare(Input in, SigningKey key) throws GeneralSecurityException {
        validate(in);
        if (key == null) invalid();
        String params = COVERED + ";created=" + in.created + ";expires=" + in.expires
                + ";nonce=\"" + in.nonce + "\";keyid=\"" + in.keyId
                + "\";alg=\"" + ALGORITHM + "\";tag=\"" + TAG + "\"";
        // Check the complete six-header envelope budget before hashing or invoking a key.
        List<Header> headers = headers(in, "sha-256=:" + repeat('A', 43) + "=:", params,
                "appguard=:" + repeat('A', 86) + "==:");
        long size = 0;
        for (Header h : headers) size += h.name.length() + h.value.length();
        if (headers.size() > 64 || size > 16384) invalid();
        String digest = "sha-256=:" + Base64.getEncoder().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(in.body)) + ":";
        String base = "\"@method\": " + in.method + "\n\"@target-uri\": " + in.origin + in.target
                + "\n\"content-type\": " + in.contentType + "\n\"content-digest\": " + digest
                + "\n\"authorization\": " + in.authorization + "\n\"appguard-app-id\": " + in.appId
                + "\n\"@signature-params\": " + params;
        byte[] raw = EcdsaP256.derToRaw(key.signDer(base.getBytes(StandardCharsets.US_ASCII)));
        return new Prepared(in, headers(in, digest, params,
                "appguard=:" + Base64.getEncoder().encodeToString(raw) + ":"));
    }

    private static List<Header> headers(Input in, String digest, String params, String signature) {
        List<Header> result = new ArrayList<>(6);
        result.add(new Header("Content-Type", in.contentType));
        result.add(new Header("Content-Digest", digest));
        result.add(new Header("Authorization", in.authorization));
        result.add(new Header("AppGuard-App-Id", in.appId));
        result.add(new Header("Signature-Input", "appguard=" + params));
        result.add(new Header("Signature", signature));
        return result;
    }

    static void validateIdentifier(String value) {
        if (value == null || !IDENTIFIER.matcher(value).matches()) invalid();
    }

    private static void validate(Input in) {
        if (in == null || in.body == null || in.body.length > 1048576 || in.method == null
                || in.method.length() > 32 || !TOKEN.matcher(in.method).matches()
                || !in.method.equals(in.method.toUpperCase(Locale.ROOT))) invalid();
        validateTarget(in.target);
        validateOrigin(in.origin);
        field(in.contentType); field(in.authorization);
        if (in.contentType.isEmpty() || !in.authorization.matches("(?i:Bearer) [A-Za-z0-9._~+/-]+=*")) invalid();
        validateIdentifier(in.appId); validateIdentifier(in.keyId);
        if (in.nonce == null || !in.nonce.matches("[A-Za-z0-9_-]{22}")) invalid();
        byte[] nonce = Base64.getUrlDecoder().decode(in.nonce);
        if (nonce.length != 16 || !Base64.getUrlEncoder().withoutPadding().encodeToString(nonce).equals(in.nonce)) invalid();
        if (in.created < 0 || in.expires < 0 || in.created > MAX_TIME || in.expires > MAX_TIME
                || in.created >= in.expires || in.expires - in.created > 120) {
            throw new IllegalArgumentException("INVALID_TIME");
        }
    }

    private static void field(String value) {
        if (value == null || value.length() > 16384 || value.startsWith(" ") || value.endsWith(" ")) invalid();
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) < 0x20 || value.charAt(i) > 0x7e) invalid();
    }

    static void validateOrigin(String origin) {
        if (origin == null || origin.length() > 512) invalid();
        Matcher match = ORIGIN.matcher(origin);
        if (!match.matches()) invalid();
        String host = match.group(1), port = match.group(2);
        if (host.length() > 253) invalid();
        for (String label : host.split("\\.", -1)) {
            if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) invalid();
        }
        if (port != null && (Integer.parseInt(port) > 65535 || Integer.parseInt(port) == 443)) invalid();
    }

    private static void validateTarget(String target) {
        if (target == null || target.length() > 8192 || target.startsWith("//") || !TARGET.matcher(target).matches()) invalid();
        String decoded = percentDecode(target);
        for (int i = 0; i < decoded.length(); i++) {
            char ch = decoded.charAt(i);
            if (ch < 0x20 || ch == 0x7f || ch == '\\') invalid();
        }
        int query = target.indexOf('?');
        String path = percentDecode(query < 0 ? target : target.substring(0, query));
        for (String segment : path.split("/", -1)) if (segment.equals(".") || segment.equals("..")) invalid();
    }

    private static String percentDecode(String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '%') {
                if (i + 2 >= value.length()) invalid();
                int a = Character.digit(value.charAt(i + 1), 16), b = Character.digit(value.charAt(i + 2), 16);
                if (a < 0 || b < 0) invalid();
                ch = (char) (a * 16 + b); i += 2;
            }
            result.append(ch);
        }
        return result.toString();
    }

    private static String repeat(char value, int count) {
        char[] result = new char[count]; java.util.Arrays.fill(result, value); return new String(result);
    }
    private static void invalid() { throw new IllegalArgumentException("INVALID_REQUEST"); }
}
