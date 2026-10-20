package io.appguard.android;

import org.json.*;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

/** The real JCA key is ephemeral; these tests never access Android Keystore. */
public class NativeBridgeTest {
    static final long NOW = 1700000000L;
    static final String ORIGIN = "https://api.example.test";
    static final String NONCE = "AAECAwQFBgcICQoLDA0ODw";
    static JSONObject common() throws Exception { return new JSONObject().put("alias", "test-installation").put("hardwareRequirement", "any"); }
    static JSONObject request() throws Exception {
        return common().put("origin", ORIGIN).put("method", "POST").put("target", "/v1/items?b=2&a=1&a=%2f?")
            .put("bodyBase64", "AP+AQQ==").put("contentType", "application/octet-stream").put("authorization", "Bearer TEST_ONLY_TOKEN")
            .put("appId", "test-app").put("keyId", "test-key").put("created", NOW).put("expires", NOW + 120).put("nonce", NONCE);
    }
    static KeyPair pair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec("secp256r1")); return g.generateKeyPair();
    }
    static NativeBridge bridge(KeyPair pair, AtomicInteger loads) throws Exception {
        JcaSigningKey key = new JcaSigningKey(pair);
        return new NativeBridge((alias, requirement) -> { loads.incrementAndGet(); return new NativeBridge.KeyHandle(key, "SOFTWARE"); }, () -> NOW);
    }
    static JSONObject success(String text) throws Exception { JSONObject response = new JSONObject(text); assertTrue(text, response.getBoolean("ok")); return response.getJSONObject("result"); }
    static Set<String> keys(JSONObject object) { Set<String> keys = new HashSet<>(); object.keys().forEachRemaining(keys::add); return keys; }
    static void error(String code, String actual) throws Exception {
        JSONObject response = new JSONObject(actual); assertFalse(actual, response.getBoolean("ok"));
        assertEquals(Set.of("ok", "error"), keys(response)); assertEquals(Set.of("code"), keys(response.getJSONObject("error")));
        assertEquals(code, response.getJSONObject("error").getString("code"));
    }
    static String header(JSONArray headers, int index, String name) throws Exception {
        JSONArray h = headers.getJSONArray(index); assertEquals(2, h.length()); assertEquals(name, h.getString(0)); return h.getString(1);
    }
    @Test public void signsExactBinaryTargetAndOrderedHeadersWithIndependentVerifier() throws Exception {
        KeyPair pair = pair(); AtomicInteger loads = new AtomicInteger(); NativeBridge bridge = bridge(pair, loads);
        JSONObject out = success(bridge.invoke("prepare", request().toString()));
        assertEquals("/v1/items?b=2&a=1&a=%2f?", out.getString("target")); assertEquals("AP+AQQ==", out.getString("bodyBase64"));
        assertEquals(ORIGIN, out.getString("origin")); assertEquals("POST", out.getString("method")); assertEquals("test-key", out.getString("keyId"));
        JSONArray h = out.getJSONArray("headers"); assertEquals(6, h.length());
        assertEquals("application/octet-stream", header(h, 0, "Content-Type"));
        String digest = header(h, 1, "Content-Digest"); assertEquals("Bearer TEST_ONLY_TOKEN", header(h, 2, "Authorization"));
        assertEquals("test-app", header(h, 3, "AppGuard-App-Id")); String params = "(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\");created=1700000000;expires=1700000120;nonce=\"AAECAwQFBgcICQoLDA0ODw\";keyid=\"test-key\";alg=\"ecdsa-p256-sha256\";tag=\"appguard-request-v0\"";
        assertEquals("appguard=" + params, header(h, 4, "Signature-Input"));
        String wire = header(h, 5, "Signature"); byte[] raw = Base64.getDecoder().decode(wire.substring(10, wire.length() - 1));
        String base = "\"@method\": POST\n\"@target-uri\": https://api.example.test/v1/items?b=2&a=1&a=%2f?\n\"content-type\": application/octet-stream\n\"content-digest\": " + digest + "\n\"authorization\": Bearer TEST_ONLY_TOKEN\n\"appguard-app-id\": test-app\n\"@signature-params\": " + params;
        assertEquals("sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(new byte[]{0, (byte)255, (byte)128, 65})) + ":", digest);
        Signature verifier = Signature.getInstance("SHA256withECDSA"); verifier.initVerify(pair.getPublic()); verifier.update(base.getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(RequestSignerTest.rawToDer(raw))); assertEquals(1, loads.get());
        JSONObject empty = success(bridge.invoke("prepare", request().put("target", "/x?").put("bodyBase64", "").toString()));
        assertEquals("/x?", empty.getString("target")); assertEquals("", empty.getString("bodyBase64"));
    }
    @Test public void exportsOnlyPublicKeyAndExplicitBacking() throws Exception {
        KeyPair pair = pair(); JSONObject out = success(bridge(pair, new AtomicInteger()).invoke("publicKey", common().toString()));
        assertEquals(Set.of("publicKeyPem", "backing"), keys(out)); assertEquals("SOFTWARE", out.getString("backing"));
        assertArrayEquals(pair.getPublic().getEncoded(), Base64.getMimeDecoder().decode(out.getString("publicKeyPem").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")));
    }
    static JSONObject enrollment(KeyPair pair) throws Exception {
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pair.getPublic().getEncoded()));
        JSONObject challenge = new JSONObject().put("appId", "test-app").put("origin", ORIGIN).put("subject", "test-user").put("keyId", "test-key")
            .put("publicKeySha256", hash).put("nonce", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").put("expires", NOW + 120);
        return common().put("challenge", challenge).put("expectedAppId", "test-app").put("expectedOrigin", ORIGIN).put("expectedSubject", "test-user").put("expectedKeyId", "test-key");
    }
    @Test public void enrollmentProofIndependentlyVerifiesExactBindingAndHashes() throws Exception {
        KeyPair pair = pair(); JSONObject payload = enrollment(pair); JSONObject out = success(bridge(pair, new AtomicInteger()).invoke("enrollmentProof", payload.toString()));
        String message = "appguard-enrollment-v0\napp-id: test-app\norigin: https://api.example.test\nsubject: test-user\nkey-id: test-key\npublic-key-sha256: " + payload.getJSONObject("challenge").getString("publicKeySha256") + "\nchallenge: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\nexpires: 1700000120";
        byte[] bytes = message.getBytes(StandardCharsets.US_ASCII), hash = MessageDigest.getInstance("SHA-256").digest(bytes);
        Signature verifier = Signature.getInstance("SHA256withECDSA"); verifier.initVerify(pair.getPublic()); verifier.update(bytes);
        assertTrue(verifier.verify(RequestSignerTest.rawToDer(Base64.getDecoder().decode(out.getString("proofBase64")))));
        assertArrayEquals(hash, Base64.getDecoder().decode(out.getString("clientDataHashBase64")));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(hash), out.getString("googleRequestHash"));
    }
    @Test public void rejectsMalformedTypesEncodingsAndAmbiguousJsonBeforeKeyLookup() throws Exception {
        AtomicInteger loads = new AtomicInteger(); NativeBridge bridge = bridge(pair(), loads);
        List<String> invalid = new ArrayList<>(List.of("", "[]", "null", "{}", "{'alias':'x'}", "{alias:1}", common() + "x",
            "{\"alias\":\"x\",\"alias\":\"y\",\"hardwareRequirement\":\"any\"}", "{\"alias\":\"x\",\"\\u0061lias\":\"y\",\"hardwareRequirement\":\"any\"}",
            "{\"alias\":\"x\",\"hardwareRequirement\":\"any\",}", "{\"alias\":\"\\ud800\",\"hardwareRequirement\":\"any\"}"));
        for(Object value : new Object[]{1, true, JSONObject.NULL, new JSONArray()}) invalid.add(common().put("alias", value).toString());
        invalid.add(common().put("hardwareRequirement", "software").toString()); invalid.add(common().put("privateKey", "secret").toString());
        for(String payload : invalid) error("APPGUARD_INVALID_INPUT", bridge.invoke("publicKey", payload));
        for(String body : List.of("AA", "AB==", "AA==\n", "_-8=", "A===", "!")) error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", request().put("bodyBase64", body).toString()));
        for(String field : List.of("created", "expires")) {
            for(String number : List.of("true", "null", "1.0", "1e3", "01", "-1", "1000000000000000", "9999999999999999999999", "\"1700000000\"")) {
                String payload = request().toString().replace("\"" + field + "\":" + (field.equals("created") ? NOW : NOW + 120), "\"" + field + "\":" + number);
                error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", payload));
            }
        }
        for(String field : List.of("origin", "method", "target", "contentType", "authorization", "appId", "keyId", "nonce"))
            error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", request().put(field, "\ninvalid").toString()));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", request().put("created", NOW + 31).put("expires", NOW + 100).toString()));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", request().put("created", NOW - 120).put("expires", NOW).toString()));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", request().put("clock", NOW).toString()));
        assertEquals(0, loads.get());
    }
    @Test public void rejectsInvalidEnrollmentBindingsAndDuplicateChallengeBeforeKeyLookup() throws Exception {
        KeyPair pair = pair(); AtomicInteger loads = new AtomicInteger(); NativeBridge bridge = bridge(pair, loads);
        for(String field : List.of("expectedAppId", "expectedOrigin", "expectedSubject", "expectedKeyId"))
            error("APPGUARD_INVALID_INPUT", bridge.invoke("enrollmentProof", enrollment(pair).put(field, field.equals("expectedOrigin") ? "https://other.test" : "other").toString()));
        JSONObject input = enrollment(pair); input.getJSONObject("challenge").put("expires", NOW); error("APPGUARD_INVALID_INPUT", bridge.invoke("enrollmentProof", input.toString()));
        input = enrollment(pair); input.getJSONObject("challenge").put("unexpected", "x"); error("APPGUARD_INVALID_INPUT", bridge.invoke("enrollmentProof", input.toString()));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("enrollmentProof", enrollment(pair).toString().replace("\"subject\":\"test-user\"", "\"subject\":\"test-user\",\"subject\":\"other\"")));
        assertEquals(0, loads.get());
    }
    @Test public void boundsInputAndBodyAndRejectsUnsupportedOperationsBeforeKeyLookup() throws Exception {
        AtomicInteger loads = new AtomicInteger(); NativeBridge bridge = bridge(pair(), loads);
        error("APPGUARD_INVALID_INPUT", bridge.invoke("publicKey", " ".repeat(1500001)));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("publicKey", common().put("alias", "é".repeat(750000)).toString()));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("prepare", request().put("bodyBase64", Base64.getEncoder().encodeToString(new byte[1048577])).toString()));
        for(String operation : List.of("sign", "privateKey", "attest", "")) error("APPGUARD_UNSUPPORTED", bridge.invoke(operation, common().toString()));
        assertEquals(0, loads.get());
    }
    @Test public void acceptsExactBodyAndUtf8JsonLimitsAndUsesNativeClockByDefault() throws Exception {
        AtomicInteger loads = new AtomicInteger(); NativeBridge bridge = bridge(pair(), loads);
        String encoded = Base64.getEncoder().encodeToString(new byte[1048576]);
        assertEquals(encoded, success(bridge.invoke("prepare", request().put("bodyBase64", encoded).toString())).getString("bodyBase64"));
        String small = common().toString();
        success(bridge.invoke("publicKey", small + " ".repeat(1500000 - small.getBytes(StandardCharsets.UTF_8).length)));
        error("APPGUARD_INVALID_INPUT", bridge.invoke("publicKey", small + " ".repeat(1500001 - small.getBytes(StandardCharsets.UTF_8).length)));
        // Expired input must reject using the real native clock, without reaching null Context/key storage.
        error("APPGUARD_INVALID_INPUT", new NativeBridge((android.content.Context) null).invoke("prepare", request().toString()));
        assertEquals(2, loads.get());
    }
    @Test public void passesEveryHardwareRequirementToInstallationKeyLoader() throws Exception {
        KeyPair pair = pair(); JcaSigningKey key = new JcaSigningKey(pair);
        List<AndroidInstallationKey.Requirement> seen = new ArrayList<>();
        NativeBridge bridge = new NativeBridge((alias, requirement) -> { seen.add(requirement); return new NativeBridge.KeyHandle(key, "SOFTWARE"); }, () -> NOW);
        for(String hardware : List.of("any", "hardware", "strongbox"))
            success(bridge.invoke("publicKey", common().put("hardwareRequirement", hardware).toString()));
        assertEquals(List.of(AndroidInstallationKey.Requirement.ANY_KEYSTORE, AndroidInstallationKey.Requirement.HARDWARE_REQUIRED,
            AndroidInstallationKey.Requirement.STRONGBOX_REQUIRED), seen);
    }
    @Test public void redactsKeyLoadAndSigningExceptions() throws Exception {
        NativeBridge unavailable = new NativeBridge((alias, requirement) -> { throw new GeneralSecurityException("Bearer SECRET /private/body"); }, () -> NOW);
        error("APPGUARD_KEY_UNAVAILABLE", unavailable.invoke("publicKey", common().toString()));
        error("APPGUARD_KEY_UNAVAILABLE", unavailable.invoke("prepare", request().toString()));
        NativeBridge broken = new NativeBridge((alias, requirement) -> new NativeBridge.KeyHandle(new RequestSigner.PublicSigningKey() {
            public byte[] signDer(byte[] base) throws GeneralSecurityException { throw new GeneralSecurityException("Bearer SECRET"); }
            public byte[] publicKeySpki() { return new byte[0]; }
        }, "SOFTWARE"), () -> NOW);
        error("APPGUARD_OPERATION_FAILED", broken.invoke("prepare", request().toString()));
    }
}
