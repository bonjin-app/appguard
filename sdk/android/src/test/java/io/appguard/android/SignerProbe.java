package io.appguard.android;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/** Test-only executable: emits public fixture material; never writes or exports a private key. */
public final class SignerProbe {
    private static String json(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair(); JcaSigningKey key = new JcaSigningKey(pair);
        RequestSigner.Input input = new RequestSigner.Input("POST", "/v1/items?b=2&a=1",
                "{}".getBytes(StandardCharsets.US_ASCII), "application/json", "Bearer TEST_ONLY_TOKEN",
                "test-app", "test-key", "https://api.example.test", 1700000000L, 1700000120L,
                "AAECAwQFBgcICQoLDA0ODw");
        final String[] base = {null};
        RequestSigner.Prepared prepared = new RequestSigner().prepare(input, bytes -> {
            base[0] = new String(bytes, StandardCharsets.US_ASCII); return key.signDer(bytes);
        });
        StringBuilder headers = new StringBuilder("["); String signature = null;
        for (RequestSigner.Header h : prepared.headers()) {
            if (headers.length() > 1) headers.append(',');
            headers.append('[').append(json(h.name)).append(',').append(json(h.value)).append(']');
            if (h.name.equals("Signature")) signature = h.value.substring(10, h.value.length() - 1);
        }
        headers.append(']');
        System.out.println("{\"id\":\"android-generated\",\"request\":{\"method\":" + json(prepared.method())
                + ",\"target\":" + json(prepared.target()) + ",\"headers\":" + headers
                + ",\"body_b64\":" + json(Base64.getEncoder().encodeToString(prepared.body()))
                + "},\"parameters\":{\"created\":1700000000,\"expires\":1700000120,\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\",\"key_id\":\"test-key\",\"algorithm\":\"ecdsa-p256-sha256\",\"tag\":\"appguard-request-v0\"},"
                + "\"signature_b64\":" + json(signature) + ",\"key\":{\"app_id\":\"test-app\",\"key_id\":\"test-key\",\"subject\":\"test-user\",\"public_key_pem\":"
                + json(key.publicKeyPem()) + ",\"algorithm\":\"ecdsa-p256-sha256\",\"revoked\":false},"
                + "\"context\":{\"origin\":\"https://api.example.test\",\"app_id\":\"test-app\",\"subject\":\"test-user\",\"now\":1700000000},"
                + "\"replay_store\":\"memory\",\"expected_signature_base\":" + json(base[0]) + ",\"expected_codes\":[\"VERIFIED\"]}");
    }
}
