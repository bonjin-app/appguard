package io.appguard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.*;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.*;

class CorpusTest {
    static final ObjectMapper JSON = new ObjectMapper();
    static List<JsonNode> vectors(String file) throws Exception {
        JsonNode root = JSON.readTree(Path.of(System.getProperty("appguard.corpus"), file + ".json").toFile());
        List<JsonNode> rows = new ArrayList<>(); root.forEach(rows::add); return rows;
    }
    static List<Header> headers(JsonNode rows) {
        List<Header> result = new ArrayList<>();
        rows.forEach(p -> result.add(new Header(p.get(0).asText(), p.get(1).asText()))); return result;
    }
    static SignatureParameters parameters(JsonNode p) {
        return new SignatureParameters(p.get("created").longValue(), p.get("expires").longValue(), p.get("nonce").asText(), p.get("key_id").asText(), p.get("algorithm").asText(), p.get("tag").asText());
    }
    @TestFactory Stream<DynamicTest> coreCorpus() throws Exception {
        List<JsonNode> rows = vectors("requests"); assertThat(rows).hasSize(40);
        return rows.stream().map(row -> DynamicTest.dynamicTest(row.get("id").asText(), () -> {
            JsonNode r = row.get("request"), c = row.get("context"), k = row.get("key");
            RequestInput input = new RequestInput(r.get("method").asText(), r.get("target").asText(), headers(r.get("headers")), Base64.getDecoder().decode(r.get("body_b64").asText()));
            SignatureParameters params = parameters(row.get("parameters"));
            if (!row.get("expected_signature_base").isNull()) {
                assertThat(new String(Canonical.signatureBase(input, params, c.get("origin").asText()), StandardCharsets.US_ASCII)).isEqualTo(row.get("expected_signature_base").asText());
            } else {
                assertThatThrownBy(() -> Canonical.signatureBase(input, params, c.get("origin").asText())).isInstanceOf(VerificationException.class);
            }
            KeyRecord key = new KeyRecord(k.get("app_id").asText(), k.get("key_id").asText(), k.get("subject").asText(), k.get("public_key_pem").asText().getBytes(StandardCharsets.US_ASCII), k.get("algorithm").asText(), k.get("revoked").booleanValue());
            ReplayStore replay = new LocalReplayStore(10000);
            if (row.get("replay_store").asText().equals("unavailable")) replay = (scope, expires, now) -> { throw new IllegalStateException("secret backend failure"); };
            if (row.get("replay_store").asText().equals("full")) {
                LocalReplayStore store = new LocalReplayStore(1);
                store.claim(new ReplayScope("occupied", "occupied", "AAAAAAAAAAAAAAAAAAAAAA"), 1700000120, 1700000000); replay = store;
            }
            List<String> actual = new ArrayList<>();
            for (JsonNode ignored : row.get("expected_codes")) {
                try {
                    actual.add(Verifier.verify(input, params, Base64.getDecoder().decode(row.get("signature_b64").asText()), c.get("origin").asText(), c.get("app_id").asText(), c.get("subject").asText(), key, c.get("now").longValue(), replay).code());
                } catch (VerificationException e) { actual.add(e.code()); }
            }
            List<String> expected = new ArrayList<>(); row.get("expected_codes").forEach(v -> expected.add(v.asText()));
            assertThat(actual).isEqualTo(expected);
        }));
    }
    @TestFactory Stream<DynamicTest> wireCorpus() throws Exception {
        List<JsonNode> rows = vectors("http"); assertThat(rows).hasSize(43);
        return rows.stream().map(row -> DynamicTest.dynamicTest(row.get("id").asText(), () -> {
            String code;
            try {
                ParsedSignature parsed = Wire.parse(headers(row.get("headers")));
                code = "PARSED";
                assertThat(parsed.parameters()).isEqualTo(parameters(row.get("expected").get("parameters")));
                assertThat(Base64.getEncoder().encodeToString(parsed.signature())).isEqualTo(row.get("expected").get("signature_b64").asText());
            } catch (VerificationException e) { code = e.code(); }
            assertThat(code).isEqualTo(row.get("expected_code").asText());
        }));
    }
}
