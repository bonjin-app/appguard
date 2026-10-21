package io.appguard;

import org.junit.jupiter.api.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.assertj.core.api.Assertions.*;

class KeyEnvelopeTest {
    @TestFactory Stream<DynamicTest> sharedKeyEnvelopes() throws Exception {
        var rows = CorpusTest.vectors("public-key-pem");
        assertThat(rows).hasSize(23);
        return rows.stream().map(row -> DynamicTest.dynamicTest(row.get("id").asText(), () -> {
            var helper = new SecurityBoundaryTest();
            var original = helper.key();
            var key = new KeyRecord(original.appId(), original.keyId(), original.subject(),
                row.get("pem").asText().getBytes(StandardCharsets.UTF_8), original.algorithm(), original.revoked());
            var claims = new AtomicInteger();
            var local = new LocalReplayStore(10);
            ReplayStore store = (scope, expires, now) -> { claims.incrementAndGet(); return local.claim(scope, expires, now); };
            var parameters = SecurityBoundaryTest.p(SignedRequests.NOW, SignedRequests.NOW + 120);
            assertThat(helper.verify(parameters, SignedRequests.NOW, key, store)).isEqualTo(row.get("expected_code").asText());
            if (row.get("expected_code").asText().equals("KEY_REJECTED")) {
                assertThat(claims).hasValue(0);
                assertThat(helper.verify(parameters, SignedRequests.NOW, original, store)).isEqualTo("VERIFIED");
            }
            assertThat(claims).hasValue(1);
        }));
    }
}
