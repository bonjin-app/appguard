package io.appguard;

import org.junit.jupiter.api.Test;
import java.util.*;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

class ReplayStoreTest {
    static final ReplayScope SCOPE = new ReplayScope("test-app", "test-key", "AAECAwQFBgcICQoLDA0ODw");
    @Test void keyMatchesIndependentCompactJsonSha256() {
        assertThat(RedisReplayStore.redisKey(SCOPE)).isEqualTo("appguard:v0:replay:c477776aa9721c0eeb63f6c4ac1da557ef881275dfa615668047c33275797a55");
    }
    @Test void atomicClaimRejectsAllButOneConcurrentCallerAndExpires() throws Exception {
        LocalReplayStore store = new LocalReplayStore(2);
        ExecutorService pool = Executors.newFixedThreadPool(12);
        try {
            List<Callable<Boolean>> claims = new ArrayList<>();
            for (int i=0;i<40;i++) claims.add(() -> store.claim(SCOPE,120,0));
            int accepted = 0; for(Future<Boolean> f:pool.invokeAll(claims)) if(f.get()) accepted++;
            assertThat(accepted).isEqualTo(1);
            assertThat(store.claim(SCOPE,240,120)).isTrue();
        } finally {pool.shutdownNow();}
    }
    @Test void capacityAndInvalidDeadlinesFailClosed() {
        LocalReplayStore store = new LocalReplayStore(1); store.claim(SCOPE,120,0);
        assertThatThrownBy(() -> store.claim(new ReplayScope("other", "key", "AAAAAAAAAAAAAAAAAAAAAA"),120,0)).isInstanceOf(IllegalStateException.class);
        for(long expires:new long[]{0,151,-1}) assertThatThrownBy(() -> store.claim(SCOPE,expires,0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RedisReplayStore.redisKey(new ReplayScope("bad app", "key", "AAAAAAAAAAAAAAAAAAAAAA"))).isInstanceOf(IllegalArgumentException.class);
    }
}
