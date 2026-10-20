package io.appguard;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import static org.assertj.core.api.Assertions.*;

class RedisIntegrationTest {
    static LettuceConnectionFactory connection(String url){URI uri=URI.create(url);if(!"redis".equals(uri.getScheme())||!"127.0.0.1".equals(uri.getHost()))throw new IllegalArgumentException("Test Redis must be disposable loopback");RedisStandaloneConfiguration c=new RedisStandaloneConfiguration(uri.getHost(),uri.getPort());c.setDatabase(Integer.parseInt(uri.getPath().substring(1)));LettuceConnectionFactory f=new LettuceConnectionFactory(c);f.afterPropertiesSet();f.start();return f;}
    @Test void liveAtomicClaimsRelativeExpiryAndBackendFailure() throws Exception {
        String url=System.getenv("APPGUARD_REDIS_URL");Assumptions.assumeTrue(url!=null,"Supply isolated disposable APPGUARD_REDIS_URL");
        LettuceConnectionFactory first=connection(url),second=connection(url);StringRedisTemplate a=new StringRedisTemplate(first),b=new StringRedisTemplate(second);RedisReplayStore one=new RedisReplayStore(a),two=new RedisReplayStore(b);
        ReplayScope scope=new ReplayScope("java-"+UUID.randomUUID(),"key","AAECAwQFBgcICQoLDA0ODw");String key=RedisReplayStore.redisKey(scope);ExecutorService pool=Executors.newFixedThreadPool(8);
        try{
            List<Callable<Boolean>> tasks=new ArrayList<>();for(int i=0;i<32;i++){RedisReplayStore store=i%2==0?one:two;tasks.add(()->store.claim(scope,120,0));}
            int claimed=0;for(Future<Boolean> result:pool.invokeAll(tasks))if(result.get())claimed++;
            assertThat(claimed).isEqualTo(1);assertThat(a.opsForValue().get(key)).isEqualTo("1");assertThat(a.getExpire(key)).isBetween(115L,120L);assertThat(two.claim(scope,120,0)).isFalse();
            first.destroy();assertThatThrownBy(()->one.claim(new ReplayScope("failure","key","AAAAAAAAAAAAAAAAAAAAAA"),120,0)).isInstanceOf(RuntimeException.class);
        }finally{pool.shutdownNow();b.delete(key);first.destroy();second.destroy();}
    }
}
