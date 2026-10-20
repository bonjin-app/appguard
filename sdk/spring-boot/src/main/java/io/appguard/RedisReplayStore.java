package io.appguard;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import org.springframework.data.redis.core.StringRedisTemplate;
/** Uses one atomic SET key 1 NX EX ttl through the caller's long-lived Redis client. */
public final class RedisReplayStore implements ReplayStore {
    private final StringRedisTemplate redis;
    public RedisReplayStore(StringRedisTemplate redis){this.redis=Objects.requireNonNull(redis);}
    public static String redisKey(ReplayScope scope){
        ReplayValidation.scope(scope);
        String compact="[\""+scope.appId()+"\",\""+scope.keyId()+"\",\""+scope.nonce()+"\"]";
        return "appguard:v0:replay:"+HexFormat.of().formatHex(Canonical.sha256(compact.getBytes(StandardCharsets.UTF_8)));
    }
    @Override public Boolean claim(ReplayScope scope,long expires,long now){
        ReplayValidation.validate(scope,expires,now);
        Boolean result=redis.opsForValue().setIfAbsent(redisKey(scope),"1",Duration.ofSeconds(expires-now));
        if(result==null) throw new IllegalStateException("Replay backend unavailable");return result;
    }
}
