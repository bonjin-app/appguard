package io.appguard;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
/** Test-only interoperability probe; never packaged in the SDK JAR. */
public final class RedisClaimCli {
    public static void main(String[] args)throws Exception{
        if(args.length!=6)throw new IllegalArgumentException("Expected url app key nonce expires now");
        LettuceConnectionFactory factory=RedisIntegrationTest.connection(args[0]);
        try{System.out.println(new RedisReplayStore(new StringRedisTemplate(factory)).claim(new ReplayScope(args[1],args[2],args[3]),Long.parseLong(args[4]),Long.parseLong(args[5]))?"CLAIMED":"REPLAY_DETECTED");}
        finally{factory.destroy();}
    }
}
