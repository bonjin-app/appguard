package io.appguard;
import java.util.*;
/** Explicit DEVELOPMENT/TEST ONLY: volatile, single-process, no restart protection. */
public final class LocalReplayStore implements ReplayStore {
    private final Map<ReplayScope,Long> claims=new HashMap<>(); private final int capacity;
    public LocalReplayStore(){this(10000);}
    public LocalReplayStore(int capacity){if(capacity<1) throw new IllegalArgumentException("Invalid capacity");this.capacity=capacity;}
    @Override public synchronized Boolean claim(ReplayScope scope,long expires,long now){
        ReplayValidation.validate(scope,expires,now);
        claims.values().removeIf(deadline->deadline<=now);
        if(claims.containsKey(scope)) return false;
        if(claims.size()>=capacity) throw new IllegalStateException("Replay capacity unavailable");
        claims.put(scope,expires);return true;
    }
}
