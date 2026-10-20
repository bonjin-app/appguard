package io.appguard;
import com.fasterxml.jackson.databind.ObjectMapper;
/** Explicit synchronous callback sink; application owns availability, storage and retention. */
public final class JsonAuditSink {
    @FunctionalInterface public interface Callback { void accept(String json) throws Exception; }
    private static final ObjectMapper JSON=new ObjectMapper();
    private final Callback callback;
    public JsonAuditSink(Callback callback) { if(callback==null)throw new AuditException();this.callback=callback; }
    public void emit(PolicyDecision decision,String eventId,String appId,long now) { emit(decision,eventId,appId,now,null); }
    public void emit(PolicyDecision decision,String eventId,String appId,long now,PolicyContext context) {
        AuditEvent event=AuditEvent.create(decision,eventId,appId,now,context);
        try { callback.accept(JSON.writeValueAsString(event.toMap())); }
        catch(Exception failure) { if(failure instanceof InterruptedException)Thread.currentThread().interrupt(); throw new AuditUnavailableException(); }
    }
}
