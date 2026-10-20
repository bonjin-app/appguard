package io.appguard;
import java.util.*;
/** Allowlisted audit metadata. IDs must be opaque and must not contain credentials or user IDs. */
public final class AuditEvent {
    private final Map<String,Object> fields;
    private AuditEvent(Map<String,Object> fields) { this.fields=Collections.unmodifiableMap(new LinkedHashMap<>(fields)); }
    public static AuditEvent create(PolicyDecision decision,String eventId,String appId,long now) { return create(decision,eventId,appId,now,null); }
    public static AuditEvent create(PolicyDecision decision,String eventId,String appId,long now,PolicyContext context) {
        if(decision==null||!PolicyValidation.decision(decision.action(),decision.code(),decision.profile())||!identifier(eventId)||!identifier(appId)||!PolicyValidation.time(now))throw new AuditException();
        Map<String,Object> event=new LinkedHashMap<>();
        event.put("schema_version","appguard-audit-v0");event.put("event_id",eventId);event.put("app_id",appId);event.put("at",now);event.put("action",decision.action());event.put("code",decision.code());event.put("profile",decision.profile());
        if(context!=null){event.put("risk_count",context.riskSignals().size());event.put("attestation_state",context.attestation());}
        return new AuditEvent(event);
    }
    private static boolean identifier(String value) { return value!=null&&value.matches("[A-Za-z0-9._:-]{1,128}"); }
    public Map<String,Object> toMap() { return fields; }
}
