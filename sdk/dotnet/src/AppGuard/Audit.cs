using System.Text.Json;
using System.Text.Json.Serialization;
namespace AppGuard;
public sealed class AuditException():Exception("INVALID_AUDIT_EVENT");
public sealed class AuditUnavailableException():Exception("AUDIT_UNAVAILABLE");
/// <summary>A closed schema. Use opaque event IDs, never credential or user identifiers.</summary>
public sealed class AuditEvent
{
    [JsonPropertyName("schema_version")]public string SchemaVersion=>"appguard-audit-v0";
    [JsonPropertyName("event_id")]public string EventId{get;}
    [JsonPropertyName("app_id")]public string AppId{get;}
    [JsonPropertyName("at")]public long At{get;}
    [JsonPropertyName("action")]public string Action{get;}
    [JsonPropertyName("code")]public string Code{get;}
    [JsonPropertyName("profile")]public string Profile{get;}
    [JsonPropertyName("risk_count"),JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]public int? RiskCount{get;}
    [JsonPropertyName("attestation_state"),JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]public string? AttestationState{get;}
    public AuditEvent(PolicyDecision decision,string eventId,string appId,long now,PolicyContext? context=null)
    {
        if(decision is null||!Validation.IsIdentifier(eventId)||!Validation.IsIdentifier(appId)||!Validation.IsTime(now))throw new AuditException();
        EventId=eventId;AppId=appId;At=now;Action=decision.Action;Code=decision.Code;Profile=decision.Profile;
        if(context is not null){RiskCount=context.RiskSignals.Count;AttestationState=context.Attestation;}
    }
    public string ToJson()=>JsonSerializer.Serialize(this);
}
/// <summary>Injected callback only; host owns retention and the impact of sink availability.</summary>
public sealed class JsonAuditSink
{
    readonly Func<string,CancellationToken,ValueTask> _callback;
    public JsonAuditSink(Func<string,CancellationToken,ValueTask> callback){_callback=callback??throw new AuditException();}
    public async ValueTask EmitAsync(PolicyDecision decision,string eventId,string appId,long now,PolicyContext? context=null,CancellationToken cancellationToken=default)
    {
        var json=new AuditEvent(decision,eventId,appId,now,context).ToJson();bool failed=false;
        try{await _callback(json,cancellationToken).ConfigureAwait(false);}catch(Exception){failed=true;}
        if(failed)throw new AuditUnavailableException();
    }
}
