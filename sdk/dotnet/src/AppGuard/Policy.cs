using System.Collections.ObjectModel;
namespace AppGuard;

public sealed class PolicyException : Exception
{
    public string Code{get;}
    public PolicyException(string code):base(code is "INVALID_POLICY" or "INVALID_POLICY_CONTEXT" or "INVALID_POLICY_DECISION"?code:"INVALID_POLICY"){Code=Message;}
}
internal static class PolicyValidation
{
    internal static bool Profile(string? profile)=>profile is "basic" or "balanced" or "strict";
    internal static IReadOnlyList<string> Signals(IEnumerable<string> values,string code)
    {
        var copy=new List<string>();var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var value in values)
        {
            if(copy.Count>=32||value is null||value.Length>64||!System.Text.RegularExpressions.Regex.IsMatch(value,@"\A[a-z][a-z0-9_]{0,63}\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant)||!seen.Add(value))throw new PolicyException(code);
            copy.Add(value);
        }
        return new ReadOnlyCollection<string>(copy);
    }
    internal static string ObservationAction(string profile)=>profile switch{"basic"=>"observe","balanced"=>"step_up",_=>"deny"};
}
/// <summary>Only explicit basic server-only policy may disable signature requirements.</summary>
public sealed class Policy
{
    public string Profile{get;}public bool RequireSignature{get;}public IReadOnlyList<string> SuspiciousSignals{get;}
    public Policy(string profile="basic",bool requireSignature=true,IEnumerable<string>? suspiciousSignals=null)
    {
        if(!PolicyValidation.Profile(profile)||!requireSignature&&profile!="basic")throw new PolicyException("INVALID_POLICY");
        Profile=profile;RequireSignature=requireSignature;SuspiciousSignals=PolicyValidation.Signals(suspiciousSignals??["debugger","root","hook","tamper"],"INVALID_POLICY");
    }
}
/// <summary>Server verdicts must come from trusted systems. Risk codes are untrusted hints, never proof.</summary>
public sealed class PolicyContext
{
    public string Authentication{get;}public string Verification{get;}public string Attestation{get;}public long? AttestationExpires{get;}public IReadOnlyList<string> RiskSignals{get;}public bool RateLimited{get;}
    public PolicyContext(string authentication="missing",string verification="missing",string attestation="missing",long? attestationExpires=null,IEnumerable<string>? riskSignals=null,bool rateLimited=false)
    {
        if(authentication is not("authenticated" or "missing" or "invalid")||verification is not("verified" or "missing" or "rejected" or "unavailable")||attestation is not("verified" or "missing" or "unsupported" or "rejected" or "unavailable")||attestationExpires is not null&&!Validation.IsTime(attestationExpires.Value))throw new PolicyException("INVALID_POLICY_CONTEXT");
        Authentication=authentication;Verification=verification;Attestation=attestation;AttestationExpires=attestationExpires;RiskSignals=PolicyValidation.Signals(riskSignals??[],"INVALID_POLICY_CONTEXT");RateLimited=rateLimited;
    }
}
public sealed record PolicyDecision
{
    public string Action{get;}public string Code{get;}public string Profile{get;}
    public bool PermitsProcessing=>Action is "allow" or "observe";
    public PolicyDecision(string action,string code,string profile)
    {
        bool denial=code is "AUTHENTICATION_REQUIRED" or "AUTHENTICATION_INVALID" or "REQUEST_REJECTED" or "VERIFICATION_UNAVAILABLE" or "SIGNATURE_REQUIRED" or "ATTESTATION_REJECTED" or "RATE_LIMITED";
        bool observation=code is "ATTESTATION_MISSING" or "ATTESTATION_UNSUPPORTED" or "ATTESTATION_UNAVAILABLE" or "ATTESTATION_EXPIRED" or "RISK_DETECTED";
        if(!PolicyValidation.Profile(profile)||!(denial&&action=="deny"||observation&&action==PolicyValidation.ObservationAction(profile)||code=="ALLOWED"&&action=="allow"))throw new PolicyException("INVALID_POLICY_DECISION");
        Action=action;Code=code;Profile=profile;
    }
}
public static class PolicyEngine
{
    public static PolicyDecision Evaluate(Policy policy,PolicyContext context,long now)
    {
        if(policy is null)throw new PolicyException("INVALID_POLICY");
        if(context is null||!Validation.IsTime(now))throw new PolicyException("INVALID_POLICY_CONTEXT");
        PolicyDecision Deny(string code)=>new("deny",code,policy.Profile);
        PolicyDecision Observe(string code)=>new(PolicyValidation.ObservationAction(policy.Profile),code,policy.Profile);
        if(context.Authentication=="missing")return Deny("AUTHENTICATION_REQUIRED");
        if(context.Authentication=="invalid")return Deny("AUTHENTICATION_INVALID");
        if(context.Verification=="rejected")return Deny("REQUEST_REJECTED");
        if(context.Verification=="unavailable")return Deny("VERIFICATION_UNAVAILABLE");
        if(context.Attestation=="rejected")return Deny("ATTESTATION_REJECTED");
        if(context.Verification=="missing"&&policy.RequireSignature)return Deny("SIGNATURE_REQUIRED");
        if(context.RateLimited)return Deny("RATE_LIMITED");
        if(context.Attestation!="verified")return Observe(context.Attestation switch{"missing"=>"ATTESTATION_MISSING","unsupported"=>"ATTESTATION_UNSUPPORTED",_=>"ATTESTATION_UNAVAILABLE"});
        if(context.AttestationExpires is null||now>=context.AttestationExpires)return Observe("ATTESTATION_EXPIRED");
        if(context.RiskSignals.Any(s=>policy.SuspiciousSignals.Contains(s)))return Observe("RISK_DETECTED");
        return new("allow","ALLOWED",policy.Profile);
    }
}
