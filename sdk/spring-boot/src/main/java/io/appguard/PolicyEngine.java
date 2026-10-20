package io.appguard;
/** Pure deterministic policy; no authentication, provider calls, counters or HTTP installation. */
public final class PolicyEngine {
    private PolicyEngine() {}
    public static PolicyDecision evaluate(String profile,PolicyContext context,long now) { return evaluate(new Policy(profile),context,now); }
    public static PolicyDecision evaluate(Policy policy,PolicyContext context,long now) {
        if(policy==null)throw new PolicyException("INVALID_POLICY");
        if(context==null||!PolicyValidation.time(now))throw new PolicyException("INVALID_POLICY_CONTEXT");
        String deny=null;
        if(context.authentication().equals("missing"))deny="AUTHENTICATION_REQUIRED";
        else if(context.authentication().equals("invalid"))deny="AUTHENTICATION_INVALID";
        else if(context.verification().equals("rejected"))deny="REQUEST_REJECTED";
        else if(context.verification().equals("unavailable"))deny="VERIFICATION_UNAVAILABLE";
        else if(context.attestation().equals("rejected"))deny="ATTESTATION_REJECTED";
        else if(context.verification().equals("missing")&&policy.requireSignature())deny="SIGNATURE_REQUIRED";
        else if(context.rateLimited())deny="RATE_LIMITED";
        if(deny!=null)return new PolicyDecision("deny",deny,policy.profile());
        String observation=null;
        if(!context.attestation().equals("verified"))observation=switch(context.attestation()){case "missing"->"ATTESTATION_MISSING";case "unsupported"->"ATTESTATION_UNSUPPORTED";default->"ATTESTATION_UNAVAILABLE";};
        else if(context.attestationExpires()==null||now>=context.attestationExpires())observation="ATTESTATION_EXPIRED";
        else if(context.riskSignals().stream().anyMatch(policy.suspiciousSignals()::contains))observation="RISK_DETECTED";
        return observation==null?new PolicyDecision("allow","ALLOWED",policy.profile()):new PolicyDecision(PolicyValidation.observation(policy.profile()),observation,policy.profile());
    }
}
