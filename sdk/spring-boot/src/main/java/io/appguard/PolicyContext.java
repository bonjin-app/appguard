package io.appguard;
import java.util.List;
/** Trusted server verdicts and bounded untrusted hints. Never trust client status fields. */
public record PolicyContext(String authentication,String verification,String attestation,Long attestationExpires,List<String> riskSignals,boolean rateLimited) {
    public PolicyContext() { this("missing","missing","missing",null,List.of(),false); }
    public PolicyContext {
        if(!PolicyValidation.oneOf(authentication,"authenticated","missing","invalid")
            ||!PolicyValidation.oneOf(verification,"verified","missing","rejected","unavailable")
            ||!PolicyValidation.oneOf(attestation,"verified","missing","unsupported","rejected","unavailable")
            ||(attestationExpires!=null&&!PolicyValidation.time(attestationExpires)))throw new PolicyException("INVALID_POLICY_CONTEXT");
        riskSignals=PolicyValidation.signals(riskSignals,"INVALID_POLICY_CONTEXT");
    }
    @Override public String toString() { return "PolicyContext[authentication="+authentication+", verification="+verification+", attestation="+attestation+", riskCount="+riskSignals.size()+", rateLimited="+rateLimited+"]"; }
}
