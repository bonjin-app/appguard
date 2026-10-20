package io.appguard;
import java.util.List;
/** Immutable policy configuration; only Basic may explicitly disable request signatures. */
public record Policy(String profile,boolean requireSignature,List<String> suspiciousSignals) {
    public Policy() { this("basic"); }
    public Policy(String profile) { this(profile,true,PolicyValidation.DEFAULT_SIGNALS); }
    public Policy {
        if(!PolicyValidation.profile(profile)||(!requireSignature&&!profile.equals("basic")))throw new PolicyException("INVALID_POLICY");
        suspiciousSignals=PolicyValidation.signals(suspiciousSignals,"INVALID_POLICY");
    }
    @Override public String toString() { return "Policy[profile="+profile+", requireSignature="+requireSignature+"]"; }
}
