package io.appguard;
/** observe permits processing; step_up requires a separate trusted verification flow. */
public record PolicyDecision(String action,String code,String profile) {
    public PolicyDecision { if(!PolicyValidation.decision(action,code,profile))throw new PolicyException("INVALID_POLICY_DECISION"); }
}
