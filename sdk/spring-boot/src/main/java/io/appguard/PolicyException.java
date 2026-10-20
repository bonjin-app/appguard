package io.appguard;
/** Fixed redacted policy validation error. */
public final class PolicyException extends IllegalArgumentException {
    private final String code;
    public PolicyException(String code) { super(fixed(code)); this.code=fixed(code); }
    private static String fixed(String code) { return "INVALID_POLICY_CONTEXT".equals(code)||"INVALID_POLICY_DECISION".equals(code)?code:"INVALID_POLICY"; }
    public String code() { return code; }
}
