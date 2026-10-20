package io.appguard;
public final class AuditUnavailableException extends RuntimeException {
    public AuditUnavailableException() { super("AUDIT_UNAVAILABLE",null,false,true); }
    public String code() { return "AUDIT_UNAVAILABLE"; }
}
