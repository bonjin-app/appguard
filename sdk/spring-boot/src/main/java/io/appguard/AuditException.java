package io.appguard;
public final class AuditException extends IllegalArgumentException {
    public AuditException() { super("INVALID_AUDIT_EVENT"); }
    public String code() { return "INVALID_AUDIT_EVENT"; }
}
