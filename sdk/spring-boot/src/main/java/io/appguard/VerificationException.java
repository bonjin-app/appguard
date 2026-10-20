package io.appguard;
/** Fixed reason only: no request data or dependency exception is retained. */
public final class VerificationException extends RuntimeException {
    private final String code;
    VerificationException(String code){super(code,null,false,false);this.code=code;}
    public String code(){return code;}
}
