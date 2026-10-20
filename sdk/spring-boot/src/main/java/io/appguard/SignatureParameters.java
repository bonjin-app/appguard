package io.appguard;
public record SignatureParameters(long created,long expires,String nonce,String keyId,String algorithm,String tag) {
    @Override public String toString(){return "SignatureParameters[redacted]";}
}
