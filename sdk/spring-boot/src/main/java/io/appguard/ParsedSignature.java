package io.appguard;
public record ParsedSignature(SignatureParameters parameters,byte[] signature) {
    public ParsedSignature {signature=signature.clone();}
    @Override public byte[] signature(){return signature.clone();}
    @Override public String toString(){return "ParsedSignature[redacted]";}
}
