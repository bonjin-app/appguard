package io.appguard;
public record KeyRecord(String appId,String keyId,String subject,byte[] publicKeyPem,String algorithm,boolean revoked) {
    public KeyRecord {if(publicKeyPem!=null) publicKeyPem=publicKeyPem.clone();}
    @Override public byte[] publicKeyPem(){return publicKeyPem==null ? null : publicKeyPem.clone();}
    boolean validResolverContract(){return Canonical.validIdentifier(appId) && Canonical.validIdentifier(keyId) && Canonical.validIdentifier(subject) && publicKeyPem!=null && algorithm!=null;}
    @Override public String toString(){return "KeyRecord[redacted]";}
}
