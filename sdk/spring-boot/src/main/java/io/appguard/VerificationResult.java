package io.appguard;
public record VerificationResult(String appId,String keyId,long expires) {public String code(){return "VERIFIED";}}
