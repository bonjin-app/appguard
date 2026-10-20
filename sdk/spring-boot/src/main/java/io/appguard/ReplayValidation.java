package io.appguard;
final class ReplayValidation {
    private ReplayValidation(){}
    static void scope(ReplayScope scope){
        try{if(scope==null) throw new IllegalArgumentException();Canonical.identifier(scope.appId());Canonical.identifier(scope.keyId());Canonical.nonce(scope.nonce());}
        catch(RuntimeException e){throw new IllegalArgumentException("Invalid replay scope");}
    }
    static void validate(ReplayScope scope,long expires,long now){
        scope(scope);if(!Canonical.validTime(expires)||!Canonical.validTime(now)||expires<=now||expires-now>150) throw new IllegalArgumentException("Invalid replay deadline");
    }
}
