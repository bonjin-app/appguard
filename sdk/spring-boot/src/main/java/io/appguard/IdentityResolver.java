package io.appguard;
import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Objects;
/** Existing authentication must validate the Bearer token; returning null means unauthenticated. */
@FunctionalInterface public interface IdentityResolver {
    Identity resolve(HttpServletRequest request,SignatureParameters parameters) throws Exception;
    static IdentityResolver fromPrincipal(KeyResolver keys){
        Objects.requireNonNull(keys);
        return (request,parameters)->{
            Principal principal=request.getUserPrincipal();if(principal==null) return null;
            // Keep repository lookup and returned identity bound to one subject.
            String subject;
            try{subject=principal.getName();}
            catch(Exception e){if(e instanceof InterruptedException)Thread.currentThread().interrupt();throw Canonical.fail("IDENTITY_UNAVAILABLE");}
            if(!Canonical.validIdentifier(subject)) throw Canonical.fail("IDENTITY_UNAVAILABLE");
            KeyRecord key;
            try{key=keys.resolve(subject,parameters.keyId());}
            catch(Exception e){if(e instanceof InterruptedException)Thread.currentThread().interrupt();throw Canonical.fail("KEY_RESOLVER_UNAVAILABLE");}
            if(key!=null && !key.validResolverContract()) throw Canonical.fail("KEY_RESOLVER_UNAVAILABLE");
            return new Identity(subject,key);
        };
    }
}
