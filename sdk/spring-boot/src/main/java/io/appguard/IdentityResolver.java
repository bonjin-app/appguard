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
            KeyRecord key;
            try{key=keys.resolve(principal.getName(),parameters.keyId());}
            catch(Exception e){throw Canonical.fail("KEY_RESOLVER_UNAVAILABLE");}
            if(key!=null && !key.validResolverContract()) throw Canonical.fail("KEY_RESOLVER_UNAVAILABLE");
            return new Identity(principal.getName(),key);
        };
    }
}
