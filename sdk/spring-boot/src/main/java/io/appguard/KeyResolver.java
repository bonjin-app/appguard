package io.appguard;
/** Look up a trusted pre-enrolled key. Unknown key may return null and will reject. */
@FunctionalInterface public interface KeyResolver {KeyRecord resolve(String authenticatedSubject,String keyId) throws Exception;}
