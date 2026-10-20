package io.appguard;
/** Must atomically claim once through expiry. Exceptions/null fail closed. */
@FunctionalInterface public interface ReplayStore {Boolean claim(ReplayScope scope,long expires,long now) throws Exception;}
