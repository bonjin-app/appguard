package io.appguard;
/** Trusted authentication result and pre-enrolled key, never client-supplied subject metadata. */
public record Identity(String subject,KeyRecord key){@Override public String toString(){return "Identity[redacted]";}}
