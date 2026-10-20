package io.appguard;
/** An original header field value. Repeated names must remain separate pairs. */
public record Header(String name, String value) { @Override public String toString() {return "Header[redacted]";} }
