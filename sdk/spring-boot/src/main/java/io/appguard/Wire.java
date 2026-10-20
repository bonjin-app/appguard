package io.appguard;
import java.util.*;
import java.util.regex.*;
/** Exact wire subset; never silently discard unsupported metadata. */
public final class Wire {
    private static final String INTEGER="(0|-?[1-9][0-9]{0,14})";
    private static final Pattern INPUT=Pattern.compile("appguard="+Pattern.quote(Canonical.COVERED)+";created="+INTEGER+";expires="+INTEGER+";nonce=\"([A-Za-z0-9_-]{22})\";keyid=\"([A-Za-z0-9._:-]{1,128})\";alg=\"([A-Za-z0-9._:-]{1,64})\";tag=\"([A-Za-z0-9._:-]{1,64})\"");
    private Wire(){}
    public static ParsedSignature parse(List<Header> headers){
        Map<String,String> h=Canonical.headers(headers,true);validateFraming(h);
        String input=h.get("signature-input"), signature=h.get("signature");
        Canonical.require(input!=null && signature!=null,"INVALID_REQUEST");
        Matcher m=INPUT.matcher(input);Canonical.require(m.matches(),"INVALID_REQUEST");
        SignatureParameters p=new SignatureParameters(Long.parseLong(m.group(1)),Long.parseLong(m.group(2)),m.group(3),m.group(4),m.group(5),m.group(6));
        Canonical.nonce(p.nonce());
        Canonical.require(signature.matches("appguard=:[A-Za-z0-9+/]{86}==:"),"INVALID_REQUEST");
        String encoded=signature.substring(10,signature.length()-1);byte[] raw;
        try{raw=Base64.getDecoder().decode(encoded);}catch(IllegalArgumentException e){throw Canonical.fail("INVALID_REQUEST");}
        Canonical.require(raw.length==64 && Base64.getEncoder().encodeToString(raw).equals(encoded),"INVALID_REQUEST");
        Canonical.require(Canonical.ALGORITHM.equals(p.algorithm()) && Canonical.TAG.equals(p.tag()),"UNSUPPORTED_PROFILE");
        return new ParsedSignature(p,raw);
    }
    private static void validateFraming(Map<String,String> h){
        String length=h.get("content-length"), transfer=h.get("transfer-encoding");
        Canonical.require(length==null || length.matches("0|[1-9][0-9]*"),"INVALID_REQUEST");
        Canonical.require(transfer==null || (length==null && transfer.equals("chunked")),"INVALID_REQUEST");
    }
    public static void validateCapturedLength(List<Header> headers,int length){
        Map<String,String> h=Canonical.headers(headers,true);validateFraming(h);String declared=h.get("content-length");
        Canonical.require(declared==null || declared.equals(Integer.toString(length)),"INVALID_REQUEST");
    }
}
