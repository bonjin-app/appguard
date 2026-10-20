package io.appguard;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.regex.*;

/** Canonicalization for the deliberately restricted request-v0 profile. */
public final class Canonical {
    public static final String ALGORITHM="ecdsa-p256-sha256", TAG="appguard-request-v0";
    public static final int MAX_BODY=1024*1024;
    public static final String COVERED="(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\")";
    private static final Pattern TOKEN=Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final Set<String> CORE_SINGLETONS=Set.of("content-type","content-digest","authorization","appguard-app-id","content-encoding");
    private static final Set<String> WIRE_SINGLETONS=Set.of("content-type","content-digest","authorization","appguard-app-id","content-encoding","signature-input","signature","content-length","transfer-encoding","host");
    private Canonical(){}
    static VerificationException fail(String code){return new VerificationException(code);}
    static void require(boolean condition,String code){if(!condition) throw fail(code);}
    public static boolean validIdentifier(String value){return value!=null && value.matches("[A-Za-z0-9._:-]{1,128}");}
    static void identifier(String value){require(validIdentifier(value),"INVALID_REQUEST");}
    static void nonce(String value){
        require(value!=null && value.matches("[A-Za-z0-9_-]{22}"),"INVALID_REQUEST");
        try{byte[] raw=Base64.getUrlDecoder().decode(value+"==");require(raw.length==16 && Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(value),"INVALID_REQUEST");}
        catch(IllegalArgumentException e){throw fail("INVALID_REQUEST");}
    }
    static Map<String,String> headers(List<Header> headers, boolean wire){
        require(headers!=null && headers.size()<=64,"INVALID_REQUEST");
        Map<String,String> result=new HashMap<>(); int size=0;
        for(Header h:headers){
            require(h!=null && h.name()!=null && h.value()!=null,"INVALID_REQUEST");
            size+=h.name().length()+h.value().length();
            require(size<=16384 && TOKEN.matcher(h.name()).matches(),"INVALID_REQUEST");
            String value=h.value();
            require(value.isEmpty() || (value.charAt(0)!=' ' && value.charAt(value.length()-1)!=' '),"INVALID_REQUEST");
            for(int i=0;i<value.length();i++) require(value.charAt(i)>=32 && value.charAt(i)<=126,"INVALID_REQUEST");
            String name=h.name().toLowerCase(Locale.ROOT);
            require(!(wire?WIRE_SINGLETONS:CORE_SINGLETONS).contains(name) || !result.containsKey(name),"INVALID_REQUEST");
            result.put(name,value);
        }
        for(String field:List.of("content-type","content-digest","authorization","appguard-app-id")) require(result.containsKey(field),"INVALID_REQUEST");
        require(!result.get("content-type").isEmpty() && result.getOrDefault("content-encoding","identity").equals("identity"),"INVALID_REQUEST");
        require(result.get("authorization").matches("(?i:Bearer) [A-Za-z0-9._~+/-]+=*"),"INVALID_REQUEST");
        identifier(result.get("appguard-app-id")); digestBytes(result.get("content-digest"));
        return result;
    }
    public static void validateOrigin(String origin){
        require(origin!=null && origin.length()<=512,"INVALID_REQUEST");
        Matcher m=Pattern.compile("https://([a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?").matcher(origin);
        require(m.matches(),"INVALID_REQUEST");String host=m.group(1), port=m.group(2);
        require(host.length()<=253,"INVALID_REQUEST");
        for(String label:host.split("\\.",-1)) require(label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"),"INVALID_REQUEST");
        require(port==null || (Integer.parseInt(port)<=65535 && !port.equals("443")),"INVALID_REQUEST");
    }
    public static void validateTarget(String target){
        require(target!=null && target.length()>=1 && target.length()<=8192 && !target.startsWith("//") && target.matches("/[A-Za-z0-9._~!$&'()*+,;=:@/?%\\-]*"),"INVALID_REQUEST");
        StringBuilder decoded=new StringBuilder();StringBuilder path=new StringBuilder(); boolean inPath=true;
        for(int i=0;i<target.length();i++){
            char c=target.charAt(i); if(c=='?') inPath=false;
            if(c=='%'){
                require(i+2<target.length(),"INVALID_REQUEST");int hi=Character.digit(target.charAt(i+1),16),lo=Character.digit(target.charAt(i+2),16);
                require(hi>=0 && lo>=0,"INVALID_REQUEST");c=(char)(hi*16+lo);i+=2;
            }
            require(c>=32 && c!=127 && c!='\\',"INVALID_REQUEST");decoded.append(c);if(inPath) path.append(c);
        }
        for(String segment:path.toString().split("/",-1)) require(!segment.equals(".") && !segment.equals(".."),"INVALID_REQUEST");
    }
    static void parameters(SignatureParameters p){
        require(p!=null,"INVALID_REQUEST");require(ALGORITHM.equals(p.algorithm()) && TAG.equals(p.tag()),"UNSUPPORTED_PROFILE");
        identifier(p.keyId());nonce(p.nonce());require(validTime(p.created()) && validTime(p.expires()),"INVALID_TIME");
    }
    static boolean validTime(long value){return value>=0 && value<=999999999999999L;}
    public static String signatureParameters(SignatureParameters p){
        return COVERED+";created="+p.created()+";expires="+p.expires()+";nonce=\""+p.nonce()+"\";keyid=\""+p.keyId()+"\";alg=\""+p.algorithm()+"\";tag=\""+p.tag()+"\"";
    }
    public static byte[] signatureBase(RequestInput request,SignatureParameters p,String origin){
        require(request!=null && request.body()!=null && request.body().length<=MAX_BODY,"INVALID_REQUEST");
        String method=request.method(); require(method!=null && method.length()<=32 && TOKEN.matcher(method).matches() && method.equals(method.toUpperCase(Locale.ROOT)),"INVALID_REQUEST");
        validateTarget(request.target());Map<String,String> h=headers(request.headers(),false);validateOrigin(origin);parameters(p);
        return ("\"@method\": "+method+"\n\"@target-uri\": "+origin+request.target()+"\n\"content-type\": "+h.get("content-type")+"\n\"content-digest\": "+h.get("content-digest")+"\n\"authorization\": "+h.get("authorization")+"\n\"appguard-app-id\": "+h.get("appguard-app-id")+"\n\"@signature-params\": "+signatureParameters(p)).getBytes(StandardCharsets.US_ASCII);
    }
    static byte[] digestBytes(String value){
        require(value!=null && value.matches("sha-256=:[A-Za-z0-9+/]{43}=:") ,"INVALID_REQUEST");
        String encoded=value.substring(9,value.length()-1);
        try{byte[] raw=Base64.getDecoder().decode(encoded);require(raw.length==32 && Base64.getEncoder().encodeToString(raw).equals(encoded),"INVALID_REQUEST");return raw;}
        catch(IllegalArgumentException e){throw fail("INVALID_REQUEST");}
    }
    static byte[] sha256(byte[] raw){try{return MessageDigest.getInstance("SHA-256").digest(raw);}catch(NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable");}}
    static void contentDigest(RequestInput r){require(MessageDigest.isEqual(digestBytes(headers(r.headers(),false).get("content-digest")),sha256(r.body())),"DIGEST_MISMATCH");}
}
