package io.appguard;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.springframework.mock.web.MockHttpServletRequest;

final class SignedRequests {
    static final long NOW=1700000000;
    static final String ORIGIN="https://api.example.test";
    static final KeyPair KEYS;
    static {try {KeyPairGenerator g=KeyPairGenerator.getInstance("EC");g.initialize(new ECGenParameterSpec("secp256r1"));KEYS=g.generateKeyPair();}catch(Exception e){throw new ExceptionInInitializerError(e);}}
    static KeyRecord key(){return new KeyRecord("test-app","test-key","test-user",("-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(KEYS.getPublic().getEncoded())+"\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII),"ecdsa-p256-sha256",false);}
    static List<Header> signed(String method,String target,byte[] body,String contentType) throws Exception {
        String nonce=Base64.getUrlEncoder().withoutPadding().encodeToString(UUID.randomUUID().toString().substring(0,16).getBytes(StandardCharsets.US_ASCII));
        String digest="sha-256=:"+Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body))+":";
        String params="(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\");created="+NOW+";expires="+(NOW+120)+";nonce=\""+nonce+"\";keyid=\"test-key\";alg=\"ecdsa-p256-sha256\";tag=\"appguard-request-v0\"";
        String base="\"@method\": "+method+"\n\"@target-uri\": "+ORIGIN+target+"\n\"content-type\": "+contentType+"\n\"content-digest\": "+digest+"\n\"authorization\": Bearer TEST_ONLY_TOKEN\n\"appguard-app-id\": test-app\n\"@signature-params\": "+params;
        Signature signer=Signature.getInstance("SHA256withECDSAinP1363Format");signer.initSign(KEYS.getPrivate());signer.update(base.getBytes(StandardCharsets.US_ASCII));
        return new ArrayList<>(List.of(new Header("Content-Type",contentType),new Header("Content-Digest",digest),new Header("Authorization","Bearer TEST_ONLY_TOKEN"),new Header("AppGuard-App-Id","test-app"),new Header("Signature-Input","appguard="+params),new Header("Signature","appguard=:"+Base64.getEncoder().encodeToString(signer.sign())+":")));
    }
    static MockHttpServletRequest request(byte[] body,String target,String type) throws Exception {
        MockHttpServletRequest r=new MockHttpServletRequest("POST",target.split("\\?",2)[0]);
        if(target.contains("?"))r.setQueryString(target.substring(target.indexOf('?')+1));
        for(Header h:signed("POST",target,body,type))r.addHeader(h.name(),h.value());
        r.setContent(body);r.setSecure(true);r.setUserPrincipal(()->"test-user");return r;
    }
}
