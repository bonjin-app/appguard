package io.appguard;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.*;

class SecurityBoundaryTest {
    static SignatureParameters p(long created,long expires){return new SignatureParameters(created,expires,"AAECAwQFBgcICQoLDA0ODw","test-key","ecdsa-p256-sha256","appguard-request-v0");}
    RequestInput request() throws Exception {var r=CorpusTest.vectors("requests").get(0).get("request");return new RequestInput(r.get("method").asText(),r.get("target").asText(),CorpusTest.headers(r.get("headers")),Base64.getDecoder().decode(r.get("body_b64").asText()));}
    byte[] signature()throws Exception{return Base64.getDecoder().decode(CorpusTest.vectors("requests").get(0).get("signature_b64").asText());}
    KeyRecord key()throws Exception{var k=CorpusTest.vectors("requests").get(0).get("key");return new KeyRecord("test-app","test-key","test-user",k.get("public_key_pem").asText().getBytes(StandardCharsets.US_ASCII),"ecdsa-p256-sha256",false);}
    String verify(SignatureParameters params,long now,KeyRecord key,ReplayStore store)throws Exception{try{return Verifier.verify(request(),params,signature(),SignedRequests.ORIGIN,"test-app","test-user",key,now,store).code();}catch(VerificationException e){return e.code();}}
    @Test void timeLimitsAreCheckedBeforeSignatureAndReplay() throws Exception {
        long now=SignedRequests.NOW;AtomicInteger claims=new AtomicInteger();ReplayStore store=(s,e,n)->{claims.incrementAndGet();return true;};
        assertThat(verify(p(now+31,now+120),now,key(),store)).isEqualTo("INVALID_TIME");
        assertThat(verify(p(now,now+121),now,key(),store)).isEqualTo("INVALID_TIME");
        assertThat(verify(p(now,now+120),now+120,key(),store)).isEqualTo("INVALID_TIME");
        assertThat(verify(p(-1,now+120),now,key(),store)).isEqualTo("INVALID_TIME");
        assertThat(verify(p(now,now+120),-1,key(),store)).isEqualTo("INVALID_TIME");
        assertThat(verify(p(now+30,now+120),now,key(),store)).isEqualTo("INVALID_SIGNATURE");
        assertThat(claims).hasValue(0);
        assertThat(verify(p(now,now+120),now+119,key(),store)).isEqualTo("VERIFIED");
    }
    @Test void otherCurvesRsaAndMalformedPemRejectBeforeBodyDigest()throws Exception {
        List<byte[]> bad=new ArrayList<>();
        KeyPairGenerator ec=KeyPairGenerator.getInstance("EC");ec.initialize(new ECGenParameterSpec("secp384r1"));bad.add(pem(ec.generateKeyPair().getPublic()));
        KeyPairGenerator rsa=KeyPairGenerator.getInstance("RSA");rsa.initialize(2048);bad.add(pem(rsa.generateKeyPair().getPublic()));bad.add(new byte[4097]);bad.add("garbage".getBytes());
        for(byte[] value:bad)assertThat(verify(p(SignedRequests.NOW,SignedRequests.NOW+120),SignedRequests.NOW,new KeyRecord("test-app","test-key","test-user",value,"ecdsa-p256-sha256",false),(s,e,n)->{throw new AssertionError("Must not claim");})).isEqualTo("KEY_REJECTED");
    }
    static byte[] pem(PublicKey key){return ("-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder().encodeToString(key.getEncoded())+"\n-----END PUBLIC KEY-----\n").getBytes(StandardCharsets.US_ASCII);}
    @Test void nullStoreContractAndRawSignatureEncodingFailClosed() throws Exception {
        assertThat(verify(p(SignedRequests.NOW,SignedRequests.NOW+120),SignedRequests.NOW,key(),(s,e,n)->null)).isEqualTo("REPLAY_STORE_UNAVAILABLE");
        assertThatThrownBy(()->Verifier.verify(request(),p(SignedRequests.NOW,SignedRequests.NOW+120),new byte[64],SignedRequests.ORIGIN,"test-app","test-user",key(),SignedRequests.NOW,(s,e,n)->{throw new AssertionError("Must not claim");})).isInstanceOf(VerificationException.class).extracting(e->((VerificationException)e).code()).isEqualTo("INVALID_SIGNATURE");
    }
    @Test void targetAndOriginValidationRejectsAmbiguityWhilePreservingValidEncoding(){
        for(String target:List.of("//host/path","/a/%2e%2E/b","/a/../b","/a%00","/a%5c","/a%7f","/a%2","/a#frag","/a b","/a\\b","/a?x=%0A"))assertThatThrownBy(()->Canonical.validateTarget(target)).isInstanceOf(VerificationException.class);
        for(String target:List.of("/","/a?","/a%2Fb?x=2&x=1","/a%2fb","/a?x=%2e%2e","/a%3Fb"))assertThatCode(()->Canonical.validateTarget(target)).doesNotThrowAnyException();
        for(String origin:List.of("http://api.test","https://API.test","https://api.test:443","https://api.test:65536","https://api.test/","https://user@api.test","https://api..test","https://api.test:0443","https://api.test."))assertThatThrownBy(()->Canonical.validateOrigin(origin)).isInstanceOf(VerificationException.class);
    }
}
