package io.appguard.android;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class EnrollmentProofTest {
    private static final String ORIGIN="https://api.example.test",NONCE="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    private static final String FP="3b99f4d208b94c14486b08d21ba830cd2af8e683882e282498372af1cae965c3";
    private static final String MESSAGE="appguard-enrollment-v0\napp-id: test-app\norigin: https://api.example.test\nsubject: test-user\nkey-id: test-key\npublic-key-sha256: "+FP+"\nchallenge: "+NONCE+"\nexpires: 1700000120";
    private static class CapturingKey implements RequestSigner.PublicSigningKey {
        final byte[] publicKey;int calls;byte[] message;
        CapturingKey(byte[] publicKey) {this.publicKey=publicKey;}
        public byte[] publicKeySpki() {return publicKey.clone();}
        public byte[] signDer(byte[] base) {calls++;message=base.clone();return RequestSignerTest.oneDer();}
    }
    private static byte[] corpusSpki() throws Exception {
        String pem=new String(Files.readAllBytes(Path.of(System.getProperty("appguard.corpus"),"test-public-key.pem")),StandardCharsets.US_ASCII);
        return Base64.getMimeDecoder().decode(pem.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----",""));
    }
    private static EnrollmentProof.Challenge challenge(String app,String origin,String subject,String key,String fp,String nonce,long expires) {
        return new EnrollmentProof.Challenge(app,origin,subject,key,fp,nonce,expires);
    }
    private static EnrollmentProof.Challenge good() {return challenge("test-app",ORIGIN,"test-user","test-key",FP,NONCE,1700000120);}
    private static EnrollmentProof.Result create(EnrollmentProof.Challenge c,RequestSigner.PublicSigningKey k) throws Exception {
        return EnrollmentProof.create(c,"test-app",ORIGIN,"test-user","test-key",1700000000,k);
    }
    @Test public void exactDomainSeparatedLiteralAndIndependentHashes() throws Exception {
        CapturingKey key=new CapturingKey(corpusSpki());EnrollmentProof.Result result=create(good(),key);
        assertEquals(MESSAGE,new String(key.message,StandardCharsets.US_ASCII));assertEquals(1,key.calls);
        assertEquals(64,result.proof().length);assertEquals(1,result.proof()[31]);assertEquals(1,result.proof()[63]);
        byte[] expected=MessageDigest.getInstance("SHA-256").digest(MESSAGE.getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals(expected,result.clientDataHash());assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(expected),result.googleRequestHash());
        byte[] hash=result.clientDataHash();Arrays.fill(hash,(byte)0);assertArrayEquals(expected,result.clientDataHash());
        byte[] proof=result.proof();proof[31]=0;assertEquals(1,result.proof()[31]);
    }
    @Test public void rejectsChallengeBindingsSyntaxTimeAndNoncanonicalNonceBeforeSigning() throws Exception {
        CapturingKey key=new CapturingKey(corpusSpki());List<EnrollmentProof.Challenge> bad=new ArrayList<>();
        bad.add(null);bad.add(challenge("other",ORIGIN,"test-user","test-key",FP,NONCE,1700000120));
        bad.add(challenge("test-app","https://other.test","test-user","test-key",FP,NONCE,1700000120));
        bad.add(challenge("test-app",ORIGIN,"other-user","test-key",FP,NONCE,1700000120));
        bad.add(challenge("test-app",ORIGIN,"test-user","other-key",FP,NONCE,1700000120));
        for(String value:new String[]{null,"","bad\nid","x".repeat(129)})bad.add(challenge("test-app",ORIGIN,value,"test-key",FP,NONCE,1700000120));
        for(String value:new String[]{null,"","0".repeat(64),FP.toUpperCase(Locale.ROOT),FP+"0"})bad.add(challenge("test-app",ORIGIN,"test-user","test-key",value,NONCE,1700000120));
        for(String value:new String[]{null,"",NONCE+"=",NONCE.substring(0,42)+"9","x".repeat(42)})bad.add(challenge("test-app",ORIGIN,"test-user","test-key",FP,value,1700000120));
        for(long value:new long[]{-1,1700000000,1700000301,1000000000000000L,Long.MAX_VALUE})bad.add(challenge("test-app",ORIGIN,"test-user","test-key",FP,NONCE,value));
        for(EnrollmentProof.Challenge c:bad)assertThrows(IllegalArgumentException.class,()->create(c,key));
        assertThrows(IllegalArgumentException.class,()->EnrollmentProof.create(good(),"test-app",ORIGIN,"test-user","test-key",-1,key));
        assertThrows(IllegalArgumentException.class,()->EnrollmentProof.create(good(),"test-app","http://api.example.test","test-user","test-key",1700000000,key));
        assertEquals(0,key.calls);
    }
    @Test public void validatesCanonicalSpkiAndWrongCurveBeforeSigning() throws Exception {
        CapturingKey bad=new CapturingKey(new byte[]{1,2,3});assertThrows(GeneralSecurityException.class,()->create(good(),bad));assertEquals(0,bad.calls);
        KeyPairGenerator g=KeyPairGenerator.getInstance("EC");g.initialize(new ECGenParameterSpec("secp384r1"));
        CapturingKey other=new CapturingKey(g.generateKeyPair().getPublic().getEncoded());assertThrows(GeneralSecurityException.class,()->create(good(),other));assertEquals(0,other.calls);
    }
    @Test public void realJcaProofVerifiesAndPublicExportsAreCopies() throws Exception {
        KeyPairGenerator g=KeyPairGenerator.getInstance("EC");g.initialize(new ECGenParameterSpec("secp256r1"));KeyPair pair=g.generateKeyPair();JcaSigningKey key=new JcaSigningKey(pair);
        byte[] spki=key.publicKeySpki();assertArrayEquals(pair.getPublic().getEncoded(),spki);Arrays.fill(spki,(byte)0);assertArrayEquals(pair.getPublic().getEncoded(),key.publicKeySpki());
        StringBuilder fp=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(pair.getPublic().getEncoded()))fp.append(String.format(Locale.ROOT,"%02x",b&255));
        EnrollmentProof.Challenge c=challenge("test-app",ORIGIN,"test-user","test-key",fp.toString(),NONCE,1700000300);
        EnrollmentProof.Result proof=create(c,key);String message=MESSAGE.replace(FP,fp).replace("1700000120","1700000300");
        Signature verify=Signature.getInstance("SHA256withECDSA");verify.initVerify(pair.getPublic());verify.update(message.getBytes(StandardCharsets.US_ASCII));assertTrue(verify.verify(RequestSignerTest.rawToDer(proof.proof())));
        verify.initVerify(pair.getPublic());verify.update((message+"\n").getBytes(StandardCharsets.US_ASCII));assertFalse(verify.verify(RequestSignerTest.rawToDer(proof.proof())));
    }
}
