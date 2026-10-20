package io.appguard.android;

import com.google.gson.*;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class RequestSignerTest {
    static final long NOW=1700000000L;
    static final String NONCE="AAECAwQFBgcICQoLDA0ODw";
    static final String ORIGIN="https://api.example.test";
    static final byte[] BODY="{}".getBytes(StandardCharsets.US_ASCII);
    static RequestSigner.Input input(String method,String target,byte[] body,String ct,String auth,
                                     String app,String key,String origin,long created,long expires,String nonce) {
        return new RequestSigner.Input(method,target,body,ct,auth,app,key,origin,created,expires,nonce);
    }
    static RequestSigner.Input good() { return input("POST","/v1/items?b=2&a=1",BODY,"application/json",
        "Bearer TEST_ONLY_TOKEN","test-app","test-key",ORIGIN,NOW,NOW+120,NONCE); }
    static byte[] oneDer() { return new byte[]{0x30,6,2,1,1,2,1,1}; }
    static String header(RequestSigner.Prepared p,String name) {
        for(RequestSigner.Header h:p.headers()) if(h.name.equalsIgnoreCase(name))return h.value;
        throw new AssertionError("missing header "+name);
    }
    static JsonArray corpus(String name) throws Exception {
        return JsonParser.parseString(new String(Files.readAllBytes(Path.of(System.getProperty("appguard.corpus"),name)),StandardCharsets.UTF_8)).getAsJsonArray();
    }
    static byte[] rawToDer(byte[] raw) {
        byte[] r=new java.math.BigInteger(1,Arrays.copyOfRange(raw,0,32)).toByteArray();
        byte[] s=new java.math.BigInteger(1,Arrays.copyOfRange(raw,32,64)).toByteArray();
        byte[] out=new byte[r.length+s.length+6];out[0]=0x30;out[1]=(byte)(out.length-2);out[2]=2;out[3]=(byte)r.length;
        System.arraycopy(r,0,out,4,r.length);out[4+r.length]=2;out[5+r.length]=(byte)s.length;
        System.arraycopy(s,0,out,6+r.length,s.length);return out;
    }
    @Test public void preservesFiveValidCorpusSignatureBases() throws Exception {
        int count=0;
        for(JsonElement e:corpus("requests.json")) {
            JsonObject v=e.getAsJsonObject();
            if(!Set.of("valid-json","valid-empty-body","valid-encoded-slash","valid-lowercase-escape","forwarded-origin-ignored").contains(v.get("id").getAsString())) continue;
            JsonObject r=v.getAsJsonObject("request");String[] base={null};
            RequestSigner.Prepared p=new RequestSigner().prepare(input(r.get("method").getAsString(),r.get("target").getAsString(),
                Base64.getDecoder().decode(r.get("body_b64").getAsString()),"application/json","Bearer TEST_ONLY_TOKEN","test-app","test-key",ORIGIN,NOW,NOW+120,NONCE),
                bytes->{base[0]=new String(bytes,StandardCharsets.US_ASCII);return oneDer();});
            assertEquals(v.get("expected_signature_base").getAsString(),base[0]);
            assertEquals(r.get("target").getAsString(),p.target());count++;
        }
        assertEquals(5,count);
    }
    @Test public void producesExactSixWireHeadersFromCorpus() throws Exception {
        JsonObject v=corpus("http.json").get(0).getAsJsonObject();
        byte[] raw=Base64.getDecoder().decode(v.getAsJsonObject("expected").get("signature_b64").getAsString());
        RequestSigner.Prepared p=new RequestSigner().prepare(good(),b->rawToDer(raw));
        JsonArray expected=v.getAsJsonArray("headers");assertEquals(6,p.headers().size());
        for(int i=0;i<6;i++) {assertEquals(expected.get(i).getAsJsonArray().get(0).getAsString(),p.headers().get(i).name);
            assertEquals(expected.get(i).getAsJsonArray().get(1).getAsString(),p.headers().get(i).value);}
        assertEquals("test-key",p.keyId());assertEquals("POST",p.method());
    }
    @Test public void copiesInputOutputAndSigningBuffers() throws Exception {
        byte[] body=BODY.clone();RequestSigner.Input in=input("POST","/x?",body,"application/json","bEaReR token","app","key",ORIGIN,NOW,NOW+1,NONCE);
        body[0]=0;RequestSigner.Prepared p=new RequestSigner().prepare(in,base->{Arrays.fill(base,(byte)0);return oneDer();});
        assertArrayEquals(BODY,p.body());byte[] out=p.body();out[0]=0;assertArrayEquals(BODY,p.body());assertEquals("/x?",p.target());
        assertEquals("bEaReR token",header(p,"Authorization"));
        assertThrows(UnsupportedOperationException.class,()->p.headers().clear());
    }
    @Test public void rejectsOversizedBodyBeforeAllocatingADefensiveCopy() {
        assertThrows(IllegalArgumentException.class,()->input("POST","/",new byte[1048577],"text/plain","Bearer token","app","key",ORIGIN,NOW,NOW+1,NONCE));
    }
    @Test public void rejectsInvalidInputsBeforeSigning() throws Exception {
        List<RequestSigner.Input> bad=new ArrayList<>();
        for(String t:new String[]{"","//host/x","/bad%","/bad%GG","/a/../b","/a/%2e/b","/%2E%2E/b","/a%2f..%2fb","/x%00","/x%0a","/x%7f","/x%5c","/a\\b","/x#f","/x y","/é","/"+"x".repeat(8192)})
            bad.add(input("POST",t,BODY,"text/plain","Bearer token","app","key",ORIGIN,NOW,NOW+1,NONCE));
        for(String m:new String[]{"","post","PoST","GET\n","A".repeat(33),"GET /"})
            bad.add(input(m,"/",BODY,"text/plain","Bearer token","app","key",ORIGIN,NOW,NOW+1,NONCE));
        for(String origin:new String[]{"http://a.test","https://A.test","https://a.test/","https://a.test:443","https://a.test:0","https://a.test:65536","https://user@a.test","https://a..test","https://-a.test","https://a.test?x","https://a.test#x","https://"+"a".repeat(64)+".test"})
            bad.add(input("POST","/",BODY,"text/plain","Bearer token","app","key",origin,NOW,NOW+1,NONCE));
        for(String ct:new String[]{""," text/plain","text/plain ","text/plain\r\nX: yes","é"})
            bad.add(input("POST","/",BODY,ct,"Bearer token","app","key",ORIGIN,NOW,NOW+1,NONCE));
        for(String auth:new String[]{"Bearer ","Bearer a b","Bearer a\n","Basic abc"," Bearer a","Bearer a=more"})
            bad.add(input("POST","/",BODY,"text/plain",auth,"app","key",ORIGIN,NOW,NOW+1,NONCE));
        for(String id:new String[]{"","bad id","bad\"id","é","a".repeat(129)}) {
            bad.add(input("POST","/",BODY,"text/plain","Bearer token",id,"key",ORIGIN,NOW,NOW+1,NONCE));
            bad.add(input("POST","/",BODY,"text/plain","Bearer token","app",id,ORIGIN,NOW,NOW+1,NONCE));
        }
        for(String n:new String[]{"",NONCE+"=","AAECAwQFBgcICQoLDA0ODx","a".repeat(21),"!".repeat(22)})
            bad.add(input("POST","/",BODY,"text/plain","Bearer token","app","key",ORIGIN,NOW,NOW+1,n));
        bad.add(input("POST","/",BODY,"x".repeat(16000),"Bearer "+"a".repeat(400),"app","key",ORIGIN,NOW,NOW+1,NONCE));
        AtomicInteger calls=new AtomicInteger();RequestSigner.SigningKey key=b->{calls.incrementAndGet();return oneDer();};
        for(RequestSigner.Input in:bad) assertThrows(IllegalArgumentException.class,()->new RequestSigner().prepare(in,key));
        assertEquals(0,calls.get());
    }
    @Test public void rejectsNullInputsBeforeSigning() throws Exception {
        AtomicInteger calls=new AtomicInteger();RequestSigner.SigningKey key=b->{calls.incrementAndGet();return oneDer();};
        assertThrows(IllegalArgumentException.class,()->new RequestSigner().prepare(null,key));
        assertThrows(IllegalArgumentException.class,()->new RequestSigner().prepare(input(null,"/",BODY,"text/plain","Bearer token","app","key",ORIGIN,NOW,NOW+1,NONCE),key));
        assertThrows(IllegalArgumentException.class,()->new RequestSigner().prepare(input("POST","/",null,"text/plain","Bearer token","app","key",ORIGIN,NOW,NOW+1,NONCE),key));
        assertEquals(0,calls.get());
    }
    @Test public void rejectsTimeRangeAndLongLifetimeBeforeSigning() throws Exception {
        AtomicInteger calls=new AtomicInteger();RequestSigner.SigningKey key=b->{calls.incrementAndGet();return oneDer();};
        for(long[] time:new long[][]{{-1,1},{0,0},{2,1},{NOW,NOW+121},{0,1000000000000000L},{Long.MIN_VALUE,Long.MAX_VALUE}})
            assertThrows(IllegalArgumentException.class,()->new RequestSigner().prepare(input("POST","/",BODY,"text/plain","Bearer token","app","key",ORIGIN,time[0],time[1],NONCE),key));
        assertEquals(0,calls.get());
    }
    @Test public void acceptsExactResourceBoundariesAndEmptyQuery() throws Exception {
        byte[] large=new byte[1048576];
        RequestSigner.Prepared p=new RequestSigner().prepare(input("A".repeat(32),"/"+"x".repeat(8190)+"?",large,"text/plain","Bearer x","a".repeat(128),"k".repeat(128),"https://a.test:65535",0,120,NONCE),b->oneDer());
        assertEquals(8192,p.target().length());assertArrayEquals(large,p.body());
    }
    @Test public void defaultInputUsesFreshSixteenByteNoncesAndShortCurrentLifetime() throws Exception {
        Set<String> nonces=new HashSet<>();long before=System.currentTimeMillis()/1000;
        for(int i=0;i<24;i++) {
            RequestSigner.Prepared p=new RequestSigner().prepare(RequestSigner.Input.fresh("GET","/",new byte[0],"application/octet-stream","Bearer x","app","key",ORIGIN),b->oneDer());
            String params=header(p,"Signature-Input");java.util.regex.Matcher m=java.util.regex.Pattern.compile(";created=(\\d+);expires=(\\d+);nonce=\"([^\"]+)\"").matcher(params);assertTrue(m.find());
            long created=Long.parseLong(m.group(1)),expires=Long.parseLong(m.group(2));
            assertTrue(created>=before && created<=System.currentTimeMillis()/1000);assertTrue(expires>created && expires-created<=120);
            assertEquals(16,Base64.getUrlDecoder().decode(m.group(3)).length);assertTrue(nonces.add(m.group(3)));
        }
    }
    @Test public void rejectsMalformedDerAndOutOfRangeScalars() throws Exception {
        byte[][] invalid={{},{0x30,6,2,1,1,2,1,1,0},{0x30,6,2,1,0,2,1,1},{0x30,6,2,1,(byte)0xff,2,1,1},
            {0x30,7,2,2,0,1,2,1,1},{0x30,(byte)0x81,6,2,1,1,2,1,1},{0x30,5,2,0,2,1,1}};
        for(byte[] der:invalid)assertThrows(GeneralSecurityException.class,()->EcdsaP256.derToRaw(der));
        byte[] order=new java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16).toByteArray();
        byte[] raw=new byte[64];System.arraycopy(order,order.length-32,raw,0,32);raw[63]=1;
        assertThrows(GeneralSecurityException.class,()->EcdsaP256.derToRaw(rawToDer(raw)));
    }
    @Test public void derHandlesLeadingZeroAndUnsignedHighBit() throws Exception {
        byte[] raw=new byte[64];raw[31]=1;raw[32]=(byte)0x80;raw[63]=2;
        assertArrayEquals(raw,EcdsaP256.derToRaw(rawToDer(raw)));
    }
    @Test public void jcaGeneratedSignaturesVerifyAndMutationFails() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair=generator.generateKeyPair();JcaSigningKey key=new JcaSigningKey(pair);
        String[] base={null};RequestSigner.Prepared p=new RequestSigner().prepare(good(),b->{base[0]=new String(b,StandardCharsets.US_ASCII);return key.signDer(b);});
        String encoded=header(p,"Signature");byte[] raw=Base64.getDecoder().decode(encoded.substring(10,encoded.length()-1));assertEquals(64,raw.length);
        Signature verify=Signature.getInstance("SHA256withECDSA");verify.initVerify(pair.getPublic());verify.update(base[0].getBytes(StandardCharsets.US_ASCII));assertTrue(verify.verify(rawToDer(raw)));
        verify.initVerify(pair.getPublic());verify.update((base[0]+"x").getBytes(StandardCharsets.US_ASCII));assertFalse(verify.verify(rawToDer(raw)));
        byte[] spki=Base64.getMimeDecoder().decode(key.publicKeyPem().replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----",""));
        assertArrayEquals(pair.getPublic().getEncoded(),spki);
    }
    @Test public void rejectsWrongCurveAndMismatchedKeyPair() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec("secp384r1"));
        assertThrows(GeneralSecurityException.class,()->new JcaSigningKey(generator.generateKeyPair()));
        generator.initialize(new ECGenParameterSpec("secp256r1"));KeyPair one=generator.generateKeyPair(),two=generator.generateKeyPair();
        assertThrows(GeneralSecurityException.class,()->new JcaSigningKey(new KeyPair(one.getPublic(),two.getPrivate())));
    }
    @Test public void signFailureDoesNotReturnPreparedRequest() throws Exception {
        assertThrows(GeneralSecurityException.class,()->new RequestSigner().prepare(good(),b->{throw new GeneralSecurityException("unavailable");}));
        assertThrows(GeneralSecurityException.class,()->new RequestSigner().prepare(good(),b->new byte[64]));
    }
}
