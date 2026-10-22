package io.appguard.example;

import io.appguard.Canonical;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;

/** Explicit single-application example configuration; no token/key discovery or fallback. */
final class BackendSettings {
    final int port, redisPort, redisDatabase;
    final String appId, origin, subject, keyId, keyStore, keyStorePassword, trustStore, trustStorePassword;
    final byte[] publicKey, bearerHash;
    final Path counterFile;

    BackendSettings(Map<String,String> env) throws IOException, GeneralSecurityException {
        port=integer(required(env,"APPGUARD_BACKEND_PORT"),1,65535);
        appId=identifier(required(env,"APPGUARD_APP_ID"));
        origin=required(env,"APPGUARD_ORIGIN");Canonical.validateOrigin(origin);
        subject=identifier(required(env,"APPGUARD_SUBJECT"));keyId=identifier(required(env,"APPGUARD_KEY_ID"));
        keyStore=file(required(env,"APPGUARD_BACKEND_KEYSTORE")).toString();
        trustStore=file(required(env,"APPGUARD_BACKEND_TRUSTSTORE")).toString();
        keyStorePassword=required(env,"APPGUARD_BACKEND_KEYSTORE_PASSWORD");
        trustStorePassword=required(env,"APPGUARD_BACKEND_TRUSTSTORE_PASSWORD");
        String hash=required(env,"APPGUARD_BEARER_SHA256");
        if(!hash.matches("[0-9a-f]{64}"))throw new IllegalArgumentException("Invalid bearer hash");
        bearerHash=HexFormat.of().parseHex(hash);
        Path pem=file(required(env,"APPGUARD_PUBLIC_KEY_FILE"));
        if(Files.size(pem)>4096)throw new IllegalArgumentException("Invalid public key");
        publicKey=Files.readAllBytes(pem);validateKey(publicKey);
        URI redis=URI.create(required(env,"APPGUARD_REDIS_URL"));
        if(!"redis".equals(redis.getScheme()) || !"127.0.0.1".equals(redis.getHost()) || redis.getPort()<1 || redis.getPort()>65535 || redis.getRawUserInfo()!=null || redis.getRawQuery()!=null || redis.getRawFragment()!=null || !redis.getRawPath().matches("/(0|[1-9][0-9]?)"))throw new IllegalArgumentException("Explicit loopback Redis URL required");
        redisPort=redis.getPort();redisDatabase=integer(redis.getPath().substring(1),0,15);
        String counters=env.get("APPGUARD_BACKEND_COUNTER_FILE");counterFile=counters==null?null:file(counters);
    }
    static String required(Map<String,String> env,String key){String value=env.get(key);if(value==null || value.isEmpty() || value.length()>8192)throw new IllegalArgumentException("Missing or invalid backend configuration");return value;}
    static String identifier(String value){if(!Canonical.validIdentifier(value))throw new IllegalArgumentException("Invalid identifier");return value;}
    static int integer(String text,int min,int max){if(!text.matches("[0-9]{1,5}"))throw new IllegalArgumentException("Invalid integer");int value=Integer.parseInt(text);if(value<min||value>max)throw new IllegalArgumentException("Out of range");return value;}
    static Path file(String value)throws IOException {Path path=Path.of(value);if(!path.isAbsolute() || !Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(path))throw new IllegalArgumentException("Readable absolute regular file required");return path;}
    static void validateKey(byte[] pem)throws GeneralSecurityException {
        String text=new String(pem,StandardCharsets.US_ASCII);
        if(!text.matches("-----BEGIN PUBLIC KEY-----[\\r\\n]+[A-Za-z0-9+/=\\r\\n]+-----END PUBLIC KEY-----[\\r\\n]*"))throw new InvalidKeyException();
        byte[] der=Base64.getMimeDecoder().decode(text.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----",""));
        PublicKey key=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        AlgorithmParameters expected=AlgorithmParameters.getInstance("EC");expected.init(new ECGenParameterSpec("secp256r1"));
        if(!(key instanceof ECPublicKey ec) || !Arrays.equals(der,key.getEncoded()))throw new InvalidKeyException();
        ECParameterSpec p=ec.getParams(),q=expected.getParameterSpec(ECParameterSpec.class);
        if(!p.getCurve().equals(q.getCurve()) || !p.getGenerator().equals(q.getGenerator()) || !p.getOrder().equals(q.getOrder()) || p.getCofactor()!=q.getCofactor())throw new InvalidKeyException();
    }
    Map<String,Object> properties(){
        Map<String,Object> p=new HashMap<>();
        p.put("server.address","127.0.0.1");p.put("server.port",port);p.put("server.ssl.enabled",true);
        p.put("server.ssl.key-store",Path.of(keyStore).toUri().toString());p.put("server.ssl.key-store-type","PKCS12");p.put("server.ssl.key-store-password",keyStorePassword);
        p.put("server.ssl.trust-store",Path.of(trustStore).toUri().toString());p.put("server.ssl.trust-store-type","PKCS12");p.put("server.ssl.trust-store-password",trustStorePassword);
        p.put("server.ssl.client-auth","need");p.put("server.ssl.enabled-protocols","TLSv1.2,TLSv1.3");
        p.put("server.http2.enabled",false);p.put("server.forward-headers-strategy","none");
        p.put("server.tomcat.connection-timeout","2s");p.put("server.tomcat.keep-alive-timeout","1s");p.put("server.tomcat.max-connections",64);p.put("server.tomcat.accept-count",32);p.put("server.tomcat.threads.max",16);p.put("server.tomcat.threads.min-spare",2);
        p.put("server.max-http-request-header-size","16KB");p.put("server.tomcat.max-http-response-header-size","16KB");
        p.put("server.error.include-message","never");p.put("server.error.include-stacktrace","never");
        p.put("appguard.enabled",true);p.put("appguard.app-id",appId);p.put("appguard.origin",origin);p.put("appguard.allow-insecure-transport",false);
        p.put("spring.main.banner-mode","off");p.put("logging.level.root","ERROR");p.put("spring.main.log-startup-info",false);
        return Map.copyOf(p);
    }
}
