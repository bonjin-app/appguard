package io.appguard.example;

import io.appguard.VerificationResult;
import jakarta.servlet.http.HttpServlet;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.*;
import static org.assertj.core.api.Assertions.*;

class BackendTest {
    @TempDir Path temp;
    static final String TOKEN="qualification-only-32-bytes-token-123456789";
    Map<String,String> environment()throws Exception {
        Map<String,String> env=new HashMap<>();
        env.put("APPGUARD_BACKEND_PORT","9443");env.put("APPGUARD_APP_ID","qualification-app");env.put("APPGUARD_ORIGIN","https://api.example.test");env.put("APPGUARD_SUBJECT","user-1");env.put("APPGUARD_KEY_ID","key-1");
        env.put("APPGUARD_BACKEND_KEYSTORE",Files.write(temp.resolve("server.p12"),new byte[]{1}).toString());env.put("APPGUARD_BACKEND_TRUSTSTORE",Files.write(temp.resolve("clients.p12"),new byte[]{1}).toString());
        env.put("APPGUARD_BACKEND_KEYSTORE_PASSWORD","qualification-password");env.put("APPGUARD_BACKEND_TRUSTSTORE_PASSWORD","qualification-password");
        env.put("APPGUARD_BEARER_SHA256",HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(TOKEN.getBytes(StandardCharsets.US_ASCII))));
        env.put("APPGUARD_REDIS_URL","redis://127.0.0.1:6379/0");env.put("APPGUARD_PUBLIC_KEY_FILE",writeKey("secp256r1").toString());return env;
    }
    Path writeKey(String curve)throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");generator.initialize(new ECGenParameterSpec(curve));
        String pem="-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(generator.generateKeyPair().getPublic().getEncoded())+"\n-----END PUBLIC KEY-----\n";
        return Files.writeString(temp.resolve(curve+".pem"),pem);
    }
    @Test void everyRequiredConfigurationMustBeExplicit()throws Exception {
        Map<String,String> env=environment();
        for(String key:env.keySet()){Map<String,String> missing=new HashMap<>(env);missing.remove(key);assertThatThrownBy(()->new BackendSettings(missing)).as(key).isInstanceOf(IllegalArgumentException.class);}
    }
    @Test void invariantsCannotBeDisabledByUnrelatedEnvironmentSettings()throws Exception {
        Map<String,String> env=environment();env.put("SERVER_SSL_CLIENT_AUTH","none");env.put("SERVER_ADDRESS","0.0.0.0");env.put("APPGUARD_ALLOW_INSECURE_TRANSPORT","true");
        Map<String,Object> properties=new BackendSettings(env).properties();
        assertThat(properties).containsEntry("server.address","127.0.0.1").containsEntry("server.ssl.client-auth","need").containsEntry("server.ssl.enabled",true).containsEntry("server.forward-headers-strategy","none").containsEntry("server.http2.enabled",false).containsEntry("appguard.allow-insecure-transport",false);
        assertThatThrownBy(()->properties.put("server.ssl.client-auth","none")).isInstanceOf(UnsupportedOperationException.class);
    }
    @Test void redisMustBeExplicitBoundedLoopbackWithoutCredentialsOrUrlOptions()throws Exception {
        Map<String,String> env=environment();
        for(String url:List.of("redis://localhost:6379/0","redis://127.0.0.1/0","redis://127.0.0.1:6379/16","redis://user:secret@127.0.0.1:6379/0","redis://127.0.0.1:6379/0?x=1","rediss://127.0.0.1:6379/0","redis://127.0.0.1:6379/%30")){
            env.put("APPGUARD_REDIS_URL",url);assertThatThrownBy(()->new BackendSettings(env)).as(url).isInstanceOf(IllegalArgumentException.class);
        }
    }
    @Test void invalidKeysHashesPortsAndOriginsFailBeforeStartup()throws Exception {
        Map<String,String> env=environment();env.put("APPGUARD_PUBLIC_KEY_FILE",writeKey("secp384r1").toString());assertThatThrownBy(()->new BackendSettings(env)).isInstanceOf(InvalidKeyException.class);
        Map<String,String> badHash=environment();badHash.put("APPGUARD_BEARER_SHA256","f".repeat(63));assertThatThrownBy(()->new BackendSettings(badHash)).isInstanceOf(IllegalArgumentException.class);
        for(String port:List.of("0","65536","-1","1.0"," 123")){Map<String,String> bad=environment();bad.put("APPGUARD_BACKEND_PORT",port);assertThatThrownBy(()->new BackendSettings(bad)).isInstanceOf(IllegalArgumentException.class);}
        Map<String,String> bad=environment();bad.put("APPGUARD_ORIGIN","http://api.example.test");assertThatThrownBy(()->new BackendSettings(bad)).isInstanceOf(RuntimeException.class);
    }
    @Test void bearerValidationHashesOnlyTheTokenAndNeverAcceptsMalformedOrShortTokens()throws Exception {
        BackendSettings settings=new BackendSettings(environment());
        assertThat(BackendMain.validBearer("Bearer "+TOKEN,settings.bearerHash)).isTrue();assertThat(BackendMain.validBearer("bearer "+TOKEN,settings.bearerHash)).isTrue();
        for(String token:List.of("Bearer wrong","Bearer "+TOKEN+"x","Bearer "+TOKEN+" "," Bearer "+TOKEN,"Basic "+TOKEN,"Bearer "+"a".repeat(8192),"Bearer x\r\nX: y"))assertThat(BackendMain.validBearer(token,settings.bearerHash)).isFalse();
        assertThat(BackendMain.validBearer(null,settings.bearerHash)).isFalse();
    }
    @Test void countersOnlyWriteFixedIntegersToNewOwnerOnlyRegularFile()throws Exception {
        Path path=Files.createFile(temp.resolve("counters.json"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        BackendCounters counters=new BackendCounters(path);counters.increment("dispatch");counters.increment("auth");
        assertThat(Files.readString(path)).isEqualTo("{\"dispatch\":1,\"auth\":1,\"key\":0,\"replay\":0,\"resource\":0}\n");
        assertThatThrownBy(()->counters.increment("sensitive-data")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->new BackendCounters(path)).isInstanceOf(IllegalArgumentException.class);
        Path permissive=Files.createFile(temp.resolve("permissive.json"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--")));
        assertThatThrownBy(()->new BackendCounters(permissive)).isInstanceOf(IllegalArgumentException.class);
        Path link=Files.createSymbolicLink(temp.resolve("link.json"),path);assertThatThrownBy(()->BackendSettings.file(link.toString())).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void resourceRequiresVerifiedPrincipalCorrectMethodAndExactPath()throws Exception {
        BackendSettings settings=new BackendSettings(environment());BackendCounters counters=new BackendCounters(null);
        HttpServlet servlet=new BackendMain().resource(settings,counters).getServlet();
        for(int scenario=0;scenario<4;scenario++){
            MockHttpServletRequest request=new MockHttpServletRequest(scenario==2?"GET":"POST",scenario==1?"/other":"/v1/items");request.setUserPrincipal(()->settings.subject);request.setContent(new byte[]{0,1,2});
            if(scenario!=0)request.setAttribute(io.appguard.AppGuardFilter.VERIFICATION_ATTRIBUTE,new VerificationResult(settings.appId,settings.keyId,1));
            if(scenario==3)request.setUserPrincipal(()->"different-user");
            MockHttpServletResponse response=new MockHttpServletResponse();servlet.service(request,response);assertThat(response.getStatus()).isEqualTo(403);
        }
        assertThat(counters.snapshot().get("resource")).isZero();
        MockHttpServletRequest request=new MockHttpServletRequest("POST","/v1/items");request.setUserPrincipal(()->settings.subject);request.setContent(new byte[]{0,1,-1,10});request.setAttribute(io.appguard.AppGuardFilter.VERIFICATION_ATTRIBUTE,new VerificationResult(settings.appId,settings.keyId,1));
        MockHttpServletResponse response=new MockHttpServletResponse();servlet.service(request,response);assertThat(response.getStatus()).isEqualTo(200);assertThat(response.getContentAsByteArray()).containsExactly(0,1,-1,10);assertThat(counters.snapshot().get("resource")).isEqualTo(1);
    }
}
