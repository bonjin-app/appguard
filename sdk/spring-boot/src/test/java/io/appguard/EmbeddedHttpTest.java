package io.appguard;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.context.ServletWebServerApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.bind.annotation.*;
import static org.assertj.core.api.Assertions.*;

/** Real Tomcat + Spring Security; plaintext is an explicit loopback-only test opt-in. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EmbeddedHttpTest {
    ServletWebServerApplicationContext context;
    int port;
    HttpClient client=HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(3)).build();
    @BeforeAll void start(){
        context=(ServletWebServerApplicationContext)new SpringApplicationBuilder(App.class).properties(
            "server.address=127.0.0.1","server.port=0","server.forward-headers-strategy=none","appguard.enabled=true","appguard.app-id=test-app","appguard.origin="+SignedRequests.ORIGIN,
            "appguard.allow-insecure-transport=true","spring.main.banner-mode=off","logging.level.root=ERROR").run();port=context.getWebServer().getPort();
    }
    @AfterAll void stop(){if(context!=null)context.close();}
    @SpringBootConfiguration @EnableAutoConfiguration @Import({Endpoints.class,Security.class}) static class App {
        @Bean Clock clock(){return Clock.fixed(Instant.ofEpochSecond(SignedRequests.NOW),ZoneOffset.UTC);}
        @Bean ReplayStore replay(){return new LocalReplayStore();}
        @Bean IdentityResolver identities(){return IdentityResolver.fromPrincipal((subject,key)->SignedRequests.key());}
    }
    @Configuration(proxyBeanMethods=false) static class Security {
        @Bean SecurityFilterChain security(HttpSecurity http) throws Exception {
            return http.csrf(c->c.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).authorizeHttpRequests(a->a.anyRequest().permitAll())
                .addFilterBefore((request,response,chain)->{
                    if("Bearer TEST_ONLY_TOKEN".equals(((HttpServletRequest)request).getHeader("Authorization")))SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated("test-user",null,List.of()));
                    chain.doFilter(request,response);
                },AnonymousAuthenticationFilter.class).build();
        }
    }
    @RestController static class Endpoints {
        @PostMapping("/echo") byte[] echo(@RequestBody byte[] body,@RequestParam(name="x",required=false) List<String> x,HttpServletResponse response,HttpServletRequest request){
            response.setHeader("X-Subject",request.getUserPrincipal().getName());
            response.setHeader("X-Query",x==null?"":String.join(",",x));response.setHeader("X-AppGuard",((VerificationResult)request.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).code());return body;
        }
        @PostMapping("/async") Callable<byte[]> async(@RequestBody byte[] body){return ()->body;}
    }
    HttpResponse<byte[]> post(String target,byte[] body,String type,List<Header> headers)throws Exception {
        var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+target)).timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofByteArray(body));
        for(Header h:headers)request.header(h.name(),h.value());return client.send(request.build(),HttpResponse.BodyHandlers.ofByteArray());
    }
    @Test void realSecurityPrincipalJsonBytesQueryAndReplayArePreserved() throws Exception {
        byte[] body="{\"hello\":\"세상\", \"n\":1}".getBytes(StandardCharsets.UTF_8);String target="/echo?x=2&x=1";
        List<Header> headers=SignedRequests.signed("POST",target,body,"application/json");
        HttpResponse<byte[]> valid=post(target,body,"application/json",headers);
        assertThat(valid.statusCode()).isEqualTo(200);assertThat(valid.body()).isEqualTo(body);assertThat(valid.headers().firstValue("X-Subject")).contains("test-user");assertThat(valid.headers().firstValue("X-Query")).contains("2,1");
        HttpResponse<byte[]> repeat=post(target,body,"application/json",headers);assertThat(repeat.statusCode()).isEqualTo(403);assertThat(new String(repeat.body(),StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"REPLAY_DETECTED\"}");
    }
    @Test void invalidBearerCannotBecomeAuthenticatedFromSignedData() throws Exception {
        byte[] body="{}".getBytes();List<Header> headers=SignedRequests.signed("POST","/echo",body,"application/json");headers.removeIf(h->h.name().equals("Authorization"));headers.add(new Header("Authorization","Bearer invalid"));
        HttpResponse<byte[]> response=post("/echo",body,"application/json",headers);assertThat(response.statusCode()).isEqualTo(401);assertThat(new String(response.body())).isEqualTo("{\"code\":\"AUTHENTICATION_REQUIRED\"}");
    }
    @Test void realAsyncRedispatchDoesNotReclaimNonce() throws Exception {
        byte[] body="{\"async\":true}".getBytes();HttpResponse<byte[]> response=post("/async",body,"application/json",SignedRequests.signed("POST","/async",body,"application/json"));assertThat(response.statusCode()).isEqualTo(200);assertThat(response.body()).isEqualTo(body);
    }
    @Test void containerChunkedCaptureAndExplicitEmptyQueryPreserveSignature() throws Exception {
        byte[] body="{}".getBytes();String response=raw("/echo?",SignedRequests.signed("POST","/echo?",body,"application/json"),"Transfer-Encoding: chunked\r\n","2\r\n{}\r\n0\r\n\r\n");
        assertThat(response).startsWith("HTTP/1.1 200");assertThat(response).endsWith("{}");
    }
    @Test void containerTruncatedStreamOversizeDuplicateAndFormAreRejected() throws Exception {
        byte[] body="{}".getBytes();
        String truncated=raw("/echo",SignedRequests.signed("POST","/echo",body,"application/json"),"Content-Length: 5\r\n","{}");
        assertThat(truncated).startsWith("HTTP/1.1 400");assertThat(truncated).contains("{\"code\":\"INVALID_REQUEST\"}");
        String oversized=raw("/echo",SignedRequests.signed("POST","/echo",body,"application/json"),"Content-Length: 1048577\r\n","");assertThat(oversized).startsWith("HTTP/1.1 413");assertThat(oversized).contains("{\"code\":\"INVALID_REQUEST\"}");
        List<Header> duplicate=SignedRequests.signed("POST","/echo",body,"application/json");duplicate.add(new Header("Signature",duplicate.stream().filter(h->h.name().equals("Signature")).findFirst().orElseThrow().value()));
        String duplicated=raw("/echo",duplicate,"Content-Length: 2\r\n","{}");assertThat(duplicated).startsWith("HTTP/1.1 400");assertThat(duplicated).contains("{\"code\":\"INVALID_REQUEST\"}");
        for(String type:List.of("application/x-www-form-urlencoded","multipart/form-data; boundary=x")){
            HttpResponse<byte[]> response=post("/echo",body,type,SignedRequests.signed("POST","/echo",body,type));assertThat(response.statusCode()).isEqualTo(400);assertThat(new String(response.body())).isEqualTo("{\"code\":\"INVALID_REQUEST\"}");
        }
    }
    String raw(String target,List<Header> headers,String framing,String body)throws Exception {
        try(Socket socket=new Socket("127.0.0.1",port)){
            socket.setSoTimeout(5000);StringBuilder text=new StringBuilder("POST "+target+" HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n");for(Header h:headers)text.append(h.name()).append(": ").append(h.value()).append("\r\n");text.append(framing).append("\r\n").append(body);
            socket.getOutputStream().write(text.toString().getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().flush();socket.shutdownOutput();return new String(socket.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
        }
    }
}
