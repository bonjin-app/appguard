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
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
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
    ConfigurableApplicationContext context;
    int port;
    HttpClient client=HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(3)).build();
    @BeforeAll void start(){
        context=new SpringApplicationBuilder(App.class).properties(
            "server.address=127.0.0.1","server.port=0","server.forward-headers-strategy=none","appguard.enabled=true","appguard.app-id=test-app","appguard.origin="+SignedRequests.ORIGIN,
            "appguard.allow-insecure-transport=true","spring.main.banner-mode=off","logging.level.root=ERROR").run();port=context.getEnvironment().getRequiredProperty("local.server.port",Integer.class);
    }
    @AfterAll void stop(){if(context!=null)context.close();}
    @SpringBootConfiguration @EnableAutoConfiguration @Import({Endpoints.class,Security.class}) static class App {
        @Bean Clock clock(){return Clock.fixed(Instant.ofEpochSecond(SignedRequests.NOW),ZoneOffset.UTC);}
        @Bean CountingReplayStore replay(){return new CountingReplayStore();}
        @Bean ServletRegistrationBean<LateBodyServlet> lateBodyServlet(){
            ServletRegistrationBean<LateBodyServlet> registration=new ServletRegistrationBean<>(new LateBodyServlet(),"/async-late","/async-explicit");
            registration.setAsyncSupported(true);return registration;
        }
        @Bean IdentityResolver identities(){return IdentityResolver.fromPrincipal((subject,key)->SignedRequests.key());}
    }
    @Configuration(proxyBeanMethods=false) static class Security {
        @Bean SecurityFilterChain security(HttpSecurity http) throws Exception {
            return http.csrf(c->c.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)).authorizeHttpRequests(a->a.anyRequest().permitAll())
                .addFilterBefore((request,response,chain)->{
                    if("Bearer TEST_ONLY_TOKEN".equals(((HttpServletRequest)request).getHeader("Authorization")))SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated("test-user",null,List.of()));
                    // Test-only upstream rewrite: never installed by the SDK.
                    if("route".equals(((HttpServletRequest)request).getHeader("X-Test-Wrapper"))) {
                        chain.doFilter(new HttpServletRequestWrapper((HttpServletRequest)request){
                            @Override public String getRequestURI(){return "/echo";}
                            @Override public String getServletPath(){return "/echo";}
                        },response);
                    } else chain.doFilter(request,response);
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
    static final class CountingReplayStore implements ReplayStore {
        final AtomicInteger attempts=new AtomicInteger();
        final LocalReplayStore delegate=new LocalReplayStore();
        @Override public Boolean claim(ReplayScope scope,long expires,long now){attempts.incrementAndGet();return delegate.claim(scope,expires,now);}
    }
    static final class LateBodyServlet extends HttpServlet {
        @Override protected void doPost(HttpServletRequest request,HttpServletResponse response)throws IOException {
            if(request.getDispatcherType()==DispatcherType.ASYNC){
                response.setHeader("X-Redispatch-Body",Base64.getEncoder().encodeToString(request.getInputStream().readAllBytes()));
                response.setHeader("X-Redispatch-Verification",((VerificationResult)request.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).code());
                response.getOutputStream().write((byte[])request.getAttribute("test.async.workerBody"));return;
            }
            // Neither the servlet nor MVC reads content before asynchronous processing starts.
            boolean explicit=request.getRequestURI().equals("/async-explicit");
            HttpServletRequest selectedRequest=explicit?new HttpServletRequestWrapper(request){}:request;
            HttpServletResponse selectedResponse=explicit?new HttpServletResponseWrapper(response){}:response;
            AsyncContext async=explicit?request.startAsync(selectedRequest,selectedResponse):request.startAsync();
            response.setHeader("X-Async-Request-Preserved",Boolean.toString(async.getRequest()==selectedRequest));
            response.setHeader("X-Async-Response-Preserved",Boolean.toString(async.getResponse()==selectedResponse));
            response.setHeader("X-Async-Context-Preserved",Boolean.toString(request.getAsyncContext().getRequest()==async.getRequest() && request.getAsyncContext().getResponse()==async.getResponse()));
            async.start(()->{
                try {
                    // The worker must read from the request actually retained by the container.
                    byte[] body=async.getRequest().getInputStream().readAllBytes();
                    async.getRequest().setAttribute("test.async.workerBody",body);async.dispatch();
                } catch(IOException e){((HttpServletResponse)async.getResponse()).setStatus(500);async.complete();}
            });
        }
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
    @Test void realUpstreamRouteRewriteRejectsWithoutConsumingNonce() throws Exception {
        byte[] body="{}".getBytes(StandardCharsets.UTF_8);String target="/async";
        List<Header> signed=SignedRequests.signed("POST",target,body,"application/json");
        List<Header> altered=new ArrayList<>(signed);altered.add(new Header("X-Test-Wrapper","route"));
        CountingReplayStore replay=context.getBean(CountingReplayStore.class);int before=replay.attempts.get();
        HttpResponse<byte[]> rejected=post(target,body,"application/json",altered);
        assertThat(rejected.statusCode()).isEqualTo(400);assertThat(new String(rejected.body(),StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"INVALID_REQUEST\"}");assertThat(replay.attempts).hasValue(before);
        HttpResponse<byte[]> healthy=post(target,body,"application/json",signed);
        assertThat(healthy.statusCode()).isEqualTo(200);assertThat(healthy.body()).isEqualTo(body);assertThat(replay.attempts).hasValue(before+1);
        HttpResponse<byte[]> duplicate=post(target,body,"application/json",signed);
        assertThat(duplicate.statusCode()).isEqualTo(403);assertThat(new String(duplicate.body(),StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"REPLAY_DETECTED\"}");
    }
    @Test void invalidBearerCannotBecomeAuthenticatedFromSignedData() throws Exception {
        byte[] body="{}".getBytes();List<Header> headers=SignedRequests.signed("POST","/echo",body,"application/json");headers.removeIf(h->h.name().equals("Authorization"));headers.add(new Header("Authorization","Bearer invalid"));
        HttpResponse<byte[]> response=post("/echo",body,"application/json",headers);assertThat(response.statusCode()).isEqualTo(401);assertThat(new String(response.body())).isEqualTo("{\"code\":\"AUTHENTICATION_REQUIRED\"}");
    }
    @Test void realAsyncRedispatchDoesNotReclaimNonce() throws Exception {
        byte[] body="{\"async\":true}".getBytes();HttpResponse<byte[]> response=post("/async",body,"application/json",SignedRequests.signed("POST","/async",body,"application/json"));assertThat(response.statusCode()).isEqualTo(200);assertThat(response.body()).isEqualTo(body);
    }
    @Test void noArgumentAsyncContextPreservesBodyForWorkerBeforeRedispatch()throws Exception {
        assertLateAsyncBody("/async-late");
    }
    @Test void explicitAsyncContextPreservesCallerRequestAndResponseWrappers()throws Exception {
        assertLateAsyncBody("/async-explicit");
    }
    void assertLateAsyncBody(String target)throws Exception {
        byte[] body="{\"late\":\"세상\", \"bytes\":[0,1,2]}".getBytes(StandardCharsets.UTF_8);
        CountingReplayStore replay=context.getBean(CountingReplayStore.class);int before=replay.attempts.get();
        HttpResponse<byte[]> response=post(target,body,"application/json",SignedRequests.signed("POST",target,body,"application/json"));
        assertThat(response.statusCode()).isEqualTo(200);assertThat(response.body()).isEqualTo(body);
        assertThat(response.headers().firstValue("X-Async-Request-Preserved")).contains("true");
        assertThat(response.headers().firstValue("X-Async-Response-Preserved")).contains("true");
        assertThat(response.headers().firstValue("X-Async-Context-Preserved")).contains("true");
        assertThat(response.headers().firstValue("X-Redispatch-Body")).contains(Base64.getEncoder().encodeToString(body));
        assertThat(response.headers().firstValue("X-Redispatch-Verification")).contains("VERIFIED");
        assertThat(replay.attempts).hasValue(before+1);
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
