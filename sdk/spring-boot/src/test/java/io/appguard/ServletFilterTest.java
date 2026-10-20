package io.appguard;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.springframework.test.web.servlet.*;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ServletFilterTest {
    final Clock clock=Clock.fixed(Instant.ofEpochSecond(SignedRequests.NOW),ZoneOffset.UTC);
    AppGuardFilter filter(IdentityResolver identities,ReplayStore replay){return new AppGuardFilter("test-app",SignedRequests.ORIGIN,identities,replay,clock,false);}
    AppGuardFilter filter(){return filter(IdentityResolver.fromPrincipal((subject,keyId)->SignedRequests.key()),new LocalReplayStore());}
    MockHttpServletResponse run(AppGuardFilter f,HttpServletRequest request) throws Exception {
        MockHttpServletResponse response=new MockHttpServletResponse();
        f.doFilter(request,response,(req,res)->{res.getWriter().write("downstream");});return response;
    }
    @Test void unchangedJsonBodyAndIdentityReachRealMvcController() throws Exception {
        byte[] bytes="{\"b\":2, \"a\":1}".getBytes(StandardCharsets.UTF_8);
        MockMvc mvc=MockMvcBuilders.standaloneSetup(new Echo()).addFilters(filter()).build();
        var builder=post("/echo?b=2&a=1").secure(true).principal(()->"test-user").content(bytes);
        for(Header h:SignedRequests.signed("POST","/echo?b=2&a=1",bytes,"application/json"))builder.header(h.name(),h.value());
        mvc.perform(builder).andExpect(status().isOk()).andExpect(content().bytes(bytes)).andExpect(header().string("X-Subject","test-user")).andExpect(header().string("X-AppGuard","VERIFIED"));
    }
    @RestController static class Echo {
        @PostMapping("/echo") byte[] echo(@RequestBody byte[] body,HttpServletRequest request,HttpServletResponse response){
            response.setHeader("X-Subject",request.getUserPrincipal().getName());
            response.setHeader("X-AppGuard",((VerificationResult)request.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).code());return body;
        }
    }
    @Test void replayAndTamperingRejectWithoutDownstreamOrNoncePrematureClaim() throws Exception {
        AppGuardFilter f=filter();MockHttpServletRequest good=SignedRequests.request("{}".getBytes(),"/echo?","application/json");
        MockHttpServletRequest bad=SignedRequests.request("{}".getBytes(),"/echo?","application/json");
        for(String name:Collections.list(good.getHeaderNames())){bad.removeHeader(name);for(String v:Collections.list(good.getHeaders(name)))bad.addHeader(name,v);} bad.setContent("[]".getBytes());
        assertThat(run(f,bad).getContentAsString()).isEqualTo("{\"code\":\"DIGEST_MISMATCH\"}");
        assertThat(run(f,good).getContentAsString()).isEqualTo("downstream");
        good.removeAttribute("irrelevant");
        // Separate servlet request, same signed envelope and nonce.
        MockHttpServletRequest repeated=SignedRequests.request("{}".getBytes(),"/echo?","application/json");
        for(String name:Collections.list(good.getHeaderNames())){repeated.removeHeader(name);for(String v:Collections.list(good.getHeaders(name)))repeated.addHeader(name,v);}
        assertThat(run(f,repeated).getContentAsString()).isEqualTo("{\"code\":\"REPLAY_DETECTED\"}");
    }
    @Test void authenticationAndDependencyFailuresHaveFixedMappings() throws Exception {
        MockHttpServletRequest noAuth=SignedRequests.request(new byte[0],"/echo","application/json");noAuth.setUserPrincipal(null);
        assertFailure(run(filter(),noAuth),401,"AUTHENTICATION_REQUIRED");
        assertFailure(run(filter((r,p)->{throw new Exception("TOKEN SECRET");},new LocalReplayStore()),SignedRequests.request(new byte[0],"/echo","application/json")),503,"IDENTITY_UNAVAILABLE");
        assertFailure(run(filter(IdentityResolver.fromPrincipal((s,k)->{throw new Exception("PEM SECRET");}),new LocalReplayStore()),SignedRequests.request(new byte[0],"/echo","application/json")),503,"KEY_RESOLVER_UNAVAILABLE");
        assertFailure(run(filter((r,p)->new Identity("test-user",SignedRequests.key()),(s,e,n)->{throw new Exception("REDIS SECRET");}),SignedRequests.request(new byte[0],"/echo","application/json")),503,"REPLAY_STORE_UNAVAILABLE");
        assertFailure(run(filter((r,p)->new Identity("bad subject",SignedRequests.key()),new LocalReplayStore()),SignedRequests.request(new byte[0],"/echo","application/json")),503,"IDENTITY_UNAVAILABLE");
    }
    @Test void unknownKeyRejectsButMalformedResolverContractsAreUnavailable()throws Exception {
        assertFailure(run(filter(IdentityResolver.fromPrincipal((s,k)->null),new LocalReplayStore()),SignedRequests.request(new byte[0],"/echo","application/json")),403,"KEY_REJECTED");
        KeyRecord broken=new KeyRecord("test-app","test-key","test-user",null,"ecdsa-p256-sha256",false);
        assertFailure(run(filter(IdentityResolver.fromPrincipal((s,k)->broken),new LocalReplayStore()),SignedRequests.request(new byte[0],"/echo","application/json")),503,"KEY_RESOLVER_UNAVAILABLE");
        assertFailure(run(filter((r,p)->new Identity("test-user",broken),new LocalReplayStore()),SignedRequests.request(new byte[0],"/echo","application/json")),503,"IDENTITY_UNAVAILABLE");
    }
    @Test void transportSpoofingDuplicateHeadersAndRawTargetLossReject() throws Exception {
        MockHttpServletRequest insecure=SignedRequests.request(new byte[0],"/echo","application/json");insecure.setSecure(false);insecure.addHeader("X-Forwarded-Proto","https");
        assertFailure(run(filter(),insecure),400,"INVALID_REQUEST");
        HttpServletRequest spoof=new HttpServletRequestWrapper(insecure){@Override public boolean isSecure(){return true;}};
        assertFailure(run(filter(),spoof),400,"INVALID_REQUEST");
        MockHttpServletRequest duplicate=SignedRequests.request(new byte[0],"/echo","application/json");duplicate.addHeader("Authorization","Bearer other");assertFailure(run(filter(),duplicate),400,"INVALID_REQUEST");
        MockHttpServletRequest lost=SignedRequests.request(new byte[0],"/echo","application/json");lost.setRequestURI("");assertFailure(run(filter(),lost),400,"INVALID_REQUEST");
    }
    @Test void unsupportedFormAndMultipartRejectBeforeParameterParsingOrNonceClaim() throws Exception {
        for(String type:List.of("application/x-www-form-urlencoded","multipart/form-data; boundary=test")) {
            AtomicInteger claims=new AtomicInteger();
            AppGuardFilter f=filter((r,p)->new Identity("test-user",SignedRequests.key()),(s,e,n)->{claims.incrementAndGet();return true;});
            assertFailure(run(f,SignedRequests.request("a=1&a=2".getBytes(),"/echo",type)),400,"INVALID_REQUEST");assertThat(claims).hasValue(0);
        }
    }
    @Test void oversizeAndTruncatedOrAbortedBodyFailClosed() throws Exception {
        byte[] huge=new byte[Canonical.MAX_BODY+1];MockHttpServletRequest large=SignedRequests.request(huge,"/echo","application/octet-stream");
        assertFailure(run(filter(),large),413,"INVALID_REQUEST");
        MockHttpServletRequest truncated=SignedRequests.request("{}".getBytes(),"/echo","application/json");truncated.addHeader("Content-Length","3");assertFailure(run(filter(),truncated),400,"INVALID_REQUEST");
        MockHttpServletRequest aborted=SignedRequests.request("{}".getBytes(),"/echo","application/json");
        HttpServletRequest broken=new MockHttpServletRequest("POST","/echo") {
            @Override public ServletInputStream getInputStream(){return new ServletInputStream(){public boolean isFinished(){return false;}public boolean isReady(){return true;}public void setReadListener(ReadListener l){} public int read() throws IOException{throw new IOException("secret transport");}};}
        };
        MockHttpServletRequest brokenMock=(MockHttpServletRequest)broken;
        for(String name:Collections.list(aborted.getHeaderNames()))for(String v:Collections.list(aborted.getHeaders(name)))brokenMock.addHeader(name,v);
        brokenMock.setSecure(true);brokenMock.setUserPrincipal(()->"test-user");assertFailure(run(filter(),broken),400,"INVALID_REQUEST");
    }
    @Test void timeIsReadOnlyAfterAuthenticationAndAsyncErrorCannotBypassOrReclaim() throws Exception {
        AtomicLong time=new AtomicLong(0);AtomicInteger claims=new AtomicInteger();
        Clock dynamic=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochSecond(time.get());}};
        AppGuardFilter f=new AppGuardFilter("test-app",SignedRequests.ORIGIN,(r,p)->{time.set(SignedRequests.NOW);return new Identity("test-user",SignedRequests.key());},(s,e,n)->{assertThat(n).isEqualTo(SignedRequests.NOW);claims.incrementAndGet();return true;},dynamic,false);
        MockHttpServletRequest r=SignedRequests.request(new byte[0],"/echo","application/json");assertThat(run(f,r).getStatus()).isEqualTo(200);
        for(DispatcherType type:List.of(DispatcherType.ASYNC,DispatcherType.ERROR)) {r.setDispatcherType(type);assertThat(run(f,r).getContentAsString()).isEqualTo("downstream");}
        assertThat(claims).hasValue(1);
        MockHttpServletRequest bypass=SignedRequests.request(new byte[0],"/echo","application/json");bypass.setDispatcherType(DispatcherType.ASYNC);assertFailure(run(f,bypass),400,"INVALID_REQUEST");
    }
    @Test void exactLimitSucceedsAndOverflowCaptureStopsAtOneExtraByte() throws Exception {
        byte[] exact=new byte[Canonical.MAX_BODY];assertThat(run(filter(),SignedRequests.request(exact,"/echo","application/octet-stream")).getContentAsString()).isEqualTo("downstream");
        AtomicInteger read=new AtomicInteger();MockHttpServletRequest huge=new MockHttpServletRequest("POST","/echo") {
            @Override public ServletInputStream getInputStream(){return new ServletInputStream(){public boolean isFinished(){return false;}public boolean isReady(){return true;}public void setReadListener(ReadListener listener){}public int read(){read.incrementAndGet();return 1;}};}
        };
        huge.setSecure(true);huge.setUserPrincipal(()->"test-user");for(Header h:SignedRequests.signed("POST","/echo",new byte[0],"application/octet-stream"))huge.addHeader(h.name(),h.value());
        assertFailure(run(filter(),huge),413,"INVALID_REQUEST");assertThat(read).hasValue(Canonical.MAX_BODY+1);
    }
    @Test void absentHeaderEnumerationAndUnavailableBodyFailClosed()throws Exception {
        MockHttpServletRequest absent=new MockHttpServletRequest("POST","/echo"){@Override public Enumeration<String> getHeaderNames(){return null;}};absent.setSecure(true);assertFailure(run(filter(),absent),400,"INVALID_REQUEST");
        MockHttpServletRequest missing=new MockHttpServletRequest("POST","/echo"){@Override public ServletInputStream getInputStream(){return null;}};missing.setSecure(true);missing.setUserPrincipal(()->"test-user");for(Header h:SignedRequests.signed("POST","/echo",new byte[0],"application/json"))missing.addHeader(h.name(),h.value());assertFailure(run(filter(),missing),400,"INVALID_REQUEST");
    }
    static void assertFailure(MockHttpServletResponse response,int status,String code)throws Exception {assertThat(response.getStatus()).isEqualTo(status);assertThat(response.getContentAsString()).isEqualTo("{\"code\":\""+code+"\"}");}
}
