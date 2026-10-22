package io.appguard;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.*;
import static org.assertj.core.api.Assertions.*;

/** A signature for one initial request must not approve a different wrapper view. */
class WrapperBoundaryTest {
    static final byte[] BODY="{\"role\":\"reader\"}".getBytes(StandardCharsets.UTF_8);
    static final Clock CLOCK=Clock.fixed(Instant.ofEpochSecond(SignedRequests.NOW),ZoneOffset.UTC);

    @ParameterizedTest @ValueSource(strings={"method","uri","query","context","servlet","pathInfo","headers","originalHeaders","header","lowerHeader","missingHeader","extraHeader","valueOrder","contentType","encoding"})
    void divergentInitialWrapperRejectsBeforeTrustedWorkAndPreservesNonce(String change) throws Exception {
        MockHttpServletRequest raw=SignedRequests.request(BODY,"/public?x=1&x=2","application/json");
        raw.addHeader("X-Trace","one");raw.addHeader("X-Trace","two");
        AtomicInteger identities=new AtomicInteger(), clocks=new AtomicInteger(), claims=new AtomicInteger(), calls=new AtomicInteger();
        Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){clocks.incrementAndGet();return CLOCK.instant();}};
        LocalReplayStore local=new LocalReplayStore();
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,(r,p)->{identities.incrementAndGet();return new Identity("test-user",SignedRequests.key());},(s,e,n)->{claims.incrementAndGet();return local.claim(s,e,n);},clock,false);
        HttpServletRequest altered=new HttpServletRequestWrapper(raw){
            @Override public String getMethod(){return change.equals("method")?"DELETE":super.getMethod();}
            @Override public String getRequestURI(){return change.equals("uri")?"/admin":super.getRequestURI();}
            @Override public String getQueryString(){return change.equals("query")?"x=admin":super.getQueryString();}
            @Override public String getContextPath(){return change.equals("context")?"/admin":super.getContextPath();}
            @Override public String getServletPath(){return change.equals("servlet")?"/admin":super.getServletPath();}
            @Override public String getPathInfo(){return change.equals("pathInfo")?"/admin":super.getPathInfo();}
            @Override public Enumeration<String> getHeaderNames(){List<String> names=Collections.list(super.getHeaderNames());if(change.equals("originalHeaders"))names=names.stream().map(n->n.toLowerCase(Locale.ROOT)).toList();if(change.equals("missingHeader"))names.removeIf(n->n.equalsIgnoreCase("Authorization"));if(change.equals("extraHeader"))names.add("X-Added");return Collections.enumeration(names);}
            @Override public Enumeration<String> getHeaders(String name){if(change.equals("originalHeaders")&&name.equals("Authorization"))return Collections.enumeration(List.of("Bearer OTHER_SECRET"));if(change.equals("extraHeader")&&name.equalsIgnoreCase("X-Added"))return Collections.enumeration(List.of("changed"));if(change.equals("valueOrder")&&name.equalsIgnoreCase("X-Trace"))return Collections.enumeration(List.of("two","one"));return change.equals("headers")&&name.equalsIgnoreCase("Authorization")?Collections.enumeration(List.of("Bearer OTHER_SECRET")):super.getHeaders(name);}
            @Override public String getHeader(String name){return (change.equals("header")&&name.equalsIgnoreCase("Authorization")||change.equals("lowerHeader")&&name.equals("authorization"))?"Bearer OTHER_SECRET":super.getHeader(name);}
            @Override public String getContentType(){return change.equals("contentType")?"text/plain":super.getContentType();}
            @Override public String getCharacterEncoding(){return change.equals("encoding")?"UTF-16":super.getCharacterEncoding();}
        };
        MockHttpServletResponse rejected=new MockHttpServletResponse();
        filter.doFilter(altered,rejected,(r,s)->calls.incrementAndGet());
        assertThat(rejected.getStatus()).isEqualTo(400);
        assertThat(rejected.getContentAsString()).isEqualTo("{\"code\":\"INVALID_REQUEST\"}");
        assertThat(identities).hasValue(0);assertThat(clocks).hasValue(0);assertThat(claims).hasValue(0);assertThat(calls).hasValue(0);
        assertThat(raw.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).isNull();
        // Reuse the same signed envelope through the unchanged raw request.
        MockHttpServletResponse healthy=new MockHttpServletResponse();
        filter.doFilter(raw,healthy,(r,s)->{calls.incrementAndGet();assertThat(((HttpServletRequest)r).getRequestURI()).isEqualTo("/public");assertThat(r.getInputStream().readAllBytes()).isEqualTo(BODY);});
        assertThat(healthy.getStatus()).isEqualTo(200);assertThat(identities).hasValue(1);assertThat(clocks).hasValue(1);assertThat(claims).hasValue(1);assertThat(calls).hasValue(1);
        raw.setContent(BODY); // A separate HTTP request has a fresh body stream with the same envelope.
        MockHttpServletResponse replay=new MockHttpServletResponse();filter.doFilter(raw,replay,(r,s)->calls.incrementAndGet());
        assertThat(replay.getStatus()).isEqualTo(403);assertThat(replay.getContentAsString()).isEqualTo("{\"code\":\"REPLAY_DETECTED\"}");assertThat(calls).hasValue(1);
    }

    @Test void transparentNestedWrappersPreserveOuterPrincipalAndRoles() throws Exception {
        MockHttpServletRequest raw=SignedRequests.request(BODY,"/public?x=1&x=2","application/json");raw.setUserPrincipal(null);
        HttpServletRequest outer=new HttpServletRequestWrapper(new HttpServletRequestWrapper(raw){}){
            @Override public java.security.Principal getUserPrincipal(){return ()->"test-user";}
            @Override public boolean isUserInRole(String role){return role.equals("reader");}
            @Override public Enumeration<String> getHeaderNames(){List<String> names=Collections.list(super.getHeaderNames());Collections.reverse(names);return Collections.enumeration(names);}
        };
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,IdentityResolver.fromPrincipal((s,k)->SignedRequests.key()),new LocalReplayStore(),CLOCK,false);
        AtomicInteger calls=new AtomicInteger();filter.doFilter(outer,new MockHttpServletResponse(),(r,s)->{
            HttpServletRequest request=(HttpServletRequest)r;calls.incrementAndGet();assertThat(request.getUserPrincipal().getName()).isEqualTo("test-user");assertThat(request.isUserInRole("reader")).isTrue();assertThat(request.getQueryString()).isEqualTo("x=1&x=2");assertThat(r.getInputStream().readAllBytes()).isEqualTo(BODY);assertThat(request.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).isInstanceOf(VerificationResult.class);
        });assertThat(calls).hasValue(1);
    }

    @Test void absentAndExplicitEmptyQueryAreDifferentWrapperViews() throws Exception {
        MockHttpServletRequest raw=SignedRequests.request(BODY,"/public?","application/json");
        HttpServletRequest altered=new HttpServletRequestWrapper(raw){@Override public String getQueryString(){return null;}};
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,IdentityResolver.fromPrincipal((s,k)->SignedRequests.key()),new LocalReplayStore(),CLOCK,false);
        MockHttpServletResponse response=new MockHttpServletResponse();filter.doFilter(altered,response,(r,s)->{throw new AssertionError("Must not dispatch");});
        assertThat(response.getStatus()).isEqualTo(400);assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"INVALID_REQUEST\"}");
    }
    @Test void headerNameCaseAndOrderDoNotRejectTransparentWrappers() throws Exception {
        MockHttpServletRequest raw=SignedRequests.request(BODY,"/public?","application/json");
        HttpServletRequest outer=new HttpServletRequestWrapper(raw){
            @Override public Enumeration<String> getHeaderNames(){List<String> names=Collections.list(super.getHeaderNames()).stream().map(n->n.toLowerCase(Locale.ROOT)).toList();return Collections.enumeration(names);}
        };
        AtomicInteger calls=new AtomicInteger();AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,IdentityResolver.fromPrincipal((s,k)->SignedRequests.key()),new LocalReplayStore(),CLOCK,false);
        filter.doFilter(outer,new MockHttpServletResponse(),(r,s)->{calls.incrementAndGet();assertThat(((HttpServletRequest)r).getQueryString()).isEmpty();});assertThat(calls).hasValue(1);
    }

    @Test void trustedForwardMayChangeRouteWithoutReclaimingOriginalNonce() throws Exception {
        MockHttpServletRequest raw=SignedRequests.request(BODY,"/public","application/json");
        AtomicInteger claims=new AtomicInteger(), identities=new AtomicInteger(), calls=new AtomicInteger();
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,(r,p)->{identities.incrementAndGet();return new Identity("test-user",SignedRequests.key());},(s,e,n)->{claims.incrementAndGet();return true;},CLOCK,false);
        filter.doFilter(raw,new MockHttpServletResponse(),(r,s)->calls.incrementAndGet());
        raw.setDispatcherType(DispatcherType.FORWARD);raw.setRequestURI("/internal");raw.setServletPath("/internal");
        filter.doFilter(new HttpServletRequestWrapper(raw){},new MockHttpServletResponse(),(r,s)->{calls.incrementAndGet();assertThat(((HttpServletRequest)r).getRequestURI()).isEqualTo("/internal");assertThat(r.getInputStream().readAllBytes()).isEqualTo(BODY);assertThat(r.getAttribute(AppGuardFilter.VERIFICATION_ATTRIBUTE)).isInstanceOf(VerificationResult.class);});
        assertThat(identities).hasValue(1);assertThat(claims).hasValue(1);assertThat(calls).hasValue(2);
    }

    @ParameterizedTest @ValueSource(strings={"method","headers","header"})
    void failingWrapperGettersReturnFixedFailureWithoutDispatch(String accessor) throws Exception {
        MockHttpServletRequest raw=SignedRequests.request(BODY,"/public","application/json");
        HttpServletRequest outer=new HttpServletRequestWrapper(raw){
            @Override public String getMethod(){if(accessor.equals("method"))throw new IllegalStateException("SECRET");return super.getMethod();}
            @Override public Enumeration<String> getHeaderNames(){if(accessor.equals("headers"))return null;return super.getHeaderNames();}
            @Override public String getHeader(String name){if(accessor.equals("header"))throw new IllegalStateException("SECRET");return super.getHeader(name);}
        };
        AppGuardFilter filter=new AppGuardFilter("test-app",SignedRequests.ORIGIN,(r,p)->{throw new AssertionError("Identity must not run");},(s,e,n)->{throw new AssertionError("Replay must not run");},CLOCK,false);
        MockHttpServletResponse response=new MockHttpServletResponse();filter.doFilter(outer,response,(r,s)->{throw new AssertionError("Must not dispatch");});
        assertThat(response.getStatus()).isEqualTo(400);assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"INVALID_REQUEST\"}");
    }

}
